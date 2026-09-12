# Publisher (signer) rules — design

**Status:** approved 2026-09-12. Backlog item D (order: A edit/delete gaps ✔,
B refresh inventory ✔, C per-device overrides ✔, **D**, E E2E MFA, F polish).

## Problem

Every allow rule FreeLocker can currently produce is a file hash or a path. A
hash rule breaks on the next application update; a path rule is weak. WDAC's
third option — allow everything signed by a given publisher — is already
supported by the rule model, the store (`policy_rules.kind = 'publisher'`),
and the compiler (`wdac.Compile` emits a `<Signer><CertRoot Type="TBS">`),
but nothing ever produces a publisher value:

- `internal/agent/scan/scan_windows.go` leaves `Signer` empty (deferred).
- The CodeIntegrity block log yields a publisher *name*, never a certificate
  identifier.
- `ObservedApp` / `BlockEvent` carry only `signer` (a name).
- Observations, block events and approval requests store only that name.

So the work is to produce, carry, store and act on a real publisher identity.

## Publisher identity

WDAC identifies a publisher by the **TBS hash** of a certificate in the
file's signing chain: the DER `TBSCertificate` bytes hashed with that
certificate's own signature hash algorithm, upper-case hex. FreeLocker uses
the **leaf signing certificate** (`Get-AuthenticodeSignature`'s
`SignerCertificate`), matching `rules.Publisher`'s existing 64-hex-char
validation (SHA-256; a SHA-1-signed certificate yields 40 chars and is
rejected — see Limits).

## Trust rule (decided)

Parsing tells us *which* certificate a file presents; it does not prove the
signature is valid. So:

- The agent parses the certificate **and** asks Windows
  (`WinVerifyTrust`, `WINTRUST_ACTION_GENERIC_VERIFY_V2`) whether the
  signature is valid and trusted, reporting `signer_verified`.
- **A publisher rule may only be created from a verified signature.** The
  server rejects the attempt otherwise (400); the console disables the
  option and shows "Unverified signature".
- Unverified publishers are still displayed (so an admin can see *why* an app
  has no publisher option), which is why unverified data is reported rather
  than dropped.

## Part 1 — `internal/appcontrol/signature`

```go
package signature

// Info describes the signing certificate of a PE file.
type Info struct {
    TBSHash     string // upper-case hex; "" when unsigned
    SubjectName string // leaf CN (friendly publisher name)
    Issuer      string // issuer CN
    Verified    bool   // Windows says the signature is valid and trusted
}

// FromFile reads path's embedded Authenticode signature.
// Unsigned files return a zero Info and nil error.
func FromFile(path string) (Info, error)
```

- Portable code (`signature.go`): parse the PE, find the certificate table
  (optional-header data directory entry 4), read the `WIN_CERTIFICATE`,
  extract the PKCS#7 `SignedData.certificates`, pick the leaf (the
  certificate that is not an issuer of any other in the set), and compute
  `TBSHash` from `x509.Certificate.RawTBSCertificate` with the algorithm
  implied by `SignatureAlgorithm`.
- `signature_windows.go` adds verification via `wintrust.dll`
  (`WinVerifyTrust` with `WTD_UI_NONE`, `WTD_REVOKE_NONE`,
  `WTD_STATEACTION_VERIFY` then `CLOSE`). Read-only; no machine state
  changes.
- `signature_other.go` (`//go:build !windows`) leaves `Verified` false.
- Catalog-signed files (no embedded signature) are treated as unsigned —
  see Limits.

## Part 2 — agent and protocol

Proto (`proto/freelocker/v1/agent.proto`), regenerated with `buf generate`:

```proto
message ObservedApp {
  string sha256 = 1;
  string path = 2;
  string signer = 3;          // friendly publisher name (existing)
  string signer_tbs = 4;      // certificate TBS hash, "" when unsigned
  bool signer_verified = 5;   // Windows verified the signature
}
message BlockEvent {
  string sha256 = 1;
  string path = 2;
  string signer = 3;
  bool blocked = 4;
  int64 at_unix = 5;
  string signer_tbs = 6;
  bool signer_verified = 7;
}
```

- `scan.Observed` gains `SignerTBS string` / `SignerVerified bool`;
  `scan_windows.go` fills them via `signature.FromFile` (best effort: a
  failure leaves them empty and never drops the observation).
- `blocks.BlockEvent` gains the same two fields. The log supplies only a
  name, so the runner enriches each event by reading the file at `Path` when
  it still exists; a missing or unreadable file leaves the fields empty.
- Both are additive: an older agent reporting no new fields behaves exactly
  as today.

## Part 3 — server and console

Migration `0016_signer_identity.sql`:

```sql
ALTER TABLE observations       ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
                               ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
ALTER TABLE block_events       ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
                               ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
ALTER TABLE approval_requests  ADD COLUMN signer_tbs text NOT NULL DEFAULT '',
                               ADD COLUMN signer_verified boolean NOT NULL DEFAULT false;
```

Existing rows keep empty/false, so they simply offer no publisher option.

- Store: the three types gain `SignerTBS`/`SignerVerified`; the observation
  upsert fills them when previously empty (same "first non-empty wins" rule
  the `signer` column already uses); `UpsertApprovalRequests` carries them.
- `POST /api/observations/promote` accepts `kind` (`hash` default, or
  `publisher`). The handler currently takes the hash from the request body and
  never reads the observation, so publisher promotion adds a server-side
  lookup — `store.ObservationPublisher(ctx, tenantID, sha256) (tbs, name
  string, verified bool, err error)`, the most recently seen row for that hash
  in the tenant — and uses *its* TBS hash. The client never supplies the TBS
  value, so the verified-only rule cannot be bypassed from the browser.
  Returns 400 when the observation has no TBS hash or is unverified, 404 when
  no observation matches.
- The shared `addHashRule` helper drops `PublisherName` when writing
  `store.PolicyRule`; it is renamed `addRule` and carries the name, or
  publisher rules lose their friendly label in the compiled XML.
- `GET /api/devices/{id}/observations` and `GET /api/blocks` add
  `signer_tbs` and `signer_verified` to their JSON so the console can show
  the publisher and its state.
- `POST /api/approvals/{id}/approve` extends its existing optional body field
  `kind` (`hash` default | `path`) with `publisher`, subject to the same
  checks. The comment in `decideApproval` explaining that publisher approval
  "isn't offered here" is replaced by the implementation.
- Both keep auditing under their current actions, with `kind`/`as` in the
  detail.

Console:
- Device detail's observed-applications table gains a Publisher column
  (name, or "Unverified signature", or "—") and an "Add as publisher"
  action, disabled without a verified publisher (with the reason in its
  title).
- Approvals page gains the same publisher column and an "Approve publisher"
  button under the same rule; `approvalJSON` (`GET /api/approvals`) carries
  `signer_tbs` and `signer_verified`.
- Policy detail already renders publisher rules; no change needed.

## Safety

No enforcement change: a policy's compiled XML is byte-identical until
someone adds a publisher rule, so the existing content-hash version and the
Windows `ConvertFrom-CIPolicy` acceptance test keep passing. Reading a file's
signature is read-only. Nothing is auto-allowed: a publisher rule is only
ever created by an explicit admin action.

## Testing

- **signature (portable):** in-test generated certificate chains drive TBS
  computation (SHA-256 and SHA-384), leaf selection, and unsigned/truncated
  PE handling. A synthesised minimal PE with an appended `WIN_CERTIFICATE`
  exercises the parser end to end on any OS.
- **signature (Windows-only, `//go:build windows`):** `FromFile` on real
  system binaries (e.g. `C:\Windows\System32\notepad.exe`) reports
  `Verified` and a TBS hash matching `certutil -dump`; an unsigned temp file
  reports unsigned. Read-only, safe on the dev box (use the 64-bit
  PowerShell — the Claude Code tool's pwsh is 32-bit and redirects
  System32).
- **agent:** `scan.Observed` and enriched block events carry the new fields;
  a block event whose file is gone still reports with empty TBS.
- **server:** store round-trip of the new columns; promote-as-publisher
  produces a `publisher` rule whose value is the TBS hash; unverified or
  TBS-less promote → 400; approve-as-publisher likewise; a compiled policy
  containing the rule still converts (existing Windows test covers it).
- **console:** typecheck + build; no automated UI test (the Playwright smoke
  suite stops at MFA).

## Limits (documented, not fixed here)

- Catalog-signed files (many Microsoft binaries) have no embedded signature
  and report unsigned; the DefaultWindows baseline already allows Microsoft
  code, so this does not block Windows itself.
- Certificates signed with SHA-1 produce a 40-char TBS hash, which
  `rules.Normalize` rejects (64 hex required). Such publishers cannot become
  rules; they still display. Widening the rule model is out of scope.
- No publisher+version or publisher+filename narrowing (WDAC `FileAttribRef`),
  no per-rule certificate pinning beyond the leaf, and no dropping back to an
  intermediate certificate for broader trust.
