import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, MfaSetup } from "../api";
import { useAuth } from "../auth";

// The login response tells us whether MFA is already enrolled; we keep it
// in sessionStorage so a refresh on /mfa still knows which flow to show.
export function Mfa() {
  const { onMfa } = useAuth();
  const [enrolled, setEnrolled] = useState<boolean | null>(null);
  const [secret, setSecret] = useState("");
  const [otpauth, setOtpauth] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const cached = sessionStorage.getItem("fl-mfa-enrolled");
    const known = cached === null ? null : cached === "1";
    if (known === false) {
      api
        .post<MfaSetup>("/api/mfa/setup")
        .then((s) => {
          setSecret(s.secret);
          setOtpauth(s.otpauth_url);
          setEnrolled(false);
        })
        .catch((e) => setErr(e instanceof ApiError ? e.message : "Could not start MFA setup"));
    } else {
      setEnrolled(true);
    }
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      await api.post("/api/mfa/verify", { code });
      sessionStorage.setItem("fl-mfa-enrolled", "1");
      onMfa();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Verification failed");
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <form className="auth-card" onSubmit={submit}>
        <h1 className="brand">
          <span className="lock">▣</span> FreeLocker
        </h1>
        {enrolled === false ? (
          <>
            <p className="auth-sub">
              Set up two-factor authentication. Add this secret to your authenticator app, then enter
              the 6-digit code.
            </p>
            <label>Setup key</label>
            <div className="copybox">
              <input aria-label="Setup key" readOnly value={secret} onFocus={(e) => e.target.select()} />
              <button type="button" className="ghost" onClick={() => navigator.clipboard?.writeText(secret)}>
                Copy
              </button>
            </div>
            {otpauth && (
              <p className="auth-sub" style={{ marginTop: 8, fontSize: 12 }}>
                Or open the otpauth link in your app.
              </p>
            )}
          </>
        ) : (
          <p className="auth-sub">Enter the 6-digit code from your authenticator app.</p>
        )}
        <label>Authentication code</label>
        <input
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          inputMode="numeric"
          autoFocus
          placeholder="000000"
        />
        {err && <p className="err">{err}</p>}
        <div className="btn-row">
          <button className="primary" disabled={busy || code.length !== 6}>
            {busy ? "Verifying…" : "Verify"}
          </button>
        </div>
      </form>
    </div>
  );
}
