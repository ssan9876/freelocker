/*
 * fl_decision implementation. See fl_decision.h for the contract.
 *
 * No CRT, no allocation, no OS calls. Everything here is byte comparison and
 * binary search over caller-owned memory.
 */

#include "fl_decision.h"

/* ---- local replacements for CRT primitives ------------------------------
 *
 * Kernel mode has no CRT. These are small, obvious, and avoid depending on
 * whatever the compiler decides to intrinsify.
 */

static int fl_bytes_cmp(const unsigned char *a, const unsigned char *b, unsigned int n)
{
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

static int fl_bytes_eq(const char *a, const char *b, unsigned int n)
{
    unsigned int i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

/* ---- lookups ------------------------------------------------------------ */

/*
 * Binary search over a sorted array of FL_HASH_LEN-byte records.
 *
 * Written with an inclusive lo / exclusive hi and a midpoint that cannot
 * overflow, because this runs on every process launch and an off-by-one here
 * does not crash — it silently returns "not found", which in enforce mode
 * blocks software that was explicitly allowed.
 */
int fl_hash_present(const unsigned char *sorted, unsigned int count, const unsigned char *needle)
{
    unsigned int lo = 0, hi = count;

    if (sorted == 0 || needle == 0 || count == 0) {
        return 0;
    }
    while (lo < hi) {
        unsigned int mid = lo + (hi - lo) / 2;
        int c = fl_bytes_cmp(sorted + (mid * FL_HASH_LEN), needle, FL_HASH_LEN);
        if (c == 0) {
            return 1;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 0;
}

/*
 * Does one path rule cover this request path?
 *
 * Exact rules require identical length and bytes. Prefix rules additionally
 * require the match to end on a separator boundary: a rule for
 * "c:\program files" must NOT cover "c:\program files evil\payload.exe".
 * That class of bug — matching on a substring rather than a path component —
 * is the same one that had to be fixed twice in the ringfencing parser, so
 * it is handled explicitly here and pinned by a test.
 */
static int fl_path_match(const fl_path_rule *rule, const char *path, unsigned int len)
{
    if (rule == 0 || rule->path == 0 || rule->len == 0 || path == 0 || len == 0) {
        return 0;
    }

    if (rule->kind == FL_PATH_EXACT) {
        return rule->len == len && fl_bytes_eq(rule->path, path, len);
    }

    /* FL_PATH_PREFIX */
    if (rule->len > len) {
        return 0;
    }
    if (!fl_bytes_eq(rule->path, path, rule->len)) {
        return 0;
    }
    if (rule->len == len) {
        /* The rule names the directory itself. Not an executable, but
         * treating it as covered is harmless and avoids a surprising edge. */
        return 1;
    }
    /* A rule already ending in a separator has consumed the boundary. */
    if (rule->path[rule->len - 1] == '\\' || rule->path[rule->len - 1] == '/') {
        return 1;
    }
    /* Otherwise the next character of the request must BE the boundary. */
    return path[rule->len] == '\\' || path[rule->len] == '/';
}

static int fl_any_path_match(const fl_path_rule *rules, unsigned int count,
                             const char *path, unsigned int len)
{
    unsigned int i;
    if (rules == 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (fl_path_match(&rules[i], path, len)) {
            return 1;
        }
    }
    return 0;
}

static int fl_ruleset_is_empty(const fl_ruleset *rs)
{
    return rs->hash_count == 0 && rs->publisher_count == 0 && rs->path_count == 0;
}

/* ---- the decision ------------------------------------------------------- */

fl_verdict fl_decide(const fl_ruleset *rs, const fl_request *req, fl_reason *reason)
{
    fl_reason why = FL_REASON_NO_MATCH;
    fl_verdict verdict;

    /* Property 1: fail open when there is nothing to decide with.
     *
     * The driver loads at boot, before the user-mode service has pushed a
     * ruleset. Failing closed in that window blocks every program on the
     * machine including the service that would fix it — an unrecoverable
     * brick. A NULL request is a caller bug, and the same reasoning applies:
     * never turn a bug in our own code into an unbootable machine. */
    if (rs == 0 || req == 0) {
        why = FL_REASON_NO_RULESET;
        verdict = FL_ALLOW;
        goto done;
    }
    if (fl_ruleset_is_empty(rs)) {
        why = FL_REASON_NO_RULESET;
        verdict = FL_ALLOW;
        goto done;
    }

    /* Property 2: the agent's own image is allowed ahead of everything else,
     * in both modes. If a bad ruleset can stop the agent running, it can
     * stop the fix arriving, and the machine has to be recovered by hand.
     * The ringfencing enforcer makes the same guarantee for the same
     * reason. */
    if (fl_any_path_match(rs->self, rs->self_count, req->path, req->path_len)) {
        why = FL_REASON_SELF;
        verdict = FL_ALLOW;
        goto done;
    }

    if (req->sha256 != 0 && fl_hash_present(rs->hashes, rs->hash_count, req->sha256)) {
        why = FL_REASON_HASH;
        verdict = FL_ALLOW;
        goto done;
    }

    /* Property 4: an unverified signature never satisfies a publisher rule.
     * Anyone can attach a certificate claiming any subject; only the OS
     * saying the chain verified makes it evidence. This mirrors the existing
     * server rule that unverified signers can be displayed but never
     * promoted into a policy. */
    if (req->signer_verified && req->signer_tbs != 0 &&
        fl_hash_present(rs->publishers, rs->publisher_count, req->signer_tbs)) {
        why = FL_REASON_PUBLISHER;
        verdict = FL_ALLOW;
        goto done;
    }

    if (fl_any_path_match(rs->paths, rs->path_count, req->path, req->path_len)) {
        why = FL_REASON_PATH;
        verdict = FL_ALLOW;
        goto done;
    }

    /* Nothing matched. Distinguish "we know what this is and it is not
     * allowed" from "we could not identify it at all" — the second is worth
     * surfacing differently, because it usually means a locked or unreadable
     * file rather than genuinely unapproved software. */
    if (req->sha256 == 0 && req->signer_tbs == 0 && (req->path == 0 || req->path_len == 0)) {
        why = FL_REASON_UNKNOWN_IMAGE;
    } else {
        why = FL_REASON_NO_MATCH;
    }

    /* Property 3: audit mode never blocks. It reports what it would have
     * blocked, which is what makes a safe rollout possible. */
    verdict = (rs->mode == FL_MODE_ENFORCE) ? FL_BLOCK : FL_WOULD_BLOCK;

done:
    if (reason != 0) {
        *reason = why;
    }
    return verdict;
}

/* ---- validation --------------------------------------------------------- */

static int fl_sorted(const unsigned char *a, unsigned int count)
{
    unsigned int i;
    if (count < 2) {
        return 1;
    }
    for (i = 1; i < count; i++) {
        /* Strictly ascending: a duplicate is not harmful to lookup, but it
         * means the service built the list wrong, and quietly accepting a
         * malformed ruleset is how a subtle bug survives to production. */
        if (fl_bytes_cmp(a + ((i - 1) * FL_HASH_LEN), a + (i * FL_HASH_LEN), FL_HASH_LEN) >= 0) {
            return 0;
        }
    }
    return 1;
}

static int fl_paths_valid(const fl_path_rule *rules, unsigned int count)
{
    unsigned int i;
    if (count == 0) {
        return 1;
    }
    if (rules == 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (rules[i].path == 0 || rules[i].len == 0 || rules[i].len > FL_MAX_PATH) {
            return 0;
        }
        if (rules[i].kind != FL_PATH_EXACT && rules[i].kind != FL_PATH_PREFIX) {
            return 0;
        }
    }
    return 1;
}

int fl_ruleset_valid(const fl_ruleset *rs)
{
    if (rs == 0) {
        return 0;
    }
    if (rs->mode != FL_MODE_AUDIT && rs->mode != FL_MODE_ENFORCE) {
        return 0;
    }
    if (rs->hash_count != 0 && rs->hashes == 0) {
        return 0;
    }
    if (rs->publisher_count != 0 && rs->publishers == 0) {
        return 0;
    }
    if (!fl_sorted(rs->hashes, rs->hash_count)) {
        return 0;
    }
    if (!fl_sorted(rs->publishers, rs->publisher_count)) {
        return 0;
    }
    if (!fl_paths_valid(rs->paths, rs->path_count)) {
        return 0;
    }
    if (!fl_paths_valid(rs->self, rs->self_count)) {
        return 0;
    }
    return 1;
}
