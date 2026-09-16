/*
 * fl_decision — the application-control decision core for freelocker.sys.
 *
 * This file is deliberately portable C with NO dependencies: no CRT, no
 * Windows headers, no allocation, no floating point. It compiles unchanged
 * into the kernel driver and into a user-mode test harness, which is the
 * whole point — the logic that decides whether a program may run is the part
 * most worth testing, and it is testable on any machine, today, without a
 * signed driver or a VM.
 *
 * Kernel constraints that shaped this interface:
 *
 *   - No allocation. Every buffer is supplied by the caller. A process
 *     creation callback that can fail to allocate is a callback that can
 *     fail open or deadlock under memory pressure.
 *   - Bounded, non-blocking work. This runs on the path of EVERY process
 *     launch on the machine; lookups are binary searches over sorted arrays,
 *     never scans, and nothing here waits on anything.
 *   - No CRT. memcmp and friends are implemented locally rather than
 *     assumed.
 *
 * The caller (kernel side) is responsible for normalising inputs before
 * calling: paths lower-cased with a resolved drive letter, hashes as raw
 * bytes. Normalisation needs OS facilities; deciding does not.
 */

#ifndef FL_DECISION_H
#define FL_DECISION_H

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256, raw bytes. Used for both image hashes and certificate TBS hashes. */
#define FL_HASH_LEN 32

/* Longest path this core will compare. Windows paths can exceed this; the
 * caller decides what to do with a longer one (see fl_decide's contract for
 * an untruncatable path). Fixed so nothing here allocates. */
#define FL_MAX_PATH 520

typedef enum {
    FL_MODE_AUDIT   = 0, /* never blocks; reports what it would have blocked */
    FL_MODE_ENFORCE = 1
} fl_mode;

typedef enum {
    FL_ALLOW = 0,
    FL_BLOCK = 1,
    /* Audit mode only: the program runs, but the caller should report it.
     * Distinct from FL_ALLOW so audit mode produces a usable learning
     * stream rather than silence. */
    FL_WOULD_BLOCK = 2
} fl_verdict;

typedef enum {
    FL_REASON_NO_RULESET = 0, /* nothing loaded yet — fail open */
    FL_REASON_SELF       = 1, /* agent's own image; never blocked */
    FL_REASON_HASH       = 2,
    FL_REASON_PUBLISHER  = 3,
    FL_REASON_PATH       = 4,
    FL_REASON_NO_MATCH   = 5,
    FL_REASON_UNKNOWN_IMAGE = 6 /* nothing identifiable about the image */
} fl_reason;

typedef enum {
    FL_PATH_EXACT  = 0, /* the file itself */
    FL_PATH_PREFIX = 1  /* a directory and everything beneath it */
} fl_path_kind;

typedef struct {
    fl_path_kind kind;
    /* Lower-cased, normalised, NOT NUL-terminated. len is authoritative. */
    const char  *path;
    unsigned int len;
} fl_path_rule;

/*
 * A ruleset as the user-mode service pushes it down. All arrays are owned by
 * the caller and must remain valid and UNCHANGED for the duration of a
 * fl_decide call.
 *
 * hashes and publishers must be sorted ascending by byte order — fl_decide
 * binary searches them. fl_ruleset_valid checks this; a driver should call it
 * once when a ruleset arrives and reject an unsorted one rather than silently
 * mis-deciding.
 */
typedef struct {
    fl_mode mode;

    /* hash_count * FL_HASH_LEN bytes, sorted ascending. */
    const unsigned char *hashes;
    unsigned int         hash_count;

    /* Certificate TBS hashes, sorted ascending. A publisher rule matches only
     * an image whose signature the OS VERIFIED — see fl_decide. */
    const unsigned char *publishers;
    unsigned int         publisher_count;

    const fl_path_rule *paths;
    unsigned int        path_count;

    /* Images that must never be blocked whatever the rules say: the agent
     * and its updater. Without this a bad ruleset severs management and the
     * machine can never be recovered remotely. */
    const fl_path_rule *self;
    unsigned int        self_count;
} fl_ruleset;

typedef struct {
    /* NULL when the image could not be hashed (locked, unreadable). */
    const unsigned char *sha256;
    /* NULL when unsigned or the signature could not be read. */
    const unsigned char *signer_tbs;
    /* Nonzero only if the OS verified the signature chain. An unverified
     * signature must never satisfy a publisher rule. */
    int signer_verified;

    /* Lower-cased, normalised, NOT NUL-terminated. */
    const char  *path;
    unsigned int path_len;
} fl_request;

/*
 * fl_decide returns the verdict for one image and, if reason is non-NULL,
 * why.
 *
 * Guaranteed properties, each pinned by a test:
 *
 *  1. A NULL ruleset, or one with no rules of any kind, ALLOWS everything.
 *     The driver loads before the service has pushed rules; failing closed
 *     there bricks the machine at boot.
 *  2. An image matching a self rule is ALWAYS allowed, ahead of every other
 *     check, in both modes.
 *  3. FL_MODE_AUDIT never returns FL_BLOCK.
 *  4. A publisher rule matches only when signer_verified is nonzero.
 *  5. Prefix path rules match only on a separator boundary, so a rule for
 *     "c:\program files" does not match "c:\program files evil\x.exe".
 */
fl_verdict fl_decide(const fl_ruleset *rs, const fl_request *req, fl_reason *reason);

/*
 * fl_ruleset_valid reports whether a ruleset is well formed: sorted hash and
 * publisher arrays, no NULL array with a nonzero count, no zero-length or
 * over-long path rule. Returns 1 when valid, 0 otherwise.
 *
 * A driver calls this when a ruleset arrives from user mode and REJECTS an
 * invalid one, keeping the previous ruleset. Binary search over an unsorted
 * array silently returns wrong answers, and "silently wrong" in this code
 * path means allowing something that should have been blocked.
 */
int fl_ruleset_valid(const fl_ruleset *rs);

/* Exposed for testing and for the driver's own normalisation step. */
int fl_hash_present(const unsigned char *sorted, unsigned int count, const unsigned char *needle);

#ifdef __cplusplus
}
#endif

#endif /* FL_DECISION_H */
