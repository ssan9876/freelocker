/*
 * Tests for the decision core.
 *
 * Plain C with a three-line assert harness, so this builds with cl, clang or
 * gcc and needs nothing installed beyond a C compiler. The point is that the
 * logic deciding whether a program may run is verifiable on any machine,
 * today, with no signed driver and no VM.
 */

#include <stdio.h>
#include "../fl_decision.h"

static int failures;
static int checks;

#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        checks++;                                                         \
        if (!(cond)) {                                                    \
            failures++;                                                   \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));        \
        }                                                                 \
    } while (0)

/* Build a 32-byte hash whose every byte is v, so ordering is obvious. */
static void mkhash(unsigned char *out, unsigned char v)
{
    int i;
    for (i = 0; i < FL_HASH_LEN; i++) {
        out[i] = v;
    }
}

static unsigned int slen(const char *s)
{
    unsigned int n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

static fl_path_rule rule(fl_path_kind kind, const char *p)
{
    fl_path_rule r;
    r.kind = kind;
    r.path = p;
    r.len = slen(p);
    return r;
}

static fl_request req_path(const char *p)
{
    fl_request q;
    q.sha256 = 0;
    q.signer_tbs = 0;
    q.signer_verified = 0;
    q.path = p;
    q.path_len = slen(p);
    return q;
}

/* ---------------------------------------------------------------------- */

/* Property 1. The driver loads at boot, before the service has pushed any
 * rules. Failing closed in that window blocks every program on the machine
 * including the service that would fix it. This is the single most important
 * behaviour in the file. */
static void test_fails_open_without_rules(void)
{
    fl_ruleset rs;
    fl_reason why;
    fl_request q = req_path("c:\\users\\u\\downloads\\anything.exe");

    CHECK(fl_decide(0, &q, &why) == FL_ALLOW, "NULL ruleset must allow");
    CHECK(why == FL_REASON_NO_RULESET, "NULL ruleset reason");

    /* An empty ruleset in ENFORCE mode is the dangerous case: a naive
     * implementation blocks the world here. */
    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = 0; rs.hash_count = 0;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = 0; rs.path_count = 0;
    rs.self = 0; rs.self_count = 0;
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "empty enforce ruleset must allow");
    CHECK(why == FL_REASON_NO_RULESET, "empty ruleset reason");

    /* A NULL request is a bug in our own code; it must not become an
     * unbootable machine. */
    CHECK(fl_decide(&rs, 0, &why) == FL_ALLOW, "NULL request must allow");
}

/* Property 2. If a bad ruleset can stop the agent running, it can stop the
 * fix arriving, and recovery becomes a desk visit. */
static void test_self_is_never_blocked(void)
{
    unsigned char h[FL_HASH_LEN];
    fl_path_rule selfs[2];
    fl_ruleset rs;
    fl_reason why;
    fl_request q;

    mkhash(h, 0x11);
    selfs[0] = rule(FL_PATH_EXACT, "c:\\program files\\freelocker\\freelocker-agent.exe");
    selfs[1] = rule(FL_PATH_EXACT, "c:\\program files\\freelocker\\agent-updater.exe");

    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = h; rs.hash_count = 1;      /* a ruleset that allows something else */
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = 0; rs.path_count = 0;
    rs.self = selfs; rs.self_count = 2;

    q = req_path("c:\\program files\\freelocker\\freelocker-agent.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "agent image must be allowed");
    CHECK(why == FL_REASON_SELF, "agent allowed for the self reason");

    q = req_path("c:\\program files\\freelocker\\agent-updater.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "updater must be allowed");

    /* Something else in the same directory is NOT self. */
    q = req_path("c:\\program files\\freelocker\\evil.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "a stranger beside the agent is not self");
}

/* Property 3. Audit mode is what makes a safe rollout possible; if it can
 * ever block, the whole staged-deployment story collapses. */
static void test_audit_never_blocks(void)
{
    unsigned char h[FL_HASH_LEN];
    fl_ruleset rs;
    fl_reason why;
    fl_request q = req_path("c:\\users\\u\\downloads\\unapproved.exe");

    mkhash(h, 0x22);
    rs.mode = FL_MODE_AUDIT;
    rs.hashes = h; rs.hash_count = 1;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = 0; rs.path_count = 0;
    rs.self = 0; rs.self_count = 0;

    CHECK(fl_decide(&rs, &q, &why) == FL_WOULD_BLOCK, "audit reports instead of blocking");
    CHECK(why == FL_REASON_NO_MATCH, "audit still explains why");

    /* Same ruleset, enforce mode: now it blocks. Pinning both directions
     * means the mode is actually consulted rather than incidentally right. */
    rs.mode = FL_MODE_ENFORCE;
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "enforce blocks the same request");
}

static void test_hash_allow(void)
{
    unsigned char hashes[3 * FL_HASH_LEN];
    unsigned char wanted[FL_HASH_LEN], absent[FL_HASH_LEN];
    fl_ruleset rs;
    fl_reason why;
    fl_request q;

    mkhash(hashes + 0 * FL_HASH_LEN, 0x10);
    mkhash(hashes + 1 * FL_HASH_LEN, 0x20);
    mkhash(hashes + 2 * FL_HASH_LEN, 0x30);
    mkhash(wanted, 0x20);
    mkhash(absent, 0x99);

    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = hashes; rs.hash_count = 3;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = 0; rs.path_count = 0;
    rs.self = 0; rs.self_count = 0;

    q = req_path("c:\\app.exe");
    q.sha256 = wanted;
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "allowed hash runs");
    CHECK(why == FL_REASON_HASH, "allowed for the hash reason");

    q.sha256 = absent;
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "unlisted hash is blocked");

    /* An image we could not hash must not accidentally match. */
    q.sha256 = 0;
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "unhashable image does not match a hash rule");
}

/* Every element must be findable, at every position — a binary search that is
 * wrong only at the boundaries silently blocks explicitly-allowed software,
 * which is the failure users would report as "your product is broken". */
static void test_binary_search_finds_every_element(void)
{
    unsigned char set[64 * FL_HASH_LEN];
    unsigned char needle[FL_HASH_LEN];
    int i;

    for (i = 0; i < 64; i++) {
        mkhash(set + (i * FL_HASH_LEN), (unsigned char)(i * 4)); /* 0,4,...252 */
    }
    for (i = 0; i < 64; i++) {
        mkhash(needle, (unsigned char)(i * 4));
        CHECK(fl_hash_present(set, 64, needle) == 1, "every present element is found");
    }
    /* Values between, below and above the set must not be found. */
    for (i = 0; i < 64; i++) {
        mkhash(needle, (unsigned char)(i * 4 + 1));
        CHECK(fl_hash_present(set, 64, needle) == 0, "absent element is not found");
    }
    CHECK(fl_hash_present(set, 0, needle) == 0, "empty set finds nothing");
    CHECK(fl_hash_present(0, 5, needle) == 0, "NULL set finds nothing");
}

/* Property 4. Anyone can attach a certificate claiming any subject; only the
 * OS saying the chain verified makes it evidence. */
static void test_publisher_requires_verified_signature(void)
{
    unsigned char pubs[FL_HASH_LEN];
    unsigned char tbs[FL_HASH_LEN];
    fl_ruleset rs;
    fl_reason why;
    fl_request q;

    mkhash(pubs, 0x55);
    mkhash(tbs, 0x55);

    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = 0; rs.hash_count = 0;
    rs.publishers = pubs; rs.publisher_count = 1;
    rs.paths = 0; rs.path_count = 0;
    rs.self = 0; rs.self_count = 0;

    q = req_path("c:\\app.exe");
    q.signer_tbs = tbs;
    q.signer_verified = 1;
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "verified publisher is allowed");
    CHECK(why == FL_REASON_PUBLISHER, "allowed for the publisher reason");

    /* Same certificate bytes, but the OS did not verify the chain. This is
     * the forgery case and it must not be allowed. */
    q.signer_verified = 0;
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "unverified signature must not satisfy a publisher rule");
}

/* Property 5. The same substring-vs-component bug that had to be fixed twice
 * in the ringfencing parser. */
static void test_prefix_matches_only_on_a_boundary(void)
{
    fl_path_rule paths[1];
    fl_ruleset rs;
    fl_reason why;
    fl_request q;

    paths[0] = rule(FL_PATH_PREFIX, "c:\\program files");

    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = 0; rs.hash_count = 0;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = paths; rs.path_count = 1;
    rs.self = 0; rs.self_count = 0;

    q = req_path("c:\\program files\\vendor\\app.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "a file under the directory is covered");
    CHECK(why == FL_REASON_PATH, "allowed for the path reason");

    /* The attack: a sibling directory sharing the prefix as a substring. */
    q = req_path("c:\\program files evil\\payload.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "a sibling directory must NOT be covered");

    /* A rule that already ends in a separator has consumed the boundary. */
    paths[0] = rule(FL_PATH_PREFIX, "c:\\program files\\");
    q = req_path("c:\\program files\\vendor\\app.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "trailing-separator rule still covers");
    q = req_path("c:\\program files evil\\payload.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "trailing-separator rule rejects the sibling");

    /* Exact rules do not cover children at all. */
    paths[0] = rule(FL_PATH_EXACT, "c:\\tools\\app.exe");
    q = req_path("c:\\tools\\app.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "exact rule covers the file itself");
    q = req_path("c:\\tools\\app.exe.bak.exe");
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "exact rule does not cover a longer path");
    q = req_path("c:\\tools\\app.ex");
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "exact rule does not cover a shorter path");
}

static void test_unknown_image_is_distinguishable(void)
{
    unsigned char h[FL_HASH_LEN];
    fl_ruleset rs;
    fl_reason why;
    fl_request q;

    mkhash(h, 0x77);
    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = h; rs.hash_count = 1;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = 0; rs.path_count = 0;
    rs.self = 0; rs.self_count = 0;

    q.sha256 = 0; q.signer_tbs = 0; q.signer_verified = 0; q.path = 0; q.path_len = 0;
    CHECK(fl_decide(&rs, &q, &why) == FL_BLOCK, "an unidentifiable image is still blocked in enforce");
    CHECK(why == FL_REASON_UNKNOWN_IMAGE, "but it is reported as unidentifiable, not merely unmatched");
}

/* A malformed ruleset must be rejected at the door. Binary search over an
 * unsorted array returns wrong answers silently, and "silently wrong" here
 * means allowing something that should have been blocked. */
static void test_ruleset_validation(void)
{
    unsigned char sorted[3 * FL_HASH_LEN];
    unsigned char unsorted[3 * FL_HASH_LEN];
    unsigned char dupes[2 * FL_HASH_LEN];
    fl_path_rule paths[1];
    fl_ruleset rs;

    mkhash(sorted + 0 * FL_HASH_LEN, 0x10);
    mkhash(sorted + 1 * FL_HASH_LEN, 0x20);
    mkhash(sorted + 2 * FL_HASH_LEN, 0x30);

    mkhash(unsorted + 0 * FL_HASH_LEN, 0x30);
    mkhash(unsorted + 1 * FL_HASH_LEN, 0x10);
    mkhash(unsorted + 2 * FL_HASH_LEN, 0x20);

    mkhash(dupes + 0 * FL_HASH_LEN, 0x10);
    mkhash(dupes + 1 * FL_HASH_LEN, 0x10);

    paths[0] = rule(FL_PATH_EXACT, "c:\\ok.exe");

    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = sorted; rs.hash_count = 3;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = paths; rs.path_count = 1;
    rs.self = 0; rs.self_count = 0;
    CHECK(fl_ruleset_valid(&rs) == 1, "a well-formed ruleset is accepted");

    rs.hashes = unsorted;
    CHECK(fl_ruleset_valid(&rs) == 0, "an unsorted hash array is rejected");

    rs.hashes = dupes; rs.hash_count = 2;
    CHECK(fl_ruleset_valid(&rs) == 0, "duplicate hashes are rejected as malformed");

    rs.hashes = sorted; rs.hash_count = 3;
    rs.hashes = 0;
    CHECK(fl_ruleset_valid(&rs) == 0, "a NULL array with a nonzero count is rejected");

    rs.hashes = sorted; rs.hash_count = 3;
    paths[0].len = 0;
    CHECK(fl_ruleset_valid(&rs) == 0, "a zero-length path rule is rejected");

    paths[0] = rule(FL_PATH_EXACT, "c:\\ok.exe");
    rs.mode = (fl_mode)42;
    CHECK(fl_ruleset_valid(&rs) == 0, "an unknown mode is rejected");

    CHECK(fl_ruleset_valid(0) == 0, "a NULL ruleset is not valid");
}

/* Ordering matters: a self rule must win over a ruleset that would otherwise
 * block, and a hash allow must not be reachable only by accident. */
static void test_precedence(void)
{
    unsigned char h[FL_HASH_LEN], other[FL_HASH_LEN];
    fl_path_rule selfs[1];
    fl_ruleset rs;
    fl_reason why;
    fl_request q;

    mkhash(h, 0x10);
    mkhash(other, 0xF0);
    selfs[0] = rule(FL_PATH_EXACT, "c:\\program files\\freelocker\\freelocker-agent.exe");

    rs.mode = FL_MODE_ENFORCE;
    rs.hashes = h; rs.hash_count = 1;
    rs.publishers = 0; rs.publisher_count = 0;
    rs.paths = 0; rs.path_count = 0;
    rs.self = selfs; rs.self_count = 1;

    /* The agent, with a hash that is NOT allowed — e.g. straight after an
     * update, before the new hash reaches the ruleset. It must still run. */
    q = req_path("c:\\program files\\freelocker\\freelocker-agent.exe");
    q.sha256 = other;
    CHECK(fl_decide(&rs, &q, &why) == FL_ALLOW, "self wins over an unlisted hash");
    CHECK(why == FL_REASON_SELF, "and is reported as self");
}

int main(void)
{
    test_fails_open_without_rules();
    test_self_is_never_blocked();
    test_audit_never_blocks();
    test_hash_allow();
    test_binary_search_finds_every_element();
    test_publisher_requires_verified_signature();
    test_prefix_matches_only_on_a_boundary();
    test_unknown_image_is_distinguishable();
    test_ruleset_validation();
    test_precedence();

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
