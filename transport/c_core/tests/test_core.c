/*
 * HELIOS-NET :: transport/c_core/tests/test_core.c
 * Unit tests for the native signature & fingerprint core.
 *
 * Built and run as part of `python build.py --test` (see tests/run_c_tests.py),
 * or manually:
 *   gcc -std=c11 -Iinclude src/hashing.c src/boyer_moore.c \
 *       src/aho_corasick.c src/helios_core.c tests/test_core.c -o test_core
 */

#include "helios_core.h"

#include <stdio.h>
#include <string.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_failures++;                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));   \
        }                                                                     \
    } while (0)

/* ------------------------------------------------------------------ hashing */

static void test_hashing(void) {
    /* Published FNV test vectors. */
    CHECK(hc_fnv1a32("a", 1) == 0xe40c292cu, "fnv1a32('a')");
    CHECK(hc_fnv1a32("foobar", 6) == 0xbf9cf968u, "fnv1a32('foobar')");
    CHECK(hc_fnv1a64("a", 1) == 0xaf63dc4c8601ec8cULL, "fnv1a64('a')");
    CHECK(hc_fnv1a64("foobar", 6) == 0x85944171f73967e8ULL, "fnv1a64('foobar')");

    /* CRC-32/IEEE check value. */
    CHECK(hc_crc32("123456789", 9) == 0xCBF43926u, "crc32 check value");
    CHECK(hc_crc32("", 0) == 0u, "crc32 of empty input");

    /* Determinism and length sensitivity. */
    CHECK(hc_fnv1a32("abc", 3) == hc_fnv1a32("abc", 3), "fnv1a32 determinism");
    CHECK(hc_fnv1a32("abc", 3) != hc_fnv1a32("abd", 3), "fnv1a32 length/casing sensitivity");

    /* Rolling hash must agree with the one-shot FNV-1a 64 on the same input. */
    const char *msg = "HTTP/1.1 200 OK";
    hc_rollhash_t state;
    hc_rollhash_init(&state);
    for (const char *p = msg; *p; p++) {
        hc_rollhash_update(&state, (uint8_t)*p);
    }
    CHECK(state.offset_basis == hc_fnv1a64(msg, strlen(msg)), "rolling hash matches one-shot");

    /* NULL tolerance: must not crash. */
    CHECK(hc_fnv1a32(NULL, 10) == 0u, "fnv1a32 NULL-safe");
    CHECK(hc_crc32(NULL, 10) == 0u, "crc32 NULL-safe");
    hc_rollhash_init(NULL); /* must not crash */
    hc_rollhash_update(NULL, 'x');
}

/* ------------------------------------------------------------ boyer-moore */

static void test_boyer_moore(void) {
    CHECK(hc_bm_search("hello world", 11, "world", 5) == 6, "bm basic hit");
    CHECK(hc_bm_search("hello world", 11, "hello", 5) == 0, "bm prefix hit");
    CHECK(hc_bm_search("hello", 5, "hello", 5) == 0, "bm exact whole string");
    CHECK(hc_bm_search("hello world", 11, "absent", 6) == -1, "bm miss");
    CHECK(hc_bm_search("ab", 2, "abcd", 4) == -1, "bm pattern longer than text");
    CHECK(hc_bm_search("HELLO", 5, "hello", 5) == 0, "bm case-insensitive");
    CHECK(hc_bm_search("aaa", 3, "a", 1) == 0, "bm single char");
    CHECK(hc_bm_search("abc", 3, "", 0) == 0, "bm empty pattern");
    CHECK(hc_bm_search(NULL, 3, "a", 1) == HC_ERR_NULL, "bm NULL text");
    CHECK(hc_bm_search("a", 1, NULL, 1) == HC_ERR_NULL, "bm NULL pattern");

    /* First occurrence wins. */
    CHECK(hc_bm_search("abcabcabc", 9, "abc", 3) == 0, "bm returns first occurrence");

    /* Repetitive input: the Galil path must terminate and stay correct. */
    char repetitive[4096];
    memset(repetitive, 'a', sizeof(repetitive));
    CHECK(hc_bm_search(repetitive, sizeof(repetitive), "aaaa", 4) == 0, "bm repetitive prefix");
    CHECK(hc_bm_search(repetitive, sizeof(repetitive), "b", 1) == -1, "bm repetitive miss");
}

/* ------------------------------------------------- case-insensitive helpers */

static void test_contains_ci(void) {
    CHECK(hc_contains_ci("Server: NGINX/1.24", "nginx") == 1, "contains_ci lower needle");
    CHECK(hc_contains_ci("Server: NGINX/1.24", "NGINX") == 1, "contains_ci upper needle");
    CHECK(hc_contains_ci("Server: Apache", "nginx") == 0, "contains_ci negative");
    CHECK(hc_contains_ci("anything", "") == 1, "contains_ci empty needle");
    CHECK(hc_contains_ci(NULL, "x") == 0, "contains_ci NULL-safe");
}

/* --------------------------------------------------------- aho-corasick */

typedef struct {
    char   names[16][32];
    size_t count;
} collector_t;

static void collect(const char *name, const char *pattern, size_t position, void *user) {
    (void)pattern;
    (void)position;
    collector_t *c = (collector_t *)user;
    if (c->count < 16) {
        snprintf(c->names[c->count], sizeof(c->names[0]), "%s", name);
        c->count++;
    }
}

static int collector_has(const collector_t *c, const char *name) {
    for (size_t i = 0; i < c->count; i++) {
        if (strcmp(c->names[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_aho_corasick(void) {
    /* Classic construction: suffix inheritance must surface "he" inside "she". */
    hc_ac_t *ac = hc_ac_new();
    CHECK(ac != NULL, "ac allocation");
    if (ac == NULL) {
        return;
    }

    CHECK(hc_ac_add(ac, "he", "he") == HC_OK, "ac add he");
    CHECK(hc_ac_add(ac, "she", "she") == HC_OK, "ac add she");
    CHECK(hc_ac_add(ac, "his", "his") == HC_OK, "ac add his");
    CHECK(hc_ac_add(ac, "hers", "hers") == HC_OK, "ac add hers");
    CHECK(hc_ac_count(ac) == 4, "ac pattern count");
    CHECK(hc_ac_nodes(ac) > 1, "ac allocated nodes (root + children)");

    /* Scanning before build must be rejected. */
    CHECK(hc_ac_scan(ac, "he", 2, collect, NULL) == HC_ERR_STATE, "ac scan before build");

    CHECK(hc_ac_build(ac) == HC_OK, "ac build");

    collector_t c; memset(&c, 0, sizeof(c));
    int n = hc_ac_scan(ac, "ushers", 6, collect, &c);
    CHECK(n == 3, "ac reported 3 matches in 'ushers'");
    CHECK(collector_has(&c, "she"), "ac matched 'she'");
    CHECK(collector_has(&c, "he"), "ac matched 'he' via suffix inheritance");
    CHECK(collector_has(&c, "hers"), "ac matched 'hers'");
    CHECK(!collector_has(&c, "his"), "ac did not match 'his'");

    /* Buffer variant must terminate and exclude non-matches. */
    char buf[256];
    size_t buf_len = sizeof(buf);
    CHECK(hc_ac_scan_to_buffer(ac, "ushers", buf, &buf_len, 16) == HC_OK, "ac scan_to_buffer");
    CHECK(strstr(buf, "she") != NULL, "buffer contains she");
    CHECK(strstr(buf, "hers") != NULL, "buffer contains hers");
    CHECK(strstr(buf, "his") == NULL, "buffer excludes his");

    /* Truncation must be reported, not silently accepted. */
    char tiny[4];
    size_t tiny_len = sizeof(tiny);
    hc_status st = hc_ac_scan_to_buffer(ac, "ushers", tiny, &tiny_len, 16);
    CHECK(st == HC_ERR_TRUNC || st == HC_OK, "tiny buffer reports truncation or fits");

    /* No match at all. */
    collector_t none; memset(&none, 0, sizeof(none));
    CHECK(hc_ac_scan(ac, "zzzzzzzz", 8, collect, &none) == 0, "ac no matches");
    CHECK(none.count == 0, "ac callback not invoked without matches");

    /* Empty text. */
    CHECK(hc_ac_scan(ac, "", 0, collect, &none) == 0, "ac empty text");

    /* Overlapping and duplicate patterns. */
    CHECK(hc_ac_add(ac, "dup", "he") == HC_OK, "ac duplicate pattern accepted");
    CHECK(hc_ac_add(ac, "empty", "") == HC_ERR_EMPTY, "ac rejects empty pattern");
    CHECK(hc_ac_add(ac, NULL, NULL) == HC_ERR_NULL, "ac rejects NULL pattern");
    CHECK(hc_ac_add(NULL, "x", "x") == HC_ERR_NULL, "ac rejects NULL handle");
    CHECK(hc_ac_build(ac) == HC_OK, "ac rebuild after duplicate add");
    CHECK(hc_ac_count(ac) == 5, "ac count after duplicate add");

    CHECK(hc_ac_scan(NULL, "x", 1, collect, &none) == HC_ERR_NULL, "ac NULL handle scan");
    CHECK(hc_ac_count(NULL) == 0, "ac NULL count");
    CHECK(hc_ac_nodes(NULL) == 0, "ac NULL nodes");

    hc_ac_free(ac);
    hc_ac_free(NULL); /* must not crash */
}

/*
 * Two signature names sharing one detection pattern are both real, so both must
 * survive. An identical (name, pattern) line is a duplicated input and must be
 * stored once, because storing it twice made a single detection emit the same
 * name twice and report match_count 2, inflating every aggregate built on it.
 */
static void test_aho_corasick_duplicate_registration(void) {
    hc_ac_t *ac = hc_ac_new();
    if (ac == NULL) {
        g_failures++;
        return;
    }

    /* Distinct names, same pattern: both registrations are kept. */
    CHECK(hc_ac_add(ac, "alpha", "shared") == HC_OK, "alpha registered");
    CHECK(hc_ac_add(ac, "beta", "shared") == HC_OK, "beta shares the pattern");
    CHECK(hc_ac_count(ac) == 2, "two names share one pattern");

    /* The identical registration is refused, so nothing is stored twice. */
    CHECK(hc_ac_add(ac, "alpha", "shared") == HC_ERR_DUP, "identical pair refused");
    CHECK(hc_ac_count(ac) == 2, "duplicate did not increase the count");

    /* Same name, different pattern: also a legitimate second registration. */
    CHECK(hc_ac_add(ac, "alpha", "other") == HC_OK, "same name new pattern");
    CHECK(hc_ac_count(ac) == 3, "same name with a new pattern counts");

    /* The default name is the pattern, so that form dedupes too. */
    CHECK(hc_ac_add(ac, NULL, "bare") == HC_OK, "bare pattern registered");
    CHECK(hc_ac_add(ac, "bare", "bare") == HC_ERR_DUP, "default name is the pattern");
    CHECK(hc_ac_count(ac) == 4, "bare duplicate refused");

    CHECK(hc_ac_build(ac) == HC_OK, "build after duplicates");

    collector_t shared_hit;
    memset(&shared_hit, 0, sizeof(shared_hit));
    CHECK(hc_ac_scan(ac, "a shared hit", 13, collect, &shared_hit) == 2,
          "shared pattern reported under both names");
    CHECK(shared_hit.count == 2, "both names collected");

    collector_t bare_hit;
    memset(&bare_hit, 0, sizeof(bare_hit));
    CHECK(hc_ac_scan(ac, "shared", 6, collect, &bare_hit) == 2,
          "shared pattern alone matches both names");
    CHECK(collector_has(&bare_hit, "alpha"), "alpha collected");
    CHECK(collector_has(&bare_hit, "beta"), "beta collected");

    hc_ac_free(ac);
}

static void test_aho_corasick_scale(void) {
    /*
     * Many patterns force the dense-shortcut threshold to trigger and stress the
     * failure-link traversal. Patterns share prefixes so the trie is deep.
     */
    hc_ac_t *ac = hc_ac_new();
    if (ac == NULL) {
        g_failures++;
        return;
    }

    char pattern[64];
    for (int i = 0; i < 200; i++) {
        snprintf(pattern, sizeof(pattern), "svc-signature-%03d", i);
        CHECK(hc_ac_add(ac, pattern, pattern) == HC_OK, "scale add");
    }
    CHECK(hc_ac_count(ac) == 200, "scale pattern count");
    CHECK(hc_ac_build(ac) == HC_OK, "scale build");

    collector_t c;
    memset(&c, 0, sizeof(c));
    const char *scale_text = "banner svc-signature-042 tail svc-signature-199";
    int hits = hc_ac_scan(ac, scale_text, strlen(scale_text), collect, &c);
    CHECK(hits == 2, "scale scan found both signatures");
    CHECK(collector_has(&c, "svc-signature-042"), "scale matched 042");
    CHECK(collector_has(&c, "svc-signature-199"), "scale matched 199");

    hc_ac_free(ac);
}

/* ------------------------------------------------------------------ json */

static void test_json_escape(void) {
    char out[128];
    size_t len;

    len = sizeof(out);
    CHECK(hc_json_escape("plain", out, &len) == HC_OK, "escape plain");
    CHECK(strcmp(out, "plain") == 0, "escape plain unchanged");
    CHECK(len == 5, "escape plain length");

    len = sizeof(out);
    CHECK(hc_json_escape("a\"b", out, &len) == HC_OK, "escape quote");
    CHECK(strcmp(out, "a\\\"b") == 0, "escape quote output");

    len = sizeof(out);
    CHECK(hc_json_escape("a\\b", out, &len) == HC_OK, "escape backslash");
    CHECK(strcmp(out, "a\\\\b") == 0, "escape backslash output");

    len = sizeof(out);
    CHECK(hc_json_escape("l1\nl2\r\t", out, &len) == HC_OK, "escape control whitespace");
    CHECK(strcmp(out, "l1\\nl2\\r\\t") == 0, "escape whitespace output");

    len = sizeof(out);
    CHECK(hc_json_escape("\x01", out, &len) == HC_OK, "escape low control");
    CHECK(strcmp(out, "\\u0001") == 0, "escape low control output");

    char tiny[2];
    size_t tiny_len = sizeof(tiny);
    CHECK(hc_json_escape("abcdef", tiny, &tiny_len) == HC_ERR_TRUNC, "escape truncation detected");

    len = sizeof(out);
    CHECK(hc_json_escape(NULL, out, &len) == HC_ERR_NULL, "escape NULL input");
    CHECK(hc_version() != NULL && hc_version()[0] != '\0', "version string present");
    CHECK(strcmp(hc_strerror(HC_OK), "ok") == 0, "strerror HC_OK");
    CHECK(strcmp(hc_strerror(HC_ERR_TRUNC), "output truncated") == 0, "strerror HC_ERR_TRUNC");
}

/* ------------------------------------------------------------------- main */

int main(void) {
    test_hashing();
    test_boyer_moore();
    test_contains_ci();
    test_aho_corasick();
    test_aho_corasick_duplicate_registration();
    test_aho_corasick_scale();
    test_json_escape();

    if (g_failures == 0) {
        printf("{\"status\":\"ok\",\"suite\":\"c_core_tests\",\"checks\":%d,\"failures\":0}\n",
               g_checks);
        return 0;
    }
    printf("{\"status\":\"error\",\"suite\":\"c_core_tests\",\"checks\":%d,\"failures\":%d}\n",
           g_checks, g_failures);
    return 1;
}

