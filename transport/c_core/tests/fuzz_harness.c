/*
 * HELIOS-NET :: transport/c_core/tests/fuzz_harness.c
 *
 * A deterministic differential fuzzer for the native core.
 *
 * The project has no libFuzzer on this host and no ASan (the MinGW toolchain
 * has no libasan), so this harness covers the two failure modes that actually
 * bit this code, using only C11 and libc:
 *
 *   1. WRONG ANSWERS. Every randomised search is compared against a naive
 *      oracle computed independently in this file. Aho-Corasick and
 *      Boyer-Moore are compared against a plain O(n*m) substring scan, so a
 *      broken failure link or a bad-character table shows up as a mismatch
 *      rather than as a silently missed signature.
 *
 *   2. BUFFER OVERRUNS. Every output call runs against a heap buffer padded
 *      with a guard pattern. The real `on_match` bug in main.c wrote past a
 *      stack entry because it trusted `snprintf`'s return value as a length
 *      before checking for truncation; guard bytes catch that class directly,
 *      and would have caught it without a sanitizer.
 *
 * The PRNG is seeded from a constant so any failure reproduces exactly. There
 * is no clock and no /dev/urandom, which keeps CI runs deterministic.
 *
 * Exit status is 0 when every check passed, 1 otherwise.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "helios_core.h"

/* ------------------------------------------------------------------ config */

#define FUZZ_ROUNDS      4000
#define MAX_LINE         4096
#define MAX_PATTERNS     16
#define MAX_NAME         64
#define GUARD_BYTES      64
#define GUARD_FILL       0xA5

static unsigned long g_checks = 0;
static unsigned long g_failures = 0;

static void fail(const char *what, const char *detail)
{
    g_failures++;
    if (g_failures <= 20) {
        fprintf(stderr, "FAIL: %s: %s\n", what, detail ? detail : "");
    }
}

static void check(int condition, const char *what, const char *detail)
{
    g_checks++;
    if (!condition) {
        fail(what, detail);
    }
}

/* -------------------------------------------------------------------- PRNG */

/* xorshift64*: deterministic, adequate for shaking out logic errors. */
static uint64_t g_state = 0x9E3779B97F4A7C15ULL;

static uint64_t rng_next(void)
{
    uint64_t x = g_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static size_t rng_below(size_t n)
{
    return n == 0 ? 0 : (size_t)(rng_next() % (uint64_t)n);
}

/*
 * Bytes are drawn from an alphabet that stresses case folding, the
 * bad-character rule and JSON escaping, plus an occasional full-range byte so
 * non-ASCII input reaches the matching code.
 */
static const char ALPHABET[] = "aAbBzZ019_-. \t\n\r\"\\/\x7f\x01\xc3\xa9";

static char rng_char(void)
{
    if (rng_next() % 16 == 0) {
        return (char)(rng_next() & 0xFF);
    }
    return ALPHABET[rng_below(sizeof(ALPHABET) - 1)];
}

/* ------------------------------------------------------------ guard buffer */

typedef struct {
    unsigned char *raw;     /* allocation, including guard padding */
    char          *data;    /* usable region handed to the core     */
    size_t          cap;     /* usable capacity                     */
} guarded_t;

static void guarded_alloc(guarded_t *g, size_t cap)
{
    g->raw = (unsigned char *)malloc(cap + GUARD_BYTES);
    if (!g->raw) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    memset(g->raw, GUARD_FILL, cap + GUARD_BYTES);
    g->data = (char *)g->raw;
    g->cap = cap;
}

static int guarded_intact(const guarded_t *g, const char *what)
{
    for (size_t i = 0; i < GUARD_BYTES; i++) {
        if (g->raw[g->cap + i] != GUARD_FILL) {
            check(0, what, "guard byte after the buffer was overwritten");
            return 0;
        }
    }
    return 1;
}

static void guarded_free(guarded_t *g)
{
    free(g->raw);
    g->raw = NULL;
    g->data = NULL;
    g->cap = 0;
}

/* ------------------------------------------------------------------ oracle */

static int ci_equal(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

/*
 * Naive case-insensitive substring search, mirroring the documented contract:
 * an empty pattern matches at offset 0, otherwise the leftmost occurrence is
 * returned, or -1. Random bytes can produce an empty pattern, because a 0x00
 * drawn from the full-range branch truncates the pattern at strlen time.
 */
static long naive_find(const char *text, size_t tlen,
                       const char *pat, size_t plen)
{
    if (plen == 0) {
        return 0;
    }
    if (plen > tlen) {
        return -1;
    }
    for (size_t i = 0; i + plen <= tlen; i++) {
        if (ci_equal(text + i, pat, plen)) {
            return (long)i;
        }
    }
    return -1;
}

typedef struct {
    int    pattern;   /* index into the harness pattern table */
    size_t position;
} pair_t;

static int pair_cmp(const void *a, const void *b)
{
    const pair_t *x = (const pair_t *)a;
    const pair_t *y = (const pair_t *)b;
    if (x->position != y->position) {
        return x->position < y->position ? -1 : 1;
    }
    if (x->pattern != y->pattern) {
        return x->pattern < y->pattern ? -1 : 1;
    }
    return 0;
}

/* --------------------------------------------------------------- collection */

typedef struct {
    pair_t  *items;
    size_t   len;
    size_t   cap;
    char   (*names)[MAX_NAME];
    size_t   name_count;
} found_t;

static void found_init(found_t *f, size_t cap)
{
    f->items = (pair_t *)calloc(cap ? cap : 1, sizeof(pair_t));
    f->names = calloc(MAX_PATTERNS, MAX_NAME);
    f->len = 0;
    f->cap = cap;
    f->name_count = 0;
}

static void found_free(found_t *f)
{
    free(f->items);
    free(f->names);
}

static int name_index(const found_t *f, const char *name)
{
    for (size_t i = 0; i < f->name_count; i++) {
        if (strcmp(f->names[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void on_match(const char *name, const char *pattern,
                     size_t position, void *user)
{
    found_t *f = (found_t *)user;
    (void)pattern;
    if (f->len < f->cap) {
        f->items[f->len].pattern = name_index(f, name);
        f->items[f->len].position = position;
        f->len++;
    }
}

/* ---------------------------------------------- Aho-Corasick vs the oracle */

static void fuzz_aho(void)
{
    char text[MAX_LINE + 1];
    char pats[MAX_PATTERNS][MAX_NAME];

    for (unsigned round = 0; round < FUZZ_ROUNDS; round++) {
        size_t tlen = rng_below(160);
        for (size_t i = 0; i < tlen; i++) {
            text[i] = rng_char();
        }
        text[tlen] = '\0';

        size_t npats = 1 + rng_below(MAX_PATTERNS);
        for (size_t i = 0; i < npats; i++) {
            size_t plen = 1 + rng_below(6);
            /*
             * The pattern embeds its own index so every needle is unique. The
             * core de-duplicates by needle, so a repeated needle under two
             * names would legitimately report one name while the oracle counts
             * two, and that difference is not a defect.
             */
            snprintf(pats[i], MAX_NAME, "k%zu-%.*s", i, (int)plen, text);
            if (strlen(pats[i]) > 20) {
                pats[i][20] = '\0';
            }
        }

        found_t got;
        found_init(&got, MAX_PATTERNS * (tlen ? tlen : 1) + 8);
        for (size_t i = 0; i < npats; i++) {
            snprintf(got.names[i], MAX_NAME, "sig%zu", i);
            got.name_count = npats;
        }

        hc_ac_t *ac = hc_ac_new();
        if (!ac) {
            check(0, "hc_ac_new", "returned NULL");
            found_free(&got);
            return;
        }
        hc_status st = HC_OK;
        for (size_t i = 0; i < npats; i++) {
            st = hc_ac_add(ac, got.names[i], pats[i]);
            if (st != HC_OK) {
                break;
            }
        }
        if (st == HC_OK) {
            st = hc_ac_build(ac);
        }
        if (st != HC_OK) {
            check(0, "hc_ac_add/build", hc_strerror(st));
            hc_ac_free(ac);
            found_free(&got);
            continue;
        }

        int reported = hc_ac_scan(ac, text, tlen, on_match, &got);
        check(reported >= 0, "hc_ac_scan", "returned a negative status");

        /* Oracle: every occurrence of every pattern, independent of the trie. */
        pair_t want[MAX_PATTERNS * 200];
        size_t want_len = 0;
        for (size_t i = 0; i < npats; i++) {
            size_t plen = strlen(pats[i]);
            for (size_t p = 0; p + plen <= tlen; p++) {
                if (ci_equal(text + p, pats[i], plen)) {
                    if (want_len < sizeof(want) / sizeof(want[0])) {
                        want[want_len].pattern = (int)i;
                        want[want_len].position = p;
                        want_len++;
                    }
                }
            }
        }

        /* Every reported position must lie inside the text. */
        for (size_t i = 0; i < got.len; i++) {
            if (got.items[i].position >= tlen) {
                check(0, "hc_ac_scan position",
                      "a match was reported past the end of the text");
                break;
            }
            if (got.items[i].pattern < 0) {
                check(0, "hc_ac_scan name", "callback received an unknown name");
                break;
            }
            /* The bytes at the reported offset must really match. */
            size_t plen = strlen(pats[got.items[i].pattern]);
            if (got.items[i].position + plen > tlen ||
                !ci_equal(text + got.items[i].position,
                          pats[got.items[i].pattern], plen)) {
                check(0, "hc_ac_scan position",
                      "a reported offset does not actually match the pattern");
                break;
            }
        }

        qsort(got.items, got.len, sizeof(pair_t), pair_cmp);
        qsort(want, want_len, sizeof(pair_t), pair_cmp);

        check(got.len == want_len, "aho match count",
              "differed from the naive oracle");
        size_t common = got.len < want_len ? got.len : want_len;
        for (size_t i = 0; i < common; i++) {
            if (got.items[i].pattern != want[i].pattern ||
                got.items[i].position != want[i].position) {
                check(0, "aho match set",
                      "differed from the naive oracle");
                break;
            }
        }

        hc_ac_free(ac);
        found_free(&got);
    }
}

/* ------------------------------------------- Boyer-Moore vs the oracle */

static void fuzz_boyer_moore(void)
{
    char text[MAX_LINE + 1];
    char pat[MAX_NAME];

    for (unsigned round = 0; round < FUZZ_ROUNDS; round++) {
        size_t tlen = rng_below(200);
        for (size_t i = 0; i < tlen; i++) {
            text[i] = rng_char();
        }
        text[tlen] = '\0';

        size_t plen = 1 + rng_below(8);
        for (size_t i = 0; i < plen && i < MAX_NAME - 1; i++) {
            pat[i] = rng_char();
        }
        pat[plen < MAX_NAME ? plen : MAX_NAME - 1] = '\0';
        plen = strlen(pat);

        int got = hc_bm_search(text, tlen, pat, plen);
        long want = naive_find(text, tlen, pat, plen);
        check((long)got == want, "hc_bm_search",
              "first-match offset differed from the naive oracle");
    }
}

/* ------------------------------------- output buffers vs guard bytes */

/*
 * The overrun this guards against lived in main.c's on_match, which sized a
 * stack entry, wrote a signature name into it, then copied using the length
 * snprintf reported. When the name was longer than the entry, snprintf
 * returned the length it *wanted* to write, and the following memcpy read past
 * the end of the name.
 */
static void fuzz_scan_to_buffer(void)
{
    char name[MAX_NAME];

    for (unsigned round = 0; round < 600; round++) {
        size_t nlen = 1 + rng_below(120);
        for (size_t i = 0; i < nlen && i < MAX_NAME - 1; i++) {
            name[i] = ALPHABET[rng_below(sizeof(ALPHABET) - 1)];
        }
        name[nlen < MAX_NAME ? nlen : MAX_NAME - 1] = '\0';

        hc_ac_t *ac = hc_ac_new();
        if (!ac) {
            check(0, "hc_ac_new", "returned NULL");
            return;
        }
        char marker[MAX_NAME];
        snprintf(marker, sizeof(marker), "SIG-%u", round);
        if (hc_ac_add(ac, marker, "needle") != HC_OK ||
            hc_ac_build(ac) != HC_OK) {
            check(0, "hc_ac_add/build", "rejected a valid pattern");
            hc_ac_free(ac);
            continue;
        }
        /* Force a real match so the buffer path is exercised. */
        char haystack[MAX_LINE + 1];
        snprintf(haystack, sizeof(haystack), "x %s y needle z", name);

        for (int tight = 0; tight < 3; tight++) {
            size_t cap = (size_t)(rng_below(200) + 1);
            guarded_t g;
            guarded_alloc(&g, cap);
            size_t out_len = g.cap;

            hc_status st = hc_ac_scan_to_buffer(ac, haystack, g.data, &out_len, 4);
            check(st == HC_OK || st == HC_ERR_TRUNC,
                  "hc_ac_scan_to_buffer status", "returned an unexpected status");
            check(out_len <= g.cap, "hc_ac_scan_to_buffer out_len",
                  "reported a length beyond the supplied capacity");
            if (guarded_intact(&g, "hc_ac_scan_to_buffer")) {
                /* The written region must always be NUL-terminated, on the
                 * success path and on the truncation path alike. */
                if (out_len > 0 && out_len < g.cap) {
                    check(g.data[out_len] == '\0', "hc_ac_scan_to_buffer terminator",
                          "output is not NUL-terminated after writing out_len bytes");
                }
            }
            guarded_free(&g);
        }

        /*
         * A zero-capacity buffer is the regression guard for the off-by-one
         * that wrote out[0] before reading *out_len. The guard byte immediately
         * after the zero-length region catches it.
         */
        {
            guarded_t z;
            guarded_alloc(&z, 0);
            size_t zero_len = 0;
            hc_status zst = hc_ac_scan_to_buffer(ac, haystack, z.data, &zero_len, 4);
            check(zst == HC_ERR_TRUNC, "hc_ac_scan_to_buffer zero capacity",
                  "did not report truncation for a zero-capacity buffer");
            guarded_intact(&z, "hc_ac_scan_to_buffer zero capacity");
            guarded_free(&z);
        }
        hc_ac_free(ac);
    }
}

/* --------------------------------------------------- JSON escape round-trip */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Reverses exactly the escape rules hc_json_escape emits, and rejects anything
 * it does not recognise. Returns the recovered length, or -1 on a malformed
 * sequence, a dangling backslash, a raw control byte, or an escape that could
 * not have come from this escaper.
 */
static long json_unescape(const char *esc, size_t n, char *out, size_t out_cap)
{
    size_t o = 0;
    for (size_t i = 0; i < n; ) {
        unsigned char c = (unsigned char)esc[i];
        if (c != '\\') {
            if (c < 0x20) {
                return -1; /* a raw control byte must never survive */
            }
            if (o + 1 >= out_cap) {
                return -1;
            }
            out[o++] = (char)c;
            i++;
            continue;
        }
        if (i + 1 >= n) {
            return -1; /* dangling backslash */
        }
        char e = esc[i + 1];
        size_t adv = 2;
        char decoded;
        switch (e) {
            case '"':  decoded = '"';  break;
            case '\\': decoded = '\\'; break;
            case 'b':  decoded = '\b'; break;
            case 'f':  decoded = '\f'; break;
            case 'n':  decoded = '\n'; break;
            case 'r':  decoded = '\r'; break;
            case 't':  decoded = '\t'; break;
            case 'u': {
                if (i + 5 >= n) {
                    return -1;
                }
                /* The escaper only ever emits \u00XX for a byte below 0x20. */
                if (esc[i + 2] != '0' || esc[i + 3] != '0') {
                    return -1;
                }
                int hi = hex_val(esc[i + 4]);
                int lo = hex_val(esc[i + 5]);
                if (hi < 0 || lo < 0) {
                    return -1;
                }
                int v = hi * 16 + lo;
                if (v >= 0x20) {
                    return -1; /* not a control byte: this escaper never emits it */
                }
                decoded = (char)v;
                adv = 6;
                break;
            }
            default:
                return -1; /* unknown escape */
        }
        if (o + 1 >= out_cap) {
            return -1;
        }
        out[o++] = decoded;
        i += adv;
    }
    out[o] = '\0';
    return (long)o;
}

static void fuzz_json_escape(void)
{
    char in[MAX_NAME];

    for (unsigned round = 0; round < 2000; round++) {
        size_t filled = rng_below(60);
        for (size_t i = 0; i < filled; i++) {
            in[i] = rng_char();
        }
        in[filled] = '\0';
        /*
         * hc_json_escape takes a NUL-terminated string and stops at the first
         * NUL, and the full-range byte branch can produce one mid-buffer. The
         * effective length is therefore strlen, not the number of bytes drawn.
         */
        size_t len = strlen(in);

        /*
         * Exact escaped length, matching the implementation: quote, backslash
         * and the five short escapes double to 2 bytes, and any other byte below
         * 0x20 becomes a six-byte \u00XX sequence. Bytes at or above 0x20 pass
         * through as one byte. High bytes are NOT escaped.
         *
         * This is the content length only. The buffer needs one byte more for
         * the terminator, and on success *out_len reports the content length,
         * not the terminator.
         */
        size_t escaped = 0;
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)in[i];
            if (c == '"' || c == '\\' || c == '\b' || c == '\f' ||
                c == '\n' || c == '\r' || c == '\t') {
                escaped += 2;
            } else if (c < 0x20) {
                escaped += 6;
            } else {
                escaped += 1;
            }
        }

        /* Exact fit: content plus the terminator. */
        guarded_t g;
        guarded_alloc(&g, escaped + 1);
        size_t out_len = escaped + 1;
        hc_status st = hc_json_escape(in, g.data, &out_len);
        if (st != HC_OK || out_len != escaped) {
            char detail[256];
            snprintf(detail, sizeof(detail),
                     "len=%zu predicted=%zu got_status=%d(%s) out_len=%zu",
                     len, escaped, (int)st, hc_strerror(st), out_len);
            check(0, "hc_json_escape exact fit", detail);
        } else {
            check(1, "hc_json_escape exact fit", NULL);
        }
        if (guarded_intact(&g, "hc_json_escape exact")) {
            check(g.data[escaped] == '\0', "hc_json_escape terminator",
                  "output is not NUL-terminated after out_len bytes");
            /*
             * Round-trip rather than an ad-hoc scan. A previous version of this
             * check flagged any '"' in the output, which wrongly rejected the
             * legitimate \" that escaping produces. Unescaping and comparing
             * against the input proves the output is exactly the input, escaped,
             * and rejects raw control bytes on the way through.
             */
            char plain[MAX_NAME * 2];
            long recovered = json_unescape(g.data, out_len, plain, sizeof(plain));
            if (recovered < 0) {
                check(0, "hc_json_escape round-trip",
                      "escaped output did not reverse cleanly");
            } else if ((size_t)recovered != len || memcmp(plain, in, len) != 0) {
                check(0, "hc_json_escape round-trip",
                      "unescaping did not reproduce the input");
            } else {
                check(1, "hc_json_escape round-trip", NULL);
            }
        }
        guarded_free(&g);

        /* One byte short: must report truncation rather than overrun. */
        if (escaped > 0) {
            guarded_t s;
            guarded_alloc(&s, escaped);
            size_t short_len = escaped;
            hc_status st2 = hc_json_escape(in, s.data, &short_len);
            check(st2 == HC_ERR_TRUNC, "hc_json_escape short buffer",
                  "did not report truncation for an undersized buffer");
            check(short_len <= s.cap, "hc_json_escape short out_len",
                  "reported a length beyond the supplied capacity");
            if (guarded_intact(&s, "hc_json_escape short")) {
                check(s.data[short_len] == '\0', "hc_json_escape short terminator",
                      "truncation path left the buffer unterminated");
            }
            guarded_free(&s);
        }

        /* Zero capacity must be refused without writing a single byte. */
        {
            guarded_t z;
            guarded_alloc(&z, 0);
            size_t zero_len = 0;
            hc_status zst = hc_json_escape(in, z.data, &zero_len);
            check(zst == HC_ERR_TRUNC, "hc_json_escape zero capacity",
                  "did not report truncation for a zero-capacity buffer");
            guarded_intact(&z, "hc_json_escape zero capacity");
            guarded_free(&z);
        }
    }
}

/* ------------------------------------------------------------ API contracts */

static void fuzz_api_contracts(void)
{
    /* NULL arguments must be rejected with a defined status, not crash. */
    check(hc_bm_search(NULL, 0, "a", 1) < 0, "hc_bm_search null",
          "accepted a NULL text");
    check(hc_bm_search("a", 1, NULL, 1) < 0, "hc_bm_search null",
          "accepted a NULL pattern");
    check(hc_ac_add(NULL, "n", "p") == HC_ERR_NULL, "hc_ac_add null handle",
          "accepted a NULL automaton");
    check(hc_ac_build(NULL) == HC_ERR_NULL, "hc_ac_build null handle",
          "accepted a NULL automaton");
    check(hc_ac_scan(NULL, "t", 1, on_match, NULL) < 0, "hc_ac_scan null handle",
          "accepted a NULL automaton");
    check(hc_ac_count(NULL) == 0, "hc_ac_count null handle",
          "accepted a NULL automaton");
    check(hc_ac_nodes(NULL) == 0, "hc_ac_nodes null handle",
          "accepted a NULL automaton");
    hc_ac_free(NULL);

    /* Zero-length text is a defined case, not an error and not a match. */
    hc_ac_t *ac = hc_ac_new();
    if (ac) {
        check(hc_ac_add(ac, "sig", "abc") == HC_OK, "hc_ac_add", "rejected a pattern");
        check(hc_ac_build(ac) == HC_OK, "hc_ac_build", "failed on a valid automaton");
        check(hc_ac_scan(ac, "", 0, on_match, NULL) == 0, "hc_ac_scan empty text",
              "reported a match in empty text");
        check(hc_ac_count(ac) == 1, "hc_ac_count", "wrong count after one add");
        check(hc_ac_nodes(ac) > 0, "hc_ac_nodes", "reported no nodes");

        /*
         * Duplicate needles are accepted, not rejected: hc_ac_add appends and
         * the automaton terminates one node with both pattern ids, so a match
         * reports both names. Note this differs from the Rust core, which
         * de-duplicates by needle and reports only the first name; see the
         * parity note in the summary.
         */
        {
            hc_ac_t *dup = hc_ac_new();
            if (dup) {
                check(hc_ac_add(dup, "first", "abc") == HC_OK, "hc_ac_add dup",
                      "rejected the first registration");
                check(hc_ac_add(dup, "second", "abc") == HC_OK, "hc_ac_add dup",
                      "rejected a duplicate needle, but the contract accepts it");
                check(hc_ac_add(dup, "third", "ABC") == HC_OK, "hc_ac_add dup",
                      "rejected a case-variant duplicate");
                check(hc_ac_count(dup) == 3, "hc_ac_add dup count",
                      "duplicate registrations were not all counted");
                check(hc_ac_build(dup) == HC_OK, "hc_ac_build dup", "failed");
                found_t d;
                found_init(&d, 16);
                snprintf(d.names[0], MAX_NAME, "first");
                snprintf(d.names[1], MAX_NAME, "second");
                snprintf(d.names[2], MAX_NAME, "third");
                d.name_count = 3;
                int n = hc_ac_scan(dup, "xxabcxx", 7, on_match, &d);
                check(n == 3, "hc_ac_scan dup reports every name",
                      "did not report all three duplicate names");
                hc_ac_free(dup);
                found_free(&d);
            }
        }

        /* Scanning before build must be refused, not read uninitialised state. */
        hc_ac_t *unbuilt = hc_ac_new();
        if (unbuilt) {
            hc_ac_add(unbuilt, "x", "y");
            check(hc_ac_scan(unbuilt, "y", 1, on_match, NULL) == HC_ERR_STATE,
                  "hc_ac_scan before build",
                  "allowed a scan before hc_ac_build");
            hc_ac_free(unbuilt);
        }
        hc_ac_free(ac);
    }

    /* Every status the library can name must map to a non-empty message. */
    const hc_status all[] = {
        HC_OK, HC_ERR_NULL, HC_ERR_NOMEM, HC_ERR_EMPTY, HC_ERR_RANGE,
        HC_ERR_STATE, HC_ERR_IO, HC_ERR_TRUNC, HC_ERR_INVALID
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char *msg = hc_strerror(all[i]);
        check(msg != NULL && msg[0] != '\0', "hc_strerror",
              "returned an empty message for a valid status");
    }
    const char *unknown = hc_strerror((hc_status)-9999);
    check(unknown != NULL && unknown[0] != '\0', "hc_strerror unknown",
          "returned an empty message for an unknown status");

    check(hc_version() != NULL && hc_version()[0] != '\0', "hc_version",
          "returned an empty version string");
}

static void fuzz_hashing(void)
{
    /* Known vectors, so a refactor that changes the constants fails here. */
    static const char empty[1] = "";
    check(hc_fnv1a32(empty, 0) == 0x811C9DC5u, "fnv1a32 empty",
          "offset basis changed");
    check(hc_fnv1a64(empty, 0) == 0xCBF29CE484222325ULL, "fnv1a64 empty",
          "offset basis changed");
    check(hc_crc32(empty, 0) == 0x00000000u, "crc32 empty",
          "initial value changed");

    static const char abc[4] = "abc";
    check(hc_fnv1a32(abc, 3) == 0x1A47E90Bu, "fnv1a32 abc", "wrong digest");

    /*
     * The rolling hash is a 64-bit FNV-1a, so it must agree with hc_fnv1a64 and
     * not with the 32-bit variant.
     */
    hc_rollhash_t roll;
    hc_rollhash_init(&roll);
    for (size_t i = 0; i < 3; i++) {
        hc_rollhash_update(&roll, (uint8_t)abc[i]);
    }
    check(roll.offset_basis == hc_fnv1a64(abc, 3), "rollhash",
          "streaming update did not match the one-shot 64-bit digest");
    check(roll.prime == 0x100000001b3ULL, "rollhash prime",
          "FNV prime constant changed");

    /* Hashing must be length-driven, so embedded NULs are included. */
    static const char with_nul[4] = { 'a', '\0', 'b', 'c' };
    check(hc_fnv1a32(with_nul, 4) != hc_fnv1a32("abc", 3), "fnv1a32 embedded NUL",
          "ignored bytes past an embedded NUL");

    /* NULL is rejected explicitly and returns 0, not the offset basis. */
    check(hc_fnv1a32(NULL, 0) == 0, "fnv1a32 NULL",
          "NULL input did not return 0");
    check(hc_fnv1a64(NULL, 0) == 0, "fnv1a64 NULL",
          "NULL input did not return 0");
    check(hc_crc32(NULL, 0) == 0, "crc32 NULL", "NULL input did not return 0");

    /* The rolling API ignores a NULL state rather than dereferencing it. */
    hc_rollhash_init(NULL);
    hc_rollhash_update(NULL, 'x');
}

/* -------------------------------------------------------------------- main */

int main(void)
{
    printf("HELIOS-NET c_core differential fuzzer\n");
    printf("rounds: %d, pattern cap: %d, guard: %d bytes\n\n",
           FUZZ_ROUNDS, MAX_PATTERNS, GUARD_BYTES);

    fuzz_aho();
    fuzz_boyer_moore();
    fuzz_scan_to_buffer();
    fuzz_json_escape();
    fuzz_api_contracts();
    fuzz_hashing();

    printf("checks: %lu, failures: %lu\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAILED\n");
        return 1;
    }
    printf("RESULT: OK\n");
    return 0;
}
