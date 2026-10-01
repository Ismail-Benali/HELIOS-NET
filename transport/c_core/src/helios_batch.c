/*
 * HELIOS-NET :: transport/c_core/src/helios_batch.c
 * Implementation of the batch front end declared in helios_batch.h.
 *
 * This is the code that used to sit in main.c as static helpers, moved out
 * unchanged in behaviour so the CLI and an in-process FFI caller produce
 * identical results. The comments explaining *why* each detail matters are
 * carried over with it: they describe contract requirements, not preferences,
 * and losing them is how the next reader "simplifies" a case that is load
 * bearing.
 */

#include "helios_batch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ input */

static int read_line(FILE *fp, char *buf, size_t cap) {
    if (fgets(buf, (int)cap, fp) == NULL) {
        return 0;
    }
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }
    return 1;
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) {
        s[--n] = '\0';
    }
    size_t start = 0;
    while (s[start] == ' ' || s[start] == '\t') {
        start++;
    }
    if (start > 0) {
        memmove(s, s + start, n - start + 1);
    }
}

hc_ac_t *hc_sig_load(const char *path, size_t *out_count) {
    if (path == NULL) {
        return NULL;
    }
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return NULL;
    }
    hc_ac_t *ac = hc_ac_new();
    if (ac == NULL) {
        fclose(fp);
        return NULL;
    }

    char line[HC_MAX_LINE];
    size_t loaded = 0;
    int first_line = 1;
    while (read_line(fp, line, sizeof(line))) {
        /*
         * Strip a leading UTF-8 BOM. PowerShell 5.1, Notepad and several other
         * Windows editors write one by default, and without this the three BOM
         * bytes silently became part of the first signature name, so
         * "alpha<TAB>foo" was registered as "\xEF\xBB\xBFalpha" and never
         * matched anything the operator expected.
         */
        if (first_line) {
            first_line = 0;
            if ((unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB &&
                (unsigned char)line[2] == 0xBF) {
                memmove(line, line + 3, strlen(line + 3) + 1);
            }
        }
        trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        char *pattern = line;
        char *name = NULL;
        char *tab = strchr(line, '\t');
        if (tab != NULL) {
            *tab = '\0';
            name = line;
            pattern = tab + 1;
        }

        if (hc_ac_add(ac, name, pattern) == HC_OK) {
            loaded++;
        }
    }
    fclose(fp);

    if (loaded == 0 || hc_ac_build(ac) != HC_OK) {
        hc_ac_free(ac);
        return NULL;
    }
    if (out_count != NULL) {
        *out_count = loaded;
    }
    return ac;
}

/* -------------------------------------------------------------- callbacks */

typedef struct {
    char   *buffer;
    size_t  capacity;
    size_t  used;
    int     count;
    int     overflow;
    char   *scratch;      /* reusable JSON-escape scratch, avoids per-match malloc */
    size_t  scratch_cap;
} match_ctx_t;

/* Emits one match record. The signature name is attacker-influenced text (it
 * comes from a signature file) and is interpolated into a JSON object, so it
 * must be escaped: an unescaped quote lets a crafted signature file forge
 * match records in the engagement output. snprintf truncation must also be
 * detected, because copying the *would-be* length from a short buffer reads
 * past the end of the stack array. */
static void on_match(const char *name, const char *pattern, size_t position, void *user) {
    (void)pattern;
    match_ctx_t *ctx = (match_ctx_t *)user;
    if (ctx == NULL) {
        return;
    }

    /* A local copy keeps the stored capacity immutable: hc_json_escape writes
     * through out_len, and letting it do so to the shared field would let one
     * truncated name shrink the buffer the next match believes it has. */
    size_t cap = ctx->scratch_cap;

    if (hc_json_escape(name, ctx->scratch, &cap) != HC_OK) {
        ctx->overflow = 1;
        return;
    }

    char entry[512];
    int n = snprintf(entry, sizeof(entry), "%s{\"signature\":\"%s\",\"position\":%zu}",
                     ctx->count ? "," : "", ctx->scratch, position);
    if (n < 0 || (size_t)n >= sizeof(entry)) {
        /* Truncated: the record would be invalid JSON. Report it instead of
         * emitting a malformed line that the Python side cannot parse. */
        ctx->overflow = 1;
        return;
    }
    size_t need = (size_t)n;
    if (ctx->used + need + 1 >= ctx->capacity) {
        ctx->overflow = 1;
        return;
    }
    memcpy(ctx->buffer + ctx->used, entry, need);
    ctx->used += need;
    ctx->count++;
    ctx->buffer[ctx->used] = '\0'; /* keep the buffer printable for %s */
}

/* ---------------------------------------------------------------- encoding */

hc_status hc_batch_match_json(const hc_ac_t *ac, const char *text,
                              char *out, size_t *out_len,
                              int *out_count, int *out_truncated) {
    if (ac == NULL || text == NULL || out == NULL || out_len == NULL) {
        return HC_ERR_NULL;
    }
    if (*out_len == 0) {
        return HC_ERR_RANGE;
    }

    char *matches = (char *)malloc(HC_MATCH_BUFFER);
    char *escaped = (char *)malloc(HC_MAX_LINE * 6 + 1);
    if (matches == NULL || escaped == NULL) {
        free(matches);
        free(escaped);
        return HC_ERR_NOMEM;
    }
    /* Worst case JSON expansion is 6 bytes per input byte (a control character
     * becomes \u00XX), so one allocation covers every name. */
    size_t scratch_cap = HC_MAX_LINE * 6 + 1;
    char *scratch = (char *)malloc(scratch_cap);
    if (scratch == NULL) {
        free(matches);
        free(escaped);
        return HC_ERR_NOMEM;
    }

    match_ctx_t ctx = { matches, HC_MATCH_BUFFER, 0, 0, 0, scratch, scratch_cap };
    int reported = hc_ac_scan(ac, text, strlen(text), on_match, &ctx);
    free(scratch);
    if (reported < 0) {
        free(matches);
        free(escaped);
        return (hc_status)reported;
    }

    size_t escaped_len = HC_MAX_LINE * 6 + 1;
    if (hc_json_escape(text, escaped, &escaped_len) != HC_OK) {
        snprintf(escaped, HC_MAX_LINE, "<truncated>");
        escaped_len = strlen(escaped);
    }

    /* Overflowed match lists are reported as truncated, never silently cut. */
    int n = snprintf(out, *out_len,
                     "{\"status\":\"ok\",\"banner\":\"%s\","
                     "\"fp_fnv1a32\":\"0x%08X\","
                     "\"fp_fnv1a64\":\"0x%016llX\","
                     "\"fp_crc32\":\"0x%08X\","
                     "\"matches\":[%s],\"match_count\":%d,\"truncated\":%s}",
                     escaped,
                     hc_fnv1a32(text, strlen(text)),
                     (unsigned long long)hc_fnv1a64(text, strlen(text)),
                     hc_crc32(text, strlen(text)),
                     ctx.count ? matches : "",
                     ctx.count,
                     ctx.overflow ? "true" : "false");

    if (out_count != NULL) {
        *out_count = ctx.count;
    }
    if (out_truncated != NULL) {
        *out_truncated = ctx.overflow;
    }
    free(matches);
    free(escaped);

    if (n < 0 || (size_t)n >= *out_len) {
        return HC_ERR_TRUNC;
    }
    *out_len = (size_t)n;
    return HC_OK;
}

/* ---------------------------------------------------------------- selftest */

hc_status hc_selftest_run(void (*on_failure)(const char *msg, void *user), void *user,
                          char *out, size_t *out_len, int *out_failures) {
    int failures = 0;
    int checks = 0;

    /* Each assertion is counted so the report can state how much was actually
     * verified. The Go and Rust cores both publish a check count; without one
     * here the three native cores could not be compared on equal terms. */
#define CHECK(cond, msg)                                  \
    do {                                                  \
        checks++;                                         \
        if (!(cond)) {                                    \
            failures++;                                   \
            if (on_failure != NULL) {                    \
                on_failure((msg), user);                  \
            }                                             \
        }                                                 \
    } while (0)

    /* Hash vectors. */
    CHECK(hc_fnv1a32("a", 1) == 0xe40c292cu, "FNV-1a 32 vector mismatch");
    CHECK(hc_fnv1a64("a", 1) == 0xaf63dc4c8601ec8cULL, "FNV-1a 64 vector mismatch");
    CHECK(hc_crc32("123456789", 9) == 0xCBF43926u, "CRC-32 vector mismatch");

    /* Boyer-Moore: hit, miss, and the single-character fast path. */
    CHECK(hc_bm_search("hello world", 11, "world", 5) == 6, "BM expected match at 6");
    CHECK(hc_bm_search("hello world", 11, "absent", 6) == -1, "BM unexpected match");
    CHECK(hc_bm_search("HELLO", 5, "hello", 5) == 0, "BM case-insensitivity broken");
    CHECK(hc_bm_search("aaa", 3, "a", 1) == 0, "BM single-char path broken");
    CHECK(hc_bm_search("ab", 2, "abcd", 4) == -1, "BM pattern longer than text");

    /* Case-insensitive containment. */
    CHECK(hc_contains_ci("Server: NGINX/1.24", "nginx"), "contains_ci negative case");
    CHECK(!hc_contains_ci("Server: Apache", "nginx"), "contains_ci false positive");

    /* Aho-Corasick: overlapping patterns and suffix inheritance. */
    hc_ac_t *ac = hc_ac_new();
    if (ac == NULL) {
        if (on_failure != NULL) {
            on_failure("automaton allocation failed", user);
        }
        if (out_failures != NULL) {
            *out_failures = -1;
        }
        return HC_ERR_NOMEM;
    }
    if (hc_ac_add(ac, "he", "he") != HC_OK ||
        hc_ac_add(ac, "she", "she") != HC_OK ||
        hc_ac_add(ac, "his", "his") != HC_OK ||
        hc_ac_add(ac, "hers", "hers") != HC_OK) {
        if (on_failure != NULL) {
            on_failure("hc_ac_add failed", user);
        }
        hc_ac_free(ac);
        if (out_failures != NULL) {
            *out_failures = -1;
        }
        return HC_ERR_STATE;
    }
    CHECK(hc_ac_count(ac) == 4, "expected 4 patterns");
    if (hc_ac_build(ac) != HC_OK) {
        if (on_failure != NULL) {
            on_failure("hc_ac_build failed", user);
        }
        hc_ac_free(ac);
        if (out_failures != NULL) {
            *out_failures = -1;
        }
        return HC_ERR_STATE;
    }

    char buf[512];
    size_t buf_len = sizeof(buf);
    CHECK(hc_ac_scan_to_buffer(ac, "ushers", buf, &buf_len, 16) == HC_OK,
          "scan_to_buffer failed");
    CHECK(strstr(buf, "he") != NULL && strstr(buf, "she") != NULL &&
              strstr(buf, "hers") != NULL,
          "expected he/she/hers in scan output");
    CHECK(strstr(buf, "his") == NULL, "unexpected 'his' match");
    /* The buffer must be a NUL-terminated C string, not a raw byte run.
     * out_len counts the written content (including the trailing newline) and
     * excludes the terminator, so the NUL sits at out[buf_len]. */
    CHECK(buf_len > 0 && buf_len < sizeof(buf) && buf[buf_len] == '\0',
          "scan buffer is not NUL terminated");

    /* Scan before build must be rejected. */
    hc_ac_t *unbuilt = hc_ac_new();
    if (unbuilt != NULL) {
        hc_ac_add(unbuilt, "x", "x");
        CHECK(hc_ac_scan(unbuilt, "x", 1, on_match, NULL) == HC_ERR_STATE,
              "scan before build was not rejected");
        hc_ac_free(unbuilt);
    }

    /* Empty pattern must be rejected. */
    CHECK(hc_ac_add(ac, "empty", "") == HC_ERR_EMPTY, "empty pattern was not rejected");

    hc_ac_free(ac);

    /* JSON escaping. */
    char esc[128];
    size_t esc_len = sizeof(esc);
    CHECK(hc_json_escape("a\"b\\c\nd", esc, &esc_len) == HC_OK &&
              strcmp(esc, "a\\\"b\\\\c\\nd") == 0,
          "JSON escaping mismatch");
    char tiny[2];
    size_t tiny_len = sizeof(tiny);
    CHECK(hc_json_escape("abc", tiny, &tiny_len) == HC_ERR_TRUNC,
          "truncation not detected");
#undef CHECK

    if (out_failures != NULL) {
        *out_failures = failures;
    }

    if (out != NULL && out_len != NULL && *out_len > 0) {
        int n = snprintf(out, *out_len,
                         "{\"status\":\"%s\",\"mode\":\"selftest\",\"checks\":%d,"
                         "\"failures\":%d,\"version\":\"%s\"}",
                         failures == 0 ? "ok" : "error", checks, failures, hc_version());
        if (n < 0 || (size_t)n >= *out_len) {
            return HC_ERR_TRUNC;
        }
        *out_len = (size_t)n;
    }
    return HC_OK;
}
hc_status hc_batch_fp_json(const char *text, char *out, size_t *out_len) {
    if (text == NULL || out == NULL || out_len == NULL) {
        return HC_ERR_NULL;
    }
    if (*out_len == 0) {
        return HC_ERR_RANGE;
    }

    size_t len = strlen(text);
    size_t escaped_len = HC_MAX_LINE * 6 + 1;
    char *escaped = (char *)malloc(escaped_len);
    if (escaped == NULL) {
        return HC_ERR_NOMEM;
    }
    if (hc_json_escape(text, escaped, &escaped_len) != HC_OK) {
        snprintf(escaped, HC_MAX_LINE, "<truncated>");
    }

    int n = snprintf(out, *out_len,
                     "{\"status\":\"ok\",\"input\":\"%s\",\"length\":%zu,"
                     "\"fp_fnv1a32\":\"0x%08X\",\"fp_fnv1a64\":\"0x%016llX\","
                     "\"fp_crc32\":\"0x%08X\"}",
                     escaped, len,
                     hc_fnv1a32(text, len),
                     (unsigned long long)hc_fnv1a64(text, len),
                     hc_crc32(text, len));
    free(escaped);

    if (n < 0 || (size_t)n >= *out_len) {
        return HC_ERR_TRUNC;
    }
    *out_len = (size_t)n;
    return HC_OK;
}
