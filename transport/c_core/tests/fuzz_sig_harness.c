/*
 * HELIOS-NET :: transport/c_core/tests/fuzz_sig_harness.c
 * Deterministic corpus fuzzer for the signature-file loader.
 *
 * The matching automaton already has a differential fuzzer. The loader did not,
 * yet it is the first code that consumes operator-supplied (and pipeline-
 * supplied) bytes: a NUL in the middle of a file, an overlong line, or a
 * duplicate registration all reach it before a single banner is scanned.
 *
 * This harness writes generated files to disk because hc_sig_load takes a path,
 * then loads, scans a hostile text with any accepted automaton, and frees it.
 * Run it under ASan/UBSan; a leak or an out-of-bounds access is the signal, not
 * a specific expected count. Exit code 1 means the loader accepted a file and
 * then failed to scan it, which is a contract violation.
 *
 * Usage: fuzz_sig_harness [iterations]   (default 2000)
 */

#include "helios_batch.h"
#include "helios_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 4096
#define MAX_TEXT 2048

static unsigned long long rng_state = 0x9E3779B97F4A7C15ULL;

static unsigned long long next_random(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static size_t next_below(size_t limit) {
    return (size_t)(next_random() % (limit ? limit : 1));
}

static void fill_random(unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        data[i] = (unsigned char)(next_random() & 0xFFu);
    }
}

static void fill_structured(unsigned char *data, size_t length) {
    static const char alphabet[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        " \t\r\n#.-_/:\"\\";
    size_t index = 0;
    if (length >= 3 && (next_random() & 1u)) {
        data[index++] = 0xEF;
        data[index++] = 0xBB;
        data[index++] = 0xBF;
    }
    while (index < length) {
        unsigned long long draw = next_random();
        if ((draw & 31u) == 0u) {
            data[index++] = '\n';
        } else if ((draw & 31u) == 1u) {
            data[index++] = '\t';
        } else {
            data[index++] = (unsigned char)alphabet[draw % (sizeof(alphabet) - 1)];
        }
    }
}

static int write_file(const unsigned char *data, size_t length) {
    FILE *fp = fopen("helios_sig_fuzz.tmp", "wb");
    if (fp == NULL) {
        return 0;
    }
    size_t written = fwrite(data, 1, length, fp);
    fclose(fp);
    return written == length;
}

typedef struct {
    size_t positions[64];
    size_t count;
} capture_t;

static void on_match(const char *name, const char *pattern, size_t position,
                     void *user) {
    (void)name;
    (void)pattern;
    capture_t *capture = (capture_t *)user;
    if (capture->count < 64) {
        capture->positions[capture->count] = position;
    }
    capture->count++;
}

int main(int argc, char **argv) {
    long iterations = 2000;
    if (argc > 1) {
        long parsed = strtol(argv[1], NULL, 10);
        if (parsed > 0) {
            iterations = parsed;
        }
    }

    unsigned char input[MAX_INPUT];
    unsigned char text[MAX_TEXT];
    long accepted = 0;
    long rejected = 0;

    for (long i = 0; i < iterations; i++) {
        size_t length = 1 + next_below(MAX_INPUT);
        if ((next_random() & 1u) == 0u) {
            fill_random(input, length);
        } else {
            fill_structured(input, length);
        }
        if (!write_file(input, length)) {
            fprintf(stderr, "FAIL: could not write the corpus file\n");
            return 2;
        }

        size_t count = 0;
        hc_ac_t *ac = hc_sig_load("helios_sig_fuzz.tmp", &count);
        if (ac == NULL) {
            rejected++;
            continue;
        }
        accepted++;

        size_t text_len = next_below(MAX_TEXT);
        fill_random(text, text_len);
        if (text_len >= 3 && (next_random() & 1u)) {
            memcpy(text, "xxxx", 4 < text_len ? 4 : text_len);
        }
        capture_t whole = {{0}, 0};
        int reported = hc_ac_scan(ac, (const char *)text, text_len, on_match, &whole);
        if (reported < 0 || count == 0) {
            fprintf(stderr, "FAIL: accepted file scanned with status %d\n", reported);
            hc_ac_free(ac);
            remove("helios_sig_fuzz.tmp");
            return 1;
        }

        hc_ac_stream_t *stream = hc_ac_stream_new(ac);
        if (stream == NULL) {
            fprintf(stderr, "FAIL: could not open a stream over a built automaton\n");
            hc_ac_free(ac);
            remove("helios_sig_fuzz.tmp");
            return 1;
        }
        capture_t chunked = {{0}, 0};
        size_t offset = 0;
        while (offset < text_len) {
            size_t piece = 1 + next_below(text_len - offset);
            int fed = hc_ac_stream_feed(stream, (const char *)text + offset, piece,
                                        on_match, &chunked);
            if (fed < 0) {
                fprintf(stderr, "FAIL: stream rejected a chunk with %d\n", fed);
                hc_ac_stream_free(stream);
                hc_ac_free(ac);
                remove("helios_sig_fuzz.tmp");
                return 1;
            }
            offset += piece;
        }
        hc_ac_stream_free(stream);
        int same = whole.count == chunked.count;
        for (size_t k = 0; same && k < whole.count && k < 64; k++) {
            if (whole.positions[k] != chunked.positions[k]) {
                same = 0;
            }
        }
        if (!same || hc_ac_stream_position(NULL) != 0) {
            fprintf(stderr, "FAIL: chunked scan disagrees with one-shot scan\n");
            hc_ac_free(ac);
            remove("helios_sig_fuzz.tmp");
            return 1;
        }
        hc_ac_free(ac);
    }

    remove("helios_sig_fuzz.tmp");
    printf("{\"status\":\"ok\",\"iterations\":%ld,\"accepted\":%ld,"
           "\"rejected\":%ld}\n",
           iterations, accepted, rejected);
    return 0;
}
