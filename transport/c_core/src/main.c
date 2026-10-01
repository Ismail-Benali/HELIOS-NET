/*
 * HELIOS-NET :: transport/c_core/src/main.c
 * Command-line front end for the native signature & fingerprint core.
 *
 * This file is deliberately thin. Everything reusable - signature-file loading,
 * result encoding, the consistency checks - lives in helios_batch.c, because an
 * in-process (FFI) caller must get byte-identical answers from the same code.
 * A second copy of the parser here would be a second set of answers to the same
 * contract, and the divergence between them would look like a bug in either one.
 *
 * Modes:
 *   match     Load a signature file, stream one banner per input line, and emit
 *             one NDJSON result object per line.
 *   fp        Emit fingerprints (FNV-1a 32/64, CRC-32) for each input line.
 *   selftest  Run built-in consistency checks and exit non-zero on failure.
 *
 * Signature file format: one pattern per line, blank lines and lines starting
 * with '#' are ignored, and an optional "name<TAB>pattern" form is supported.
 */

#include "helios_batch.h"
#include "helios_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The banner is read into its own buffer and the result is encoded into a
 * different one. The previous version formatted the result into the very buffer
 * that held the match list it was still reading from; that is formally
 * undefined behaviour, and it only worked because the write cursor trailed the
 * read cursor. Two buffers cost 64 KB and remove the question. */
static char banner_buf[HC_MAX_LINE];
static char result_buf[HC_MAX_LINE * 8 + 1];

static int mode_match(const char *sig_file) {
    size_t count = 0;
    hc_ac_t *ac = hc_sig_load(sig_file, &count);
    if (ac == NULL) {
        fprintf(stderr, "c_core: cannot load signatures from '%s'\n", sig_file);
        return 1;
    }
    fprintf(stderr, "c_core: loaded %zu signatures from '%s'\n", count, sig_file);

    while (fgets(banner_buf, (int)sizeof(banner_buf), stdin) != NULL) {
        size_t n = strlen(banner_buf);
        while (n > 0 && (banner_buf[n - 1] == '\n' || banner_buf[n - 1] == '\r')) {
            banner_buf[--n] = '\0';
        }

        size_t out_len = sizeof(result_buf);
        if (hc_batch_match_json(ac, banner_buf, result_buf, &out_len, NULL, NULL) != HC_OK) {
            /* A dropped banner must be visible, not silently absent: the
             * consumer counts lines, and a line that vanishes is a detection
             * that never happened. */
            printf("{\"status\":\"error\",\"error\":\"encode_failed\"}\n");
            continue;
        }
        fputs(result_buf, stdout);
        fputc('\n', stdout);
    }

    hc_ac_free(ac);
    return 0;
}

static int mode_fp(void) {
    while (fgets(banner_buf, (int)sizeof(banner_buf), stdin) != NULL) {
        size_t n = strlen(banner_buf);
        while (n > 0 && (banner_buf[n - 1] == '\n' || banner_buf[n - 1] == '\r')) {
            banner_buf[--n] = '\0';
        }

        size_t out_len = sizeof(result_buf);
        if (hc_batch_fp_json(banner_buf, result_buf, &out_len) != HC_OK) {
            printf("{\"status\":\"error\",\"error\":\"encode_failed\"}\n");
            continue;
        }
        fputs(result_buf, stdout);
        fputc('\n', stdout);
    }
    return 0;
}

static void report_failure(const char *msg, void *user) {
    (void)user;
    fprintf(stderr, "selftest: %s\n", msg);
}

static int mode_selftest(void) {
    char out[1024];
    size_t out_len = sizeof(out);
    int failures = -1;

    if (hc_selftest_run(report_failure, NULL, out, &out_len, &failures) != HC_OK) {
        return 1;
    }
    fputs(out, stdout);
    fputc('\n', stdout);
    return failures == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ main */

static void usage(const char *argv0) {
    fprintf(stderr,
            "HELIOS-NET native core %s\n"
            "Usage:\n"
            "  %s selftest\n"
            "  %s match <signatures-file>   < banners.txt\n"
            "  %s fp                        < banners.txt\n"
            "  %s version\n",
            hc_version(), argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "selftest") == 0) {
        return mode_selftest();
    }
    if (strcmp(argv[1], "match") == 0) {
        if (argc < 3) {
            usage(argv[0]);
            return 2;
        }
        return mode_match(argv[2]);
    }
    if (strcmp(argv[1], "fp") == 0) {
        return mode_fp();
    }
    if (strcmp(argv[1], "version") == 0) {
        printf("{\"status\":\"ok\",\"component\":\"c_core\",\"version\":\"%s\"}\n", hc_version());
        return 0;
    }

    usage(argv[0]);
    return 2;
}
