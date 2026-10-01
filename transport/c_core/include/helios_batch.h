/*
 * HELIOS-NET :: transport/c_core/include/helios_batch.h
 * Batch front end: signature-file loading and whole-banner result encoding.
 *
 * Why this is separate from helios_core.h
 * --------------------------------------
 * helios_core.h is the matching library - an automaton, hashes, a search. It
 * knows nothing about signature files or JSON. Those lived in main.c as static
 * helpers, which meant the reusable half of the front end was unreachable from
 * anywhere except the CLI: an in-process caller had to shell out per banner,
 * re-read the signature file, and rebuild the automaton on every call.
 *
 * They are here so the CLI and an in-process FFI caller execute the *same*
 * code. A second implementation of the parser or the JSON encoder would be a
 * second set of answers for the same contract, and a silent divergence between
 * them is indistinguishable from a bug in either.
 */

#ifndef HELIOS_BATCH_H
#define HELIOS_BATCH_H

#include "helios_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Buffer sizes, shared so the CLI and the FFI cannot disagree about capacity. */
#define HC_MAX_LINE 65536
#define HC_MATCH_BUFFER 8192

/*
 * Loads a signature file into a built automaton.
 *
 * Format: one pattern per line; blank lines and lines starting with '#' are
 * ignored; an optional "name<TAB>pattern" form is supported; a leading UTF-8
 * BOM is stripped from the first line. `out_count` receives the number of
 * registered signatures and may be NULL.
 *
 * Returns NULL when the file cannot be read, holds no usable pattern, or the
 * automaton cannot be built. The caller owns the result and releases it with
 * hc_ac_free().
 */
hc_ac_t *hc_sig_load(const char *path, size_t *out_count);

/*
 * Encodes one banner's result as a single JSON object - the same object the
 * CLI emits for that banner, byte for byte.
 *
 * `out` is filled with a NUL-terminated object; `out_len` is in/out, holding
 * the capacity on entry and the written length on exit. `out_truncated` and
 * `out_count` may be NULL.
 *
 * A match list that does not fit is reported through `out_truncated` and the
 * emitted `truncated` field, never silently cut: a caller that cannot tell a
 * complete answer from a clipped one would report a short detection list as
 * complete.
 */
hc_status hc_batch_match_json(const hc_ac_t *ac, const char *text,
                              char *out, size_t *out_len,
                              int *out_count, int *out_truncated);

/* Encodes a banner's three digests as a single JSON object. */
hc_status hc_batch_fp_json(const char *text, char *out, size_t *out_len);

/*
 * Runs the full built-in consistency check suite and writes a JSON summary.
 *
 * One implementation serves the CLI and the FFI caller. A second, slightly
 * smaller copy of these checks is worse than no copy at all: the narrower one
 * becomes the "in-process" gate, passes while the real suite would have failed,
 * and the divergence is invisible because both report a success shape.
 *
 * `on_failure` may be NULL; it receives each failing check's message so the CLI
 * can name the failure on stderr while the FFI path just counts them.
 *
 * `out` receives {"status","mode","checks","failures","version"}; `out_failures`
 * receives the count and may be NULL.
 */
hc_status hc_selftest_run(void (*on_failure)(const char *msg, void *user), void *user,
                          char *out, size_t *out_len, int *out_failures);

#ifdef __cplusplus
}
#endif

#endif /* HELIOS_BATCH_H */
