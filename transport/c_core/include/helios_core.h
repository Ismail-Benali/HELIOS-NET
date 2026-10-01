/*
 * HELIOS-NET :: transport/c_core/include/helios_core.h
 * Public API for the HELIOS-NET native signature & fingerprint core.
 *
 * Design goals:
 *   - Zero external dependencies (C11 + libc only).
 *   - Deterministic, allocation-safe, and free of global mutable state.
 *   - Every entry point is bounds-checked; malformed input yields a defined
 *     failure code instead of undefined behaviour.
 *
 * Thread safety: handles are not internally synchronised. Concurrent readers
 * may share one immutable `hc_ac_t` after `hc_ac_build()`; concurrent writers
 * require external locking.
 */

#ifndef HELIOS_CORE_H
#define HELIOS_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- status */

typedef enum {
    HC_OK = 0,
    HC_ERR_NULL = -1,       /* NULL handle or buffer argument            */
    HC_ERR_NOMEM = -2,      /* allocation failure                        */
    HC_ERR_EMPTY = -3,      /* empty text or pattern set                 */
    HC_ERR_RANGE = -4,      /* capacity/length out of range              */
    HC_ERR_STATE = -5,      /* API called before hc_ac_build()           */
    HC_ERR_IO = -6,         /* file or stream failure                    */
    HC_ERR_TRUNC = -7,      /* output buffer too small                   */
    HC_ERR_INVALID = -8,    /* malformed input                           */
    HC_ERR_DUP     = -9     /* identical (name, pattern) already added  */
} hc_status;

const char *hc_strerror(hc_status status);

/* ------------------------------------------------------------- hashing */

uint32_t hc_fnv1a32(const void *data, size_t len);
uint64_t hc_fnv1a64(const void *data, size_t len);
uint32_t hc_crc32(const void *data, size_t len);

/* FNV-1a 64-bit rolling hash for streaming prefiltering. */
typedef struct {
    uint64_t offset_basis;
    uint64_t prime;
} hc_rollhash_t;

void hc_rollhash_init(hc_rollhash_t *state);
void hc_rollhash_update(hc_rollhash_t *state, uint8_t byte);

/* --------------------------------------------------- Boyer-Moore search */

/*
 * Case-insensitive single-pattern search using the bad-character rule with the
 * Galil termination optimisation. Returns the 0-based match offset, -1 when
 * absent, or a negative `hc_status` on invalid input.
 */
int hc_bm_search(const char *text, size_t text_len,
                 const char *pattern, size_t pattern_len);

/* ------------------------------------------------- Aho-Corasick automaton */

/*
 * Multi-pattern, case-insensitive, single-pass substring matcher. Supports tens
 * of thousands of patterns with linear-time scanning and bounded memory via
 * sparse child edges plus binary-search transitions.
 */
typedef struct hc_ac hc_ac_t;

hc_ac_t *hc_ac_new(void);
void hc_ac_free(hc_ac_t *ac);

/*
 * Registers `pattern` under `name`. Both are copied. A NULL or empty `name`
 * defaults to the pattern text. Returns HC_OK or a negative status.
 */
hc_status hc_ac_add(hc_ac_t *ac, const char *name, const char *pattern);

/* Computes failure links. Must be called once after the final hc_ac_add(). */
hc_status hc_ac_build(hc_ac_t *ac);

/* Number of registered patterns. */
size_t hc_ac_count(const hc_ac_t *ac);

/* Number of nodes in the automaton (diagnostics). */
size_t hc_ac_nodes(const hc_ac_t *ac);

/*
 * Streams `text` through the automaton, invoking `cb` once per match.
 * `user` is passed through untouched. Returns the number of matches reported,
 * or a negative `hc_status`.
 */
typedef void (*hc_ac_match_fn)(const char *name, const char *pattern,
                               size_t position, void *user);

int hc_ac_scan(const hc_ac_t *ac, const char *text, size_t text_len,
               hc_ac_match_fn cb, void *user);

/*
 * Convenience wrapper: scans `text` and copies up to `max_names` matched
 * pattern names into `out` as newline-separated NUL-terminated storage.
 * Returns HC_OK, a negative status, or the number of bytes written (excluding
 * the trailing NUL). `out_len` is in/out: capacity on entry, written on exit.
 */
hc_status hc_ac_scan_to_buffer(const hc_ac_t *ac, const char *text,
                               char *out, size_t *out_len, size_t max_names);

/* ------------------------------------------------------------- utilities */

/* Returns non-zero when `text` contains `needle`, ignoring ASCII case. */
int hc_contains_ci(const char *text, const char *needle);

/* Writes a JSON-escaped copy of `in` into `out`. Returns HC_OK or HC_ERR_TRUNC. */
hc_status hc_json_escape(const char *in, char *out, size_t *out_len);

/* Library version string, e.g. "2.1.0". Never NULL. */
const char *hc_version(void);

#ifdef __cplusplus
}
#endif

#endif /* HELIOS_CORE_H */
