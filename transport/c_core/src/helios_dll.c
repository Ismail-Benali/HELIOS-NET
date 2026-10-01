/*
 * HELIOS-NET :: transport/c_core/src/helios_dll.c
 * Flat C ABI for in-process (ctypes) callers.
 *
 * Why this file is thin
 * ---------------------
 * Everything here delegates to helios_core.h and helios_batch.h. There is no
 * matching, parsing or encoding logic in this translation unit, and that is the
 * whole point: the CLI and an FFI caller must produce the same answers for the
 * same input, and the only way to guarantee that is for both to run the same
 * code rather than two implementations that agree until they don't.
 *
 * Why a flat ABI
 * --------------
 * ctypes can call the library API directly, but hc_sig_load() takes a path and
 * returns an opaque handle that the caller must free, and the encoder wants an
 * output length in/out. Marshalling that from Python means reproducing the
 * in/out convention and the ownership rules on the Python side, where a mistake
 * is a memory error rather than a compile error. These wrappers own every
 * allocation and return a plain `char *` that the caller releases with
 * hc_free(), so the only thing crossing the boundary is a string.
 *
 * Thread safety: hc_dll_* is safe to call concurrently as long as each thread
 * uses its own handle. Sharing one handle across threads is the caller's
 * problem, exactly as with the library API.
 */

#include "helios_batch.h"
#include "helios_core.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define HC_API __declspec(dllexport)
#else
#define HC_API __attribute__((visibility("default")))
#endif

/* Bounded so a hostile or accidental length cannot make the Python side
 * allocate without limit: the caller has to size a buffer, and if the encoder
 * needs more it says so rather than growing. */
#define HC_DLL_OUT_CAP (HC_MAX_LINE * 8 + 1)

/*
 * Releases a string returned by any hc_dll_* function.
 *
 * The Python side calls this through ctypes; without it every call would leak
 * the buffer, and a long scan would grow the process without bound.
 */
HC_API void hc_free(char *p) {
    free(p);
}

HC_API const char *hc_dll_version(void) {
    return hc_version();
}

HC_API const char *hc_dll_strerror(int status) {
    return hc_strerror((hc_status)status);
}

/*
 * Opens a signature file and returns an opaque handle.
 *
 * Returns NULL on failure; a NULL handle is the only failure signal, so the
 * caller cannot distinguish "no such file" from "no usable pattern" - which is
 * acceptable, because the Python side reports both the same way and neither is
 * a condition it can act on.
 */
HC_API void *hc_dll_open(const char *path) {
    if (path == NULL) {
        return NULL;
    }
    return (void *)hc_sig_load(path, NULL);
}

HC_API void hc_dll_close(void *handle) {
    if (handle != NULL) {
        hc_ac_free((hc_ac_t *)handle);
    }
}

HC_API unsigned long hc_dll_pattern_count(void *handle) {
    if (handle == NULL) {
        return 0;
    }
    return (unsigned long)hc_ac_count((const hc_ac_t *)handle);
}

HC_API unsigned long hc_dll_node_count(void *handle) {
    if (handle == NULL) {
        return 0;
    }
    return (unsigned long)hc_ac_nodes((const hc_ac_t *)handle);
}

/*
 * Scans one banner and returns the same JSON object the CLI emits for it.
 * Returns NULL on failure; the caller frees it with hc_free().
 */
HC_API char *hc_dll_match_json(void *handle, const char *text) {
    if (handle == NULL || text == NULL) {
        return NULL;
    }
    size_t cap = HC_DLL_OUT_CAP;
    char *out = (char *)malloc(cap);
    if (out == NULL) {
        return NULL;
    }
    if (hc_batch_match_json((const hc_ac_t *)handle, text, out, &cap, NULL, NULL) != HC_OK) {
        free(out);
        return NULL;
    }
    return out;
}

/* Fingerprints one banner. Returns NULL on failure; free with hc_free(). */
HC_API char *hc_dll_fp_json(const char *text) {
    if (text == NULL) {
        return NULL;
    }
    size_t cap = HC_DLL_OUT_CAP;
    char *out = (char *)malloc(cap);
    if (out == NULL) {
        return NULL;
    }
    if (hc_batch_fp_json(text, out, &cap) != HC_OK) {
        free(out);
        return NULL;
    }
    return out;
}

/*
 * Runs the consistency checks and returns a JSON summary, so the FFI path can
 * be health-probed the same way the CLI is. A host that refuses to execute the
 * CLI binary can still prove the library is sound by calling in.
 *
 * This delegates rather than restating the checks. An earlier draft of this
 * function carried its own copy of the suite and it was already weaker than the
 * CLI's - missing the truncation, empty-pattern and scan-before-build cases -
 * which would have made this the narrowest gate in the project: it would pass
 * while the real suite failed, and both would print a success shape.
 */
HC_API char *hc_dll_selftest_json(void) {
    size_t cap = 1024;
    char *out = (char *)malloc(cap);
    if (out == NULL) {
        return NULL;
    }

    int failures = -1;
    if (hc_selftest_run(NULL, NULL, out, &cap, &failures) != HC_OK) {
        free(out);
        return NULL;
    }
    return out;
}
