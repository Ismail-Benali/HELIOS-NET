/*
 * HELIOS-NET :: transport/c_core/include/helios_dll.h
 * Flat C ABI for in-process callers (ctypes).
 *
 * Why this is a header and not just definitions
 * ---------------------------------------------
 * helios_dll.c is compiled into the executable's test links and into the shared
 * library alike, under -Wmissing-prototypes -Werror. Without a declaration every
 * exported function in that file is an error: the flag exists to catch a function
 * whose signature has drifted from its only description, which here is ctypes.
 * The Python side passes and receives pointers and integers, so a change to a
 * parameter type is invisible at the boundary until it corrupts memory - and a
 * caller with no header to include has nothing to check against.
 *
 * Declaring the ABI here also means the contract has exactly one written form.
 * The ctypes bridge in core/c_core_bridge.py restates these signatures in Python;
 * this file is the C half of that pair, so the two can be diffed by eye.
 */

#ifndef HELIOS_DLL_H
#define HELIOS_DLL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Export marker. Public on Windows (the .def equivalent) and a visibility
 * override elsewhere; the shared library is linked with -fvisibility=hidden so
 * that only these entry points are reachable from outside.
 */
#ifdef _WIN32
#define HC_API __declspec(dllexport)
#else
#define HC_API __attribute__((visibility("default")))
#endif

/* Releases a string returned by any other hc_dll_* function. NULL is a no-op. */
HC_API void hc_free(char *p);

/* Version of the core behind this library, as a static string. Never freed. */
HC_API const char *hc_dll_version(void);

/* Human-readable form of an hc_status value. Static; never freed. */
HC_API const char *hc_dll_strerror(int status);

/*
 * Opens a signature file and returns an opaque handle, or NULL on failure.
 * A NULL handle is the only failure signal: the caller cannot distinguish "no
 * such file" from "no usable pattern", which is acceptable because the FFI
 * caller reports both identically and can act on neither.
 */
HC_API void *hc_dll_open(const char *path);

/* Releases a handle from hc_dll_open. NULL is a no-op. */
HC_API void hc_dll_close(void *handle);

/* Patterns registered in the handle, or 0 for a NULL handle. */
HC_API unsigned long hc_dll_pattern_count(void *handle);

/* Automaton nodes built for the handle, or 0 for a NULL handle. */
HC_API unsigned long hc_dll_node_count(void *handle);

/*
 * Matches one banner and returns the same JSON object the CLI emits for it.
 * Returns NULL on failure; free the result with hc_free().
 */
HC_API char *hc_dll_match_json(void *handle, const char *text);

/* Fingerprints one banner. Returns NULL on failure; free with hc_free(). */
HC_API char *hc_dll_fp_json(const char *text);

/*
 * Runs the consistency checks and returns a JSON summary, so an FFI caller can
 * health-probe the library the same way the CLI is probed. A host that refuses
 * to execute the CLI binary can still prove the library is sound by calling in.
 * Returns NULL on failure; free with hc_free().
 */
HC_API char *hc_dll_selftest_json(void);

#ifdef __cplusplus
}
#endif

#endif /* HELIOS_DLL_H */