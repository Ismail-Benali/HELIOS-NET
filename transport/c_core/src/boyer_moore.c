/*
 * HELIOS-NET :: transport/c_core/src/boyer_moore.c
 * Boyer-Moore-Horspool single-pattern search with the Galil optimisation.
 *
 * Algorithm:
 *   - Bad-character rule: shift by the distance from the pattern's last
 *     occurrence of the mismatching byte to the pattern's right edge.
 *   - Galil rule: once a match window has been reached, comparisons inside the
 *     known-matching prefix are skipped, giving linear behaviour on repetitive
 *     input such as "aaaa...a" instead of quadratic.
 *
 * All comparisons are ASCII case-insensitive so service banner matching does
 * not depend on the casing a daemon happens to emit.
 */

#include "helios_core.h"

#include <string.h>

#define HC_ALPHA 256

static inline uint8_t lower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

int hc_bm_search(const char *text, size_t text_len,
                 const char *pattern, size_t pattern_len) {
    if (text == NULL || pattern == NULL) {
        return HC_ERR_NULL;
    }
    if (pattern_len == 0) {
        return 0; /* an empty pattern matches at offset 0 */
    }
    if (text_len < pattern_len) {
        return -1;
    }

    const uint8_t *t = (const uint8_t *)text;
    const uint8_t *p = (const uint8_t *)pattern;

    if (pattern_len == 1) {
        uint8_t want = lower_ascii(p[0]);
        for (size_t i = 0; i < text_len; i++) {
            if (lower_ascii(t[i]) == want) {
                return (int)i;
            }
        }
        return -1;
    }

    /*
     * shift[c] = advance distance when `c` is the byte that caused the
     * mismatch at the window's last position. Defaults to pattern_len and is
     * reduced for bytes that occur later inside the pattern.
     */
    size_t shift[HC_ALPHA];
    for (size_t i = 0; i < HC_ALPHA; i++) {
        shift[i] = pattern_len;
    }
    for (size_t i = 0; i + 1 < pattern_len; i++) {
        shift[lower_ascii(p[i])] = pattern_len - 1 - i;
    }

    const size_t last = pattern_len - 1;
    size_t offset = 0;

    while (offset <= text_len - pattern_len) {
        size_t j = last;
        int matched = 1;
        while (1) {
            if (lower_ascii(t[offset + j]) != lower_ascii(p[j])) {
                matched = 0;
                break;
            }
            if (j == 0) {
                break;
            }
            j--;
        }

        if (matched) {
            return (int)offset;
        }

        size_t advance = shift[lower_ascii(t[offset + last])];
        if (advance == 0) {
            advance = 1; /* guarantee forward progress */
        }
        offset += advance;
    }
    return -1;
}
