/*
 * HELIOS-NET :: transport/c_core/src/helios_core.c
 * Library-level helpers: version string, status codes, JSON escaping.
 */

#include "helios_core.h"

#include <stdio.h>
#include <string.h>

#define HC_CORE_VERSION "2.1.0"

const char *hc_version(void) {
    return HC_CORE_VERSION;
}

const char *hc_strerror(hc_status status) {
    switch (status) {
        case HC_OK:          return "ok";
        case HC_ERR_NULL:    return "null argument";
        case HC_ERR_NOMEM:   return "out of memory";
        case HC_ERR_EMPTY:   return "empty input";
        case HC_ERR_RANGE:   return "value out of range";
        case HC_ERR_STATE:   return "invalid state";
        case HC_ERR_IO:      return "io failure";
        case HC_ERR_TRUNC:   return "output truncated";
        case HC_ERR_INVALID: return "invalid input";
        case HC_ERR_DUP:     return "signature already registered";
        default:             return "unknown error";
    }
}

/*
 * Escapes a byte string for embedding inside a JSON string literal. Control
 * characters use the \u00XX form; everything else passes through unchanged,
 * which keeps service banners byte-identical for the consumer.
 */
hc_status hc_json_escape(const char *in, char *out, size_t *out_len) {
    if (in == NULL || out == NULL || out_len == NULL) {
        return HC_ERR_NULL;
    }
    size_t capacity = *out_len;
    size_t written = 0;
    *out_len = 0;

    /*
     * A zero-capacity buffer must be refused before any store. The truncation
     * path below terminates in place, which needs `written < capacity`, and that
     * only holds once capacity is known to be non-zero.
     */
    if (capacity == 0) {
        return HC_ERR_TRUNC;
    }
    out[0] = '\0';

    static const char hex[] = "0123456789ABCDEF";

    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        unsigned char c = *p;
        char scratch[8];
        size_t n = 0;

        switch (c) {
            case '"':  memcpy(scratch, "\\\"", 2); n = 2; break;
            case '\\': memcpy(scratch, "\\\\", 2); n = 2; break;
            case '\b': memcpy(scratch, "\\b", 2);  n = 2; break;
            case '\f': memcpy(scratch, "\\f", 2);  n = 2; break;
            case '\n': memcpy(scratch, "\\n", 2);  n = 2; break;
            case '\r': memcpy(scratch, "\\r", 2);  n = 2; break;
            case '\t': memcpy(scratch, "\\t", 2);  n = 2; break;
            default:
                if (c < 0x20) {
                    scratch[0] = '\\';
                    scratch[1] = 'u';
                    scratch[2] = '0';
                    scratch[3] = '0';
                    scratch[4] = hex[(c >> 4) & 0x0F];
                    scratch[5] = hex[c & 0x0F];
                    n = 6;
                } else {
                    scratch[0] = (char)c;
                    n = 1;
                }
                break;
        }

        if (written + n + 1 > capacity) {
            /* `written < capacity` holds here, so terminating is in bounds and
             * keeps the buffer a valid C string on the truncation path too. */
            out[written] = '\0';
            *out_len = written;
            return HC_ERR_TRUNC;
        }
        memcpy(out + written, scratch, n);
        written += n;
    }

    out[written] = '\0';
    *out_len = written;
    return HC_OK;
}
