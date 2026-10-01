/*
 * HELIOS-NET :: transport/c_core/src/hashing.c
 * Non-cryptographic hashing primitives: FNV-1a (32/64), CRC-32 (IEEE),
 * a rolling FNV-1a window hash, and case-insensitive substring search.
 *
 * These are distribution and fingerprinting hashes only - not cryptographic.
 * For integrity guarantees use a MAC or AEAD, never these functions.
 */

#include "helios_core.h"

#include <string.h>

/* ------------------------------------------------------------------ FNV-1a */

uint32_t hc_fnv1a32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t hash = 0x811c9dc5u; /* FNV offset basis */
    if (p == NULL) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint32_t)p[i];
        hash *= 0x01000193u; /* FNV prime */
    }
    return hash;
}

uint64_t hc_fnv1a64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t hash = 0xcbf29ce484222325ULL;
    if (p == NULL) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)p[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

/* ------------------------------------------------------------------ CRC-32 */

/*
 * IEEE 802.3 polynomial, reflected (0xEDB88320). The table is built once at
 * first use; construction is deterministic so no locking is required for
 * read-only concurrent use after initialisation.
 */
static uint32_t crc_table[256];
static int crc_table_ready = 0;

static void crc32_build_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
    crc_table_ready = 1;
}

uint32_t hc_crc32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    if (p == NULL) {
        return 0;
    }
    if (!crc_table_ready) {
        crc32_build_table();
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* -------------------------------------------------------------- rolling FNV */

void hc_rollhash_init(hc_rollhash_t *state) {
    if (state == NULL) {
        return;
    }
    state->offset_basis = 0xcbf29ce484222325ULL;
    state->prime = 0x100000001b3ULL;
}

void hc_rollhash_update(hc_rollhash_t *state, uint8_t byte) {
    if (state == NULL) {
        return;
    }
    state->offset_basis ^= (uint64_t)byte;
    state->offset_basis *= state->prime;
}

/* ------------------------------------------------------ case-insensitive search */

static inline uint8_t lower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

int hc_contains_ci(const char *text, const char *needle) {
    if (text == NULL || needle == NULL) {
        return 0;
    }
    size_t nlen = strlen(needle);
    if (nlen == 0) {
        return 1; /* an empty needle is trivially present */
    }
    size_t tlen = strlen(text);
    if (nlen > tlen) {
        return 0;
    }

    uint8_t first = lower_ascii((uint8_t)needle[0]);
    for (size_t i = 0; i + nlen <= tlen; i++) {
        if (lower_ascii((uint8_t)text[i]) != first) {
            continue;
        }
        size_t j = 1;
        while (j < nlen &&
               lower_ascii((uint8_t)text[i + j]) == lower_ascii((uint8_t)needle[j])) {
            j++;
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}
