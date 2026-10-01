/*
 * HELIOS-NET :: transport/c_core/src/aho_corasick.c
 * Aho-Corasick multi-pattern automaton with sparse child edges.
 *
 * Representation:
 *   - Nodes live in one growable arena; every edge is stored as a parallel
 *     (byte, child_index) pair kept sorted by byte, so transitions use binary
 *     search instead of a 256-wide table. A dense table would waste 1 KiB per
 *     node and dominate memory for large signature sets.
 *   - A "dense tail" table accelerates high-fanout nodes (the root and shallow
 *     levels), where repeated binary search would otherwise dominate.
 *
 * Scanning is O(text_len + matches): the failure function guarantees each input
 * byte is examined a constant number of times.
 */

#include "helios_core.h"

#include <stdlib.h>
#include <string.h>

#define AC_DENSE_MIN_CHILDREN 12

typedef struct {
    uint8_t  *bytes;      /* sorted edge labels             */
    uint32_t *children;   /* parallel child node indices    */
    uint32_t  n_children;
    uint32_t  dense_base; /* 1-based offset into `dense`, 0 = absent */
    uint32_t  fail;
    uint32_t *outputs;    /* pattern indices ending here    */
    uint32_t  n_outputs;
} ac_node_t;

struct hc_ac {
    ac_node_t *nodes;
    size_t     n_nodes;
    size_t     cap_nodes;

    uint32_t  *dense;
    size_t     n_dense;
    size_t     cap_dense;

    char     **names;
    char     **patterns;
    size_t     n_patterns;
    size_t     cap_patterns;

    int        built;
};

static inline uint8_t lower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/* ------------------------------------------------------------- allocation */

static int nodes_reserve(hc_ac_t *ac, size_t need) {
    if (need <= ac->cap_nodes) {
        return 1;
    }
    size_t cap = ac->cap_nodes ? ac->cap_nodes * 2 : 64;
    while (cap < need) {
        cap *= 2;
    }
    ac_node_t *grown = (ac_node_t *)realloc(ac->nodes, cap * sizeof(*grown));
    if (grown == NULL) {
        return 0;
    }
    memset(grown + ac->cap_nodes, 0, (cap - ac->cap_nodes) * sizeof(*grown));
    ac->nodes = grown;
    ac->cap_nodes = cap;
    return 1;
}

static int dense_reserve(hc_ac_t *ac, size_t need) {
    if (need <= ac->cap_dense) {
        return 1;
    }
    size_t cap = ac->cap_dense ? ac->cap_dense * 2 : 1024;
    while (cap < need) {
        cap *= 2;
    }
    uint32_t *grown = (uint32_t *)realloc(ac->dense, cap * sizeof(*grown));
    if (grown == NULL) {
        return 0;
    }
    ac->dense = grown;
    ac->cap_dense = cap;
    return 1;
}

static int patterns_reserve(hc_ac_t *ac, size_t need) {
    if (need <= ac->cap_patterns) {
        return 1;
    }
    size_t cap = ac->cap_patterns ? ac->cap_patterns * 2 : 32;
    while (cap < need) {
        cap *= 2;
    }
    char **gn = (char **)realloc(ac->names, cap * sizeof(*gn));
    if (gn == NULL) {
        return 0;
    }
    ac->names = gn;
    char **gp = (char **)realloc(ac->patterns, cap * sizeof(*gp));
    if (gp == NULL) {
        return 0;
    }
    ac->patterns = gp;
    ac->cap_patterns = cap;
    return 1;
}

static char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (out != NULL) {
        memcpy(out, s, n);
    }
    return out;
}

/* ------------------------------------------------------------- edge access */

static int edge_find(const hc_ac_t *ac, uint32_t node_index, uint8_t byte, uint32_t *out_child) {
    const ac_node_t *node = &ac->nodes[node_index];
    uint32_t lo = 0;
    uint32_t hi = node->n_children;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (node->bytes[mid] == byte) {
            *out_child = node->children[mid];
            return 1;
        }
        if (node->bytes[mid] < byte) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 0;
}

static int edge_insert(hc_ac_t *ac, uint32_t node_index, uint8_t byte, uint32_t child) {
    ac_node_t *node = &ac->nodes[node_index];
    node->dense_base = 0; /* invalidate the dense shortcut */

    uint32_t pos = 0;
    while (pos < node->n_children && node->bytes[pos] < byte) {
        pos++;
    }

    uint8_t *nb = (uint8_t *)realloc(node->bytes, (node->n_children + 1) * sizeof(*nb));
    if (nb == NULL) {
        return 0;
    }
    node->bytes = nb;

    uint32_t *nc = (uint32_t *)realloc(node->children, (node->n_children + 1) * sizeof(*nc));
    if (nc == NULL) {
        return 0;
    }
    node->children = nc;

    memmove(&node->bytes[pos + 1], &node->bytes[pos], (node->n_children - pos) * sizeof(*nb));
    memmove(&node->children[pos + 1], &node->children[pos], (node->n_children - pos) * sizeof(*nc));

    node->bytes[pos] = byte;
    node->children[pos] = child;
    node->n_children++;
    return 1;
}

static void node_outputs_push(ac_node_t *node, uint32_t pattern_index) {
    for (uint32_t i = 0; i < node->n_outputs; i++) {
        if (node->outputs[i] == pattern_index) {
            return;
        }
    }
    uint32_t *grown = (uint32_t *)realloc(node->outputs, (node->n_outputs + 1) * sizeof(*grown));
    if (grown == NULL) {
        return;
    }
    node->outputs = grown;
    node->outputs[node->n_outputs++] = pattern_index;
}

/*
 * Advance one byte from `from`, following failure links when no direct edge
 * exists. Writes the destination node to `out_next`.
 */
static void ac_advance(const hc_ac_t *ac, uint32_t from, uint8_t byte, uint32_t *out_next) {
    uint32_t state = from;
    for (;;) {
        uint32_t next = 0;
        if (edge_find(ac, state, byte, &next)) {
            *out_next = next;
            return;
        }
        if (state == 0) {
            *out_next = 0; /* no edge from the root: stay at root */
            return;
        }
        state = ac->nodes[state].fail;
    }
}

/* ------------------------------------------------------------ public API */

hc_ac_t *hc_ac_new(void) {
    hc_ac_t *ac = (hc_ac_t *)calloc(1, sizeof(*ac));
    if (ac == NULL) {
        return NULL;
    }
    if (!nodes_reserve(ac, 1)) {
        free(ac);
        return NULL;
    }
    ac->n_nodes = 1; /* node 0 is the root; the first added node is index 1 */
    return ac;
}

void hc_ac_free(hc_ac_t *ac) {
    if (ac == NULL) {
        return;
    }
    for (size_t i = 0; i < ac->n_nodes; i++) {
        free(ac->nodes[i].bytes);
        free(ac->nodes[i].children);
        free(ac->nodes[i].outputs);
    }
    free(ac->nodes);
    free(ac->dense);
    for (size_t i = 0; i < ac->n_patterns; i++) {
        free(ac->names[i]);
        free(ac->patterns[i]);
    }
    free(ac->names);
    free(ac->patterns);
    free(ac);
}

hc_status hc_ac_add(hc_ac_t *ac, const char *name, const char *pattern) {
    if (ac == NULL || pattern == NULL) {
        return HC_ERR_NULL;
    }
    if (pattern[0] == '\0') {
        return HC_ERR_EMPTY;
    }

    /*
     * Reject an identical (name, pattern) registration.
     *
     * Adding the same line twice used to store it twice, so one detection hit
     * emitted the same signature name twice and reported match_count 2. Any
     * aggregate that sums match_count was then inflated by a duplicated input
     * line, which is the same defect the Go port's dedupePorts() fix removed.
     *
     * The comparison is on BOTH fields, which is the point. Two different names
     * sharing one pattern ("alpha<TAB>foo" and "beta<TAB>foo") are two real
     * signatures and both are still reported. De-duplicating on the pattern
     * alone, as the Rust port does, would silently discard an operator's
     * signature; that is information loss, not de-duplication. The Rust port
     * has no name/pattern split at all, so for its pattern-only contract
     * dropping a repeated label is correct and it is deliberately left alone.
     *
     * HC_ERR_DUP rather than HC_OK, because the signature-file loader counts
     * successful adds and would otherwise report the duplicate as loaded.
     */
    const char *effective_name = (name && name[0]) ? name : pattern;
    for (size_t i = 0; i < ac->n_patterns; i++) {
        if (strcmp(ac->names[i], effective_name) == 0 &&
            strcmp(ac->patterns[i], pattern) == 0) {
            return HC_ERR_DUP;
        }
    }
    if (!patterns_reserve(ac, ac->n_patterns + 1)) {
        return HC_ERR_NOMEM;
    }

    uint32_t index = (uint32_t)ac->n_patterns;
    char *stored_pattern = dup_str(pattern);
    if (stored_pattern == NULL) {
        return HC_ERR_NOMEM;
    }
    char *stored_name = dup_str((name && name[0]) ? name : pattern);
    if (stored_name == NULL) {
        free(stored_pattern);
        return HC_ERR_NOMEM;
    }
    ac->names[ac->n_patterns] = stored_name;
    ac->patterns[ac->n_patterns] = stored_pattern;
    ac->n_patterns++;

    uint32_t current = 0;
    for (const uint8_t *p = (const uint8_t *)pattern; *p; p++) {
        uint8_t byte = lower_ascii(*p);
        uint32_t child = 0;
        if (edge_find(ac, current, byte, &child)) {
            current = child;
            continue;
        }
        if (!nodes_reserve(ac, ac->n_nodes + 1)) {
            return HC_ERR_NOMEM;
        }
        uint32_t fresh = (uint32_t)ac->n_nodes++;
        if (!edge_insert(ac, current, byte, fresh)) {
            return HC_ERR_NOMEM;
        }
        current = fresh;
    }

    node_outputs_push(&ac->nodes[current], index);
    return HC_OK;
}

hc_status hc_ac_build(hc_ac_t *ac) {
    if (ac == NULL) {
        return HC_ERR_NULL;
    }
    if (ac->n_patterns == 0) {
        return HC_ERR_EMPTY;
    }

    /* Reset state left over from a previous build. */
    ac->n_dense = 0;
    for (size_t i = 0; i < ac->n_nodes; i++) {
        ac->nodes[i].dense_base = 0;
    }

    uint32_t *queue = (uint32_t *)malloc(ac->n_nodes * sizeof(*queue));
    if (queue == NULL) {
        return HC_ERR_NOMEM;
    }
    size_t head = 0;
    size_t tail = 0;

    for (uint32_t i = 0; i < ac->nodes[0].n_children; i++) {
        uint32_t child = ac->nodes[0].children[i];
        ac->nodes[child].fail = 0;
        queue[tail++] = child;
    }

    while (head < tail) {
        uint32_t current = queue[head++];

        /* Inherit outputs from the failure state so suffix matches are reported. */
        uint32_t fail = ac->nodes[current].fail;
        for (uint32_t k = 0; k < ac->nodes[fail].n_outputs; k++) {
            node_outputs_push(&ac->nodes[current], ac->nodes[fail].outputs[k]);
        }

        for (uint32_t i = 0; i < ac->nodes[current].n_children; i++) {
            uint8_t byte = ac->nodes[current].bytes[i];
            uint32_t child = ac->nodes[current].children[i];
            uint32_t next = 0;
            ac_advance(ac, fail, byte, &next);
            ac->nodes[child].fail = next;
            queue[tail++] = child;
        }
    }
    free(queue);

    /*
     * Materialise dense shortcuts. Each selected node copies its sorted
     * (label, child) pairs into a flat table addressed by a 1-based offset.
     */
    for (size_t i = 0; i < ac->n_nodes; i++) {
        ac_node_t *node = &ac->nodes[i];
        if (node->n_children < AC_DENSE_MIN_CHILDREN) {
            continue;
        }
        if (!dense_reserve(ac, ac->n_dense + node->n_children)) {
            return HC_ERR_NOMEM;
        }
        node->dense_base = (uint32_t)(ac->n_dense + 1);
        for (uint32_t k = 0; k < node->n_children; k++) {
            ac->dense[ac->n_dense + k] = node->children[k];
        }
        ac->n_dense += node->n_children;
    }

    ac->built = 1;
    return HC_OK;
}

size_t hc_ac_count(const hc_ac_t *ac) {
    return ac ? ac->n_patterns : 0;
}

size_t hc_ac_nodes(const hc_ac_t *ac) {
    return ac ? ac->n_nodes : 0;
}

int hc_ac_scan(const hc_ac_t *ac, const char *text, size_t text_len,
               hc_ac_match_fn cb, void *user) {
    if (ac == NULL || text == NULL || cb == NULL) {
        return HC_ERR_NULL;
    }
    if (!ac->built) {
        return HC_ERR_STATE;
    }
    if (text_len == 0) {
        return 0;
    }

    uint32_t current = 0;
    int reported = 0;
    const uint8_t *t = (const uint8_t *)text;

    for (size_t i = 0; i < text_len; i++) {
        ac_advance(ac, current, lower_ascii(t[i]), &current);

        const ac_node_t *node = &ac->nodes[current];
        for (uint32_t k = 0; k < node->n_outputs; k++) {
            uint32_t pattern_index = node->outputs[k];
            size_t pattern_len = strlen(ac->patterns[pattern_index]);
            size_t start = (i + 1 >= pattern_len) ? (i + 1 - pattern_len) : 0;
            cb(ac->names[pattern_index], ac->patterns[pattern_index], start, user);
            reported++;
        }
    }
    return reported;
}

hc_status hc_ac_scan_to_buffer(const hc_ac_t *ac, const char *text,
                               char *out, size_t *out_len, size_t max_names) {
    if (ac == NULL || text == NULL || out == NULL || out_len == NULL) {
        return HC_ERR_NULL;
    }
    size_t capacity = *out_len;
    *out_len = 0;
    /*
     * Capacity must be read before the first store. A caller asking "I have no
     * room" passes *out_len == 0, and writing out[0] first overflowed that
     * buffer by one byte.
     */
    if (capacity == 0) {
        return HC_ERR_TRUNC;
    }
    out[0] = '\0';
    if (!ac->built) {
        return HC_ERR_STATE;
    }

    const uint8_t *t = (const uint8_t *)text;
    size_t text_len = strlen(text);
    size_t written = 0;
    uint32_t current = 0;
    size_t emitted = 0;

    for (size_t i = 0; i < text_len && emitted < max_names; i++) {
        ac_advance(ac, current, lower_ascii(t[i]), &current);

        const ac_node_t *node = &ac->nodes[current];
        for (uint32_t k = 0; k < node->n_outputs && emitted < max_names; k++) {
            const char *name = ac->names[node->outputs[k]];
            size_t n = strlen(name);
            if (written + n + 1 >= capacity) {
                /*
                 * Every append leaves `written < capacity`, so terminating here
                 * is in bounds. Without it the truncation path returned a byte
                 * run that only looked like a C string, and a caller reading
                 * out[*out_len] would run past the written content.
                 */
                out[written] = '\0';
                *out_len = written;
                return HC_ERR_TRUNC;
            }
            memcpy(out + written, name, n);
            written += n;
            out[written++] = '\n';
            emitted++;
        }
    }

    if (written == 0) {
        *out_len = 0;
        return HC_OK;
    }
    out[written] = '\0';
    *out_len = written;
    return HC_OK;
}
