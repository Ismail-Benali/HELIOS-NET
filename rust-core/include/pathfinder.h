/* HELIOS-NET :: rust-core/include/pathfinder.h
   C Header for Rust A* Pathfinder FFI Library.
*/

#ifndef HELIOS_PATHFINDER_H
#define HELIOS_PATHFINDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct {
    const char *node_id;
    double edr_presence_score;
    double firewall_level;
    double honeypot_probability;
    double network_barrier;
    double base_distance;
} NodeRiskProfile;

typedef struct {
    char **path_nodes;
    int path_length;
    double total_risk_score;
    const char *strategy;
} OptimalPath;

OptimalPath* calculate_optimal_path(
    const NodeRiskProfile *nodes_ptr,
    int node_count,
    const char *start_node,
    const char *target_node,
    const char *strategy
);

void free_path(OptimalPath *path_ptr);

#ifdef __cplusplus
}
#endif

#endif /* HELIOS-NET :: pathfinder.h */
