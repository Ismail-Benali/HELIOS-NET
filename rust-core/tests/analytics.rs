//! Contract tests for the directed/weighted CSR analytics.
//!
//! These cover the properties the Python reference implementation and the ABI
//! rely on: duplicate edges collapse to the cheapest weight, direction is
//! honoured by PageRank and routing, the undirected view drives articulation,
//! and an overflowing cost is unreachable rather than silently wrapped.

use helios_rust_core::analytics::Csr;

#[test]
fn duplicate_edges_keep_the_cheapest_weight() {
    let graph = Csr::from_edges(2, &[(0, 1, 9), (0, 1, 2)], false);
    assert_eq!(graph.edge_count(), 1);
    assert_eq!(
        graph.weighted_shortest_path(0, 1).map(|(cost, _)| cost),
        Some(2)
    );
}

#[test]
fn self_edges_and_out_of_range_endpoints_are_dropped() {
    let graph = Csr::from_edges(2, &[(0, 0, 1), (0, 5, 1), (1, 1, 1)], false);
    assert_eq!(graph.edge_count(), 0);
    let rank = graph.pagerank();
    assert_eq!(rank, vec![0.5, 0.5]);
    assert!((rank.iter().sum::<f64>() - 1.0).abs() < 1e-9);
}

#[test]
fn direction_changes_reachability_and_pagerank() {
    let edges = [(0, 1, 1), (1, 2, 1)];
    let directed = Csr::from_edges(3, &edges, true);
    assert_eq!(
        directed.weighted_shortest_path(0, 2).map(|(cost, _)| cost),
        Some(2)
    );
    assert!(directed.weighted_shortest_path(2, 0).is_none());
    let rank = directed.pagerank();
    assert!(rank[0] < rank[1] && rank[1] < rank[2]);
    assert!((rank.iter().sum::<f64>() - 1.0).abs() < 1e-9);

    let undirected = Csr::from_edges(3, &edges, false);
    assert_eq!(
        undirected
            .weighted_shortest_path(2, 0)
            .map(|(cost, _)| cost),
        Some(2)
    );
}

#[test]
fn pagerank_of_a_cycle_is_uniform_and_sums_to_one() {
    let graph = Csr::from_edges(4, &[(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1)], true);
    let rank = graph.pagerank();
    for value in &rank {
        assert!((value - 0.25).abs() < 1e-9, "rank drifted: {rank:?}");
    }
    assert!((rank.iter().sum::<f64>() - 1.0).abs() < 1e-9);
}

#[test]
fn weighted_route_prefers_the_cheaper_detour() {
    let graph = Csr::from_edges(
        4,
        &[(0, 1, 1), (1, 2, 1), (0, 2, 10), (0, 3, 1), (3, 2, 1)],
        true,
    );
    assert_eq!(graph.weighted_shortest_path(0, 2), Some((2, vec![0, 1, 2])));
}

#[test]
fn an_overflowing_cost_is_unreachable() {
    let huge = u64::MAX / 2 + 1;
    let graph = Csr::from_edges(3, &[(0, 1, huge), (1, 2, huge)], true);
    assert!(graph.weighted_shortest_path(0, 2).is_none());
}

#[test]
fn a_path_graph_reports_its_inner_nodes_and_every_edge() {
    let graph = Csr::from_edges(4, &[(0, 1, 1), (1, 2, 1), (2, 3, 1)], false);
    let (points, bridges) = graph.articulation_and_bridges();
    assert_eq!(points, vec![1, 2]);
    assert_eq!(bridges, vec![(0, 1), (1, 2), (2, 3)]);
}

#[test]
fn a_triangle_has_no_articulation_points_or_bridges() {
    let graph = Csr::from_edges(3, &[(0, 1, 1), (1, 2, 1), (2, 0, 1)], false);
    assert_eq!(graph.articulation_and_bridges(), (Vec::new(), Vec::new()));
}

#[test]
fn disconnected_components_are_analysed_independently() {
    let graph = Csr::from_edges(6, &[(0, 1, 1), (1, 2, 1), (3, 4, 1)], false);
    let (points, bridges) = graph.articulation_and_bridges();
    assert_eq!(points, vec![1]);
    assert_eq!(bridges, vec![(0, 1), (1, 2), (3, 4)]);
}

#[test]
fn articulation_ignores_direction_and_weights() {
    let graph = Csr::from_edges(3, &[(2, 1, 9), (0, 1, 3)], true);
    let (points, bridges) = graph.articulation_and_bridges();
    assert_eq!(points, vec![1]);
    assert_eq!(bridges, vec![(0, 1), (1, 2)]);
}

#[test]
fn empty_and_single_node_graphs_are_total() {
    let empty = Csr::from_edges(0, &[], true);
    assert!(empty.pagerank().is_empty());
    assert!(empty.weighted_shortest_path(0, 0).is_none());

    let single = Csr::from_edges(1, &[], true);
    assert_eq!(single.pagerank(), vec![1.0]);
    assert_eq!(single.weighted_shortest_path(0, 0), Some((0, vec![0])));
}
