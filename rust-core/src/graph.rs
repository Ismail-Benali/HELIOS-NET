//! Undirected graph analytics for the asset graph.
//!
//! `engine/graph/core.py` is the Python reference implementation; this module is
//! the native counterpart and is held to producing identical numbers by
//! `tests/test_rust_core.py`.
//!
//! Everything is iterative rather than recursive so a deep attack path cannot
//! overflow the stack, and every cost accumulation is checked so a hostile graph
//! cannot wrap the counter in a release build.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Maximum path cost considered by the bounded searches.
const COST_INFINITY: u64 = u64::MAX;

/// Min-heap entry for Dijkstra.
struct Entry {
    cost: u64,
    node: usize,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.node == other.node
    }
}

impl Eq for Entry {}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so `BinaryHeap` (a max-heap) pops the cheapest node first.
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| other.node.cmp(&self.node))
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// An undirected graph over `0..n`.
pub struct Graph {
    n: usize,
    adj: Vec<Vec<usize>>,
}

impl Graph {
    /// Builds from a flat edge list. Self-loops and out-of-range endpoints are dropped.
    pub fn from_edges(n: usize, edges: &[(usize, usize)]) -> Self {
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(a, b) in edges {
            if a >= n || b >= n || a == b {
                continue;
            }
            adj[a].push(b);
            adj[b].push(a);
        }
        // Deduplicate parallel edges; centrality must not double-count them.
        for list in &mut adj {
            list.sort_unstable();
            list.dedup();
        }
        Graph { n, adj }
    }

    pub fn node_count(&self) -> usize {
        self.n
    }

    pub fn edge_count(&self) -> usize {
        self.adj.iter().map(|l| l.len()).sum::<usize>() / 2
    }

    pub fn degree(&self, node: usize) -> usize {
        self.adj.get(node).map(|l| l.len()).unwrap_or(0)
    }

    /// Normalized degree centrality in `[0, 1]`, descending.
    ///
    /// An isolated single-node graph yields `0.0` rather than dividing by zero.
    pub fn degree_centrality(&self) -> Vec<(usize, f64)> {
        if self.n == 0 {
            return Vec::new();
        }
        // With a single node there is no possible neighbour, so normalising by
        // (n - 1) would divide 0.0 by 0.0 and yield NaN. Report 0.0 instead.
        let max_degree = (self.n - 1) as f64;
        if max_degree == 0.0 {
            return (0..self.n).map(|i| (i, 0.0)).collect();
        }
        let mut out: Vec<(usize, f64)> = (0..self.n)
            .map(|i| (i, self.degree(i) as f64 / max_degree))
            .collect();
        out.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(Ordering::Equal)
                .then(a.0.cmp(&b.0))
        });
        out
    }

    /// Betweenness centrality via Brandes' algorithm (unweighted, undirected).
    ///
    /// Uses an explicit stack instead of recursion. Result is divided by two for
    /// the undirected case so the values match the Python reference.
    pub fn betweenness_centrality(&self) -> Vec<f64> {
        let mut cb = vec![0.0f64; self.n];
        for s in 0..self.n {
            let mut stack: Vec<usize> = Vec::new();
            let mut preds: Vec<Vec<usize>> = vec![Vec::new(); self.n];
            let mut sigma = vec![0.0f64; self.n];
            let mut dist = vec![-1i64; self.n];
            let mut queue: Vec<usize> = Vec::new();

            sigma[s] = 1.0;
            dist[s] = 0;
            queue.push(s);

            let mut head = 0usize;
            while head < queue.len() {
                let v = queue[head];
                head += 1;
                stack.push(v);

                for &w in &self.adj[v] {
                    if dist[w] < 0 {
                        dist[w] = dist[v] + 1;
                        queue.push(w);
                    }
                    if dist[w] == dist[v] + 1 {
                        sigma[w] += sigma[v];
                        preds[w].push(v);
                    }
                }
            }

            let mut delta = vec![0.0f64; self.n];
            while let Some(w) = stack.pop() {
                for &v in &preds[w] {
                    if sigma[w] > 0.0 {
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
                    }
                }
                if w != s {
                    cb[w] += delta[w];
                }
            }
        }

        // Undirected: every shortest path was counted once from each endpoint.
        for value in &mut cb {
            *value /= 2.0;
        }
        cb
    }

    /// Connected components, each sorted ascending, ordered by their first member.
    pub fn connected_components(&self) -> Vec<Vec<usize>> {
        let mut seen = vec![false; self.n];
        let mut components: Vec<Vec<usize>> = Vec::new();

        for root in 0..self.n {
            if seen[root] {
                continue;
            }
            seen[root] = true;
            let mut stack = vec![root];
            let mut members: Vec<usize> = Vec::new();

            while let Some(v) = stack.pop() {
                members.push(v);
                for &w in &self.adj[v] {
                    if !seen[w] {
                        seen[w] = true;
                        stack.push(w);
                    }
                }
            }
            members.sort_unstable();
            components.push(members);
        }
        components
    }

    /// Single-source shortest paths in hop count, via Dijkstra.
    ///
    /// Returns `None` for unreachable nodes. `dist[s] = 0` even when the source
    /// is isolated. Uses `u64` with checked addition so a huge hop count cannot wrap.
    pub fn shortest_hops_from(&self, source: usize) -> Vec<Option<u64>> {
        let mut dist: Vec<u64> = vec![COST_INFINITY; self.n];
        if source >= self.n {
            return vec![None; self.n];
        }
        dist[source] = 0;
        let mut settled = vec![false; self.n];
        let mut heap = BinaryHeap::new();
        heap.push(Entry {
            cost: 0,
            node: source,
        });

        while let Some(Entry { cost, node }) = heap.pop() {
            if settled[node] {
                continue;
            }
            settled[node] = true;
            for &next in &self.adj[node] {
                if settled[next] {
                    continue;
                }
                // Unit weights, but the add is checked so the invariant is explicit.
                let candidate = match cost.checked_add(1) {
                    Some(c) => c,
                    None => continue,
                };
                if candidate < dist[next] {
                    dist[next] = candidate;
                    heap.push(Entry {
                        cost: candidate,
                        node: next,
                    });
                }
            }
        }

        dist.iter()
            .map(|&d| if d == COST_INFINITY { None } else { Some(d) })
            .collect()
    }

    /// Hop distance from `source` to `goal`, plus the path when reachable.
    pub fn shortest_path(&self, source: usize, goal: usize) -> Option<(u64, Vec<usize>)> {
        if source >= self.n || goal >= self.n {
            return None;
        }
        let dist = self.shortest_hops_from(source);
        let cost = dist[goal]?;

        let mut prev = vec![usize::MAX; self.n];
        let mut seen = vec![false; self.n];
        let mut frontier = vec![source];
        seen[source] = true;
        let mut depth = 0u64;

        while depth < cost && !frontier.is_empty() {
            let mut next_frontier = Vec::new();
            for &v in &frontier {
                for &w in &self.adj[v] {
                    if !seen[w] {
                        seen[w] = true;
                        prev[w] = v;
                        next_frontier.push(w);
                    }
                }
            }
            frontier = next_frontier;
            depth += 1;
        }

        let mut path = vec![goal];
        let mut cur = goal;
        while cur != source {
            let p = prev[cur];
            if p == usize::MAX {
                return Some((cost, vec![goal]));
            }
            path.push(p);
            cur = p;
        }
        path.reverse();
        Some((cost, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A - B - C, with D isolated.
    fn chain() -> Graph {
        Graph::from_edges(4, &[(0, 1), (1, 2)])
    }

    #[test]
    fn builds_and_counts() {
        let g = chain();
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.edge_count(), 2);
        assert_eq!(g.degree(1), 2);
        assert_eq!(g.degree(3), 0);
    }

    #[test]
    fn drops_self_loops_and_out_of_range_edges() {
        let g = Graph::from_edges(3, &[(0, 0), (0, 9), (1, 2)]);
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.degree(0), 0);
    }

    #[test]
    fn parallel_edges_are_deduplicated() {
        let g = Graph::from_edges(2, &[(0, 1), (0, 1), (1, 0)]);
        assert_eq!(g.degree(0), 1);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn empty_graph_is_safe() {
        let g = Graph::from_edges(0, &[]);
        assert!(g.degree_centrality().is_empty());
        assert!(g.connected_components().is_empty());
        assert!(g.betweenness_centrality().is_empty());
        assert!(g.shortest_path(0, 0).is_none());
    }

    #[test]
    fn single_node_graph_has_zero_centrality_not_nan() {
        let g = Graph::from_edges(1, &[]);
        let dc = g.degree_centrality();
        assert_eq!(dc, vec![(0, 0.0)]);
        assert!(dc[0].1.is_finite());
    }

    #[test]
    fn degree_centrality_is_normalized_and_sorted() {
        // Hub 0 connected to 1,2,3; 1-2 connected.
        let g = Graph::from_edges(4, &[(0, 1), (0, 2), (0, 3), (1, 2)]);
        let dc = g.degree_centrality();
        assert_eq!(dc[0].0, 0, "the hub ranks first");
        assert!((dc[0].1 - 1.0).abs() < 1e-12, "hub is fully central");
        assert!(dc.iter().all(|&(_, v)| (0.0..=1.0).contains(&v)));
    }

    #[test]
    fn connected_components_separates_islands() {
        let g = Graph::from_edges(6, &[(0, 1), (1, 2), (3, 4)]);
        let comps = g.connected_components();
        assert_eq!(comps, vec![vec![0, 1, 2], vec![3, 4], vec![5]]);
    }

    #[test]
    fn components_of_fully_connected_graph_is_one() {
        let g = Graph::from_edges(3, &[(0, 1), (1, 2), (0, 2)]);
        assert_eq!(g.connected_components(), vec![vec![0, 1, 2]]);
    }

    #[test]
    fn betweenness_peaks_at_the_middle_node() {
        // 0 - 1 - 2 : node 1 lies on every path.
        let g = Graph::from_edges(3, &[(0, 1), (1, 2)]);
        let cb = g.betweenness_centrality();
        assert!(cb[1] > cb[0], "middle node must dominate: {cb:?}");
        assert!(cb[1] > cb[2]);
        // Undirected normalisation: the single path 0->2 is counted once.
        assert!((cb[1] - 1.0).abs() < 1e-12, "got {cb:?}");
        assert!(cb[0].abs() < 1e-12);
    }

    #[test]
    fn betweenness_of_star_graph() {
        // 0 is the hub with 4 leaves; no path between leaves needs it twice.
        let g = Graph::from_edges(5, &[(0, 1), (0, 2), (0, 3), (0, 4)]);
        let cb = g.betweenness_centrality();
        assert!(cb[0] > 0.0, "hub carries all leaf-to-leaf traffic");
        for value in cb.iter().skip(1) {
            assert!(value.abs() < 1e-12, "leaf should be zero: {cb:?}");
        }
    }

    #[test]
    fn betweenness_all_zero_for_disconnected_pairs() {
        let g = Graph::from_edges(4, &[(0, 1)]);
        let cb = g.betweenness_centrality();
        assert!(cb.iter().all(|&v| v.abs() < 1e-12), "{cb:?}");
    }

    #[test]
    fn dijkstra_finds_hop_distances() {
        let g = chain();
        let d = g.shortest_hops_from(0);
        assert_eq!(d[0], Some(0));
        assert_eq!(d[1], Some(1));
        assert_eq!(d[2], Some(2));
        assert_eq!(d[3], None, "isolated node is unreachable");
    }

    #[test]
    fn dijkstra_source_is_always_zero_even_when_isolated() {
        let g = chain();
        let d = g.shortest_hops_from(3);
        assert_eq!(d[3], Some(0));
        assert_eq!(d[0], None);
    }

    #[test]
    fn dijkstra_out_of_range_source_is_all_none() {
        let g = chain();
        assert!(g.shortest_hops_from(99).iter().all(|d| d.is_none()));
    }

    #[test]
    fn shortest_path_returns_cost_and_route() {
        let g = chain();
        let (cost, path) = g.shortest_path(0, 2).expect("path exists");
        assert_eq!(cost, 2);
        assert_eq!(path, vec![0, 1, 2]);
    }

    #[test]
    fn shortest_path_to_self_is_trivial() {
        let g = chain();
        let (cost, path) = g.shortest_path(2, 2).unwrap();
        assert_eq!(cost, 0);
        assert_eq!(path, vec![2]);
    }

    #[test]
    fn shortest_path_unreachable_returns_none() {
        let g = chain();
        assert!(g.shortest_path(3, 0).is_none());
        assert!(g.shortest_path(0, 99).is_none());
    }

    #[test]
    fn shortest_path_in_cycle_is_minimum() {
        // Square 0-1-2-3-0; 0 to 2 is two hops either way.
        let g = Graph::from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]);
        let (cost, path) = g.shortest_path(0, 2).unwrap();
        assert_eq!(cost, 2);
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], 0);
        assert_eq!(*path.last().unwrap(), 2);
    }

    #[test]
    fn deep_chain_does_not_overflow_the_stack() {
        // 50k-node path: recursion would blow up here, the iterative walk must not.
        let n = 50_000usize;
        let edges: Vec<(usize, usize)> = (0..n - 1).map(|i| (i, i + 1)).collect();
        let g = Graph::from_edges(n, &edges);
        let d = g.shortest_hops_from(0);
        assert_eq!(d[n - 1], Some((n - 1) as u64));
        let (cost, path) = g.shortest_path(0, n - 1).unwrap();
        assert_eq!(cost, (n - 1) as u64);
        assert_eq!(path.len(), n);
    }
}
