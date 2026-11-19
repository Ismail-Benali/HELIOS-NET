//! Directed, weighted graph analytics in CSR form.
//!
//! `graph.rs` answers the legacy undirected, unit-weight questions exposed by
//! ABI v2. This module adds the questions an asset graph actually asks: what is
//! important (PageRank), what does a route cost (weighted Dijkstra), and what
//! breaks the graph when it fails (articulation points and bridges).
//!
//! Representation is a flat CSR (offsets -> targets -> weights) rather than a
//! `Vec<Vec<usize>>` per node. Rebuilding adjacency per call is still the
//! caller's choice; this only makes each call cheaper and cache-friendly.
//!
//! Parallel edges collapse to the cheapest one and self-edges are dropped, so a
//! re-ingested relationship cannot inflate a score or shorten a route. Every
//! traversal is iterative: a hostile graph with a million-deep path must return
//! a number, not overflow the stack.
//!
//! All arithmetic is checked. A weight or path cost that would wrap returns the
//! node as unreachable instead of silently reporting a cheaper route.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Damping factor for PageRank.
const DAMPING: f64 = 0.85;
/// PageRank stops when the L1 delta falls below this.
const PAGERANK_TOLERANCE: f64 = 1e-10;
/// Hard iteration cap so a host cannot spend unbounded time in one call.
const PAGERANK_MAX_ITERATIONS: usize = 100;

/// Heap entry ordered so `BinaryHeap` pops the cheapest route first.
struct CostEntry {
    cost: u64,
    node: usize,
}

impl PartialEq for CostEntry {
    fn eq(&self, other: &Self) -> bool {
        self.cost == other.cost && self.node == other.node
    }
}

impl Eq for CostEntry {}

impl Ord for CostEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| other.node.cmp(&self.node))
    }
}

impl PartialOrd for CostEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A directed or undirected graph in compressed sparse row form.
pub struct Csr {
    n: usize,
    directed: bool,
    offsets: Vec<usize>,
    targets: Vec<usize>,
    weights: Vec<u64>,
}

impl Csr {
    /// Builds CSR from `(source, target, weight)` triples.
    ///
    /// Endpoints outside `0..n` and self-edges are dropped. When `directed` is
    /// false every edge is inserted in both directions. Duplicate targets keep
    /// the lowest weight.
    pub fn from_edges(n: usize, edges: &[(usize, usize, u64)], directed: bool) -> Self {
        let mut rows: Vec<Vec<(usize, u64)>> = vec![Vec::new(); n];
        for &(a, b, weight) in edges {
            if a >= n || b >= n || a == b {
                continue;
            }
            rows[a].push((b, weight));
            if !directed {
                rows[b].push((a, weight));
            }
        }

        let mut offsets = Vec::with_capacity(n + 1);
        let mut targets = Vec::new();
        let mut weights = Vec::new();
        let mut total = 0usize;
        for row in &mut rows {
            row.sort_unstable();
            row.dedup_by_key(|entry| entry.0);
            offsets.push(total);
            for &(target, weight) in row.iter() {
                targets.push(target);
                weights.push(weight);
            }
            total += row.len();
        }
        offsets.push(total);

        Csr {
            n,
            directed,
            offsets,
            targets,
            weights,
        }
    }

    pub fn node_count(&self) -> usize {
        self.n
    }

    pub fn is_directed(&self) -> bool {
        self.directed
    }

    pub fn edge_count(&self) -> usize {
        if self.directed {
            self.targets.len()
        } else {
            self.targets.len() / 2
        }
    }

    /// PageRank over the stored orientation, in `[0, 1]`, indexed by node.
    ///
    /// A dangling node (out-degree zero) spreads its mass evenly, and an empty
    /// graph returns an empty vector rather than dividing by zero.
    pub fn pagerank(&self) -> Vec<f64> {
        if self.n == 0 {
            return Vec::new();
        }
        let inv = 1.0 / self.n as f64;
        let mut rank = vec![inv; self.n];

        for _ in 0..PAGERANK_MAX_ITERATIONS {
            let mut next = vec![0.0f64; self.n];
            let mut dangling = 0.0f64;
            for (node, value) in rank.iter().enumerate() {
                let start = self.offsets[node];
                let end = self.offsets[node + 1];
                let out_degree = end - start;
                if out_degree == 0 {
                    dangling += value;
                    continue;
                }
                let share = value / out_degree as f64;
                for &target in &self.targets[start..end] {
                    next[target] += share;
                }
            }

            let base = (1.0 - DAMPING) * inv + DAMPING * dangling * inv;
            let mut delta = 0.0f64;
            for (node, value) in next.iter_mut().enumerate() {
                *value = base + DAMPING * *value;
                delta += (*value - rank[node]).abs();
            }
            rank = next;
            if delta < PAGERANK_TOLERANCE {
                break;
            }
        }
        rank
    }

    /// Cheapest route from `source` to `goal` as `(cost, path)`.
    ///
    /// `None` means unreachable (including an out-of-range endpoint or a cost
    /// that would overflow). Equal-cost routes resolve by lowest node index so
    /// the answer does not depend on insertion order.
    pub fn weighted_shortest_path(&self, source: usize, goal: usize) -> Option<(u64, Vec<usize>)> {
        if source >= self.n || goal >= self.n {
            return None;
        }
        if source == goal {
            return Some((0, vec![source]));
        }

        let mut dist = vec![u64::MAX; self.n];
        let mut prev = vec![usize::MAX; self.n];
        let mut settled = vec![false; self.n];
        let mut heap = BinaryHeap::new();
        dist[source] = 0;
        heap.push(CostEntry {
            cost: 0,
            node: source,
        });

        while let Some(CostEntry { cost, node }) = heap.pop() {
            if settled[node] {
                continue;
            }
            settled[node] = true;
            if node == goal {
                break;
            }
            for offset in self.offsets[node]..self.offsets[node + 1] {
                let target = self.targets[offset];
                if settled[target] {
                    continue;
                }
                let candidate = match cost.checked_add(self.weights[offset]) {
                    Some(value) => value,
                    None => continue,
                };
                if candidate < dist[target] {
                    dist[target] = candidate;
                    prev[target] = node;
                    heap.push(CostEntry {
                        cost: candidate,
                        node: target,
                    });
                }
            }
        }

        if dist[goal] == u64::MAX {
            return None;
        }
        let mut path = vec![goal];
        let mut cursor = goal;
        while cursor != source {
            let parent = prev[cursor];
            if parent == usize::MAX {
                return None;
            }
            path.push(parent);
            cursor = parent;
        }
        path.reverse();
        Some((dist[goal], path))
    }

    /// Articulation points and bridges of the underlying undirected graph.
    ///
    /// Direction and weights are ignored: the question is "what removal
    /// disconnects the network", and a bridge is a bridge regardless of which
    /// way the asset graph happened to record the relationship.
    pub fn articulation_and_bridges(&self) -> (Vec<usize>, Vec<(usize, usize)>) {
        let adjacency = self.undirected_neighbours();
        let n = self.n;
        let mut discovery = vec![usize::MAX; n];
        let mut low = vec![0usize; n];
        let mut parent = vec![usize::MAX; n];
        let mut children = vec![0usize; n];
        let mut articulation = vec![false; n];
        let mut bridges: Vec<(usize, usize)> = Vec::new();
        let mut clock = 0usize;

        for root in 0..n {
            if discovery[root] != usize::MAX {
                continue;
            }
            discovery[root] = clock;
            low[root] = clock;
            clock += 1;
            let mut stack: Vec<(usize, usize)> = vec![(root, 0)];

            while let Some((node, next_index)) = stack.pop() {
                if next_index < adjacency[node].len() {
                    let neighbour = adjacency[node][next_index];
                    stack.push((node, next_index + 1));

                    if neighbour == parent[node] {
                        continue;
                    }
                    if discovery[neighbour] == usize::MAX {
                        parent[neighbour] = node;
                        children[node] += 1;
                        discovery[neighbour] = clock;
                        low[neighbour] = clock;
                        clock += 1;
                        stack.push((neighbour, 0));
                    } else {
                        low[node] = low[node].min(discovery[neighbour]);
                    }
                    continue;
                }

                if let Some(ancestor) = stack.last().map(|entry| entry.0) {
                    low[ancestor] = low[ancestor].min(low[node]);
                    if low[node] > discovery[ancestor] {
                        bridges.push((ancestor.min(node), ancestor.max(node)));
                    }
                    if parent[ancestor] != usize::MAX && low[node] >= discovery[ancestor] {
                        articulation[ancestor] = true;
                    }
                }
            }

            if children[root] > 1 {
                articulation[root] = true;
            }
        }

        let points = (0..n).filter(|&node| articulation[node]).collect();
        bridges.sort_unstable();
        bridges.dedup();
        (points, bridges)
    }

    fn undirected_neighbours(&self) -> Vec<Vec<usize>> {
        let mut rows: Vec<Vec<usize>> = vec![Vec::new(); self.n];
        for node in 0..self.n {
            for &target in &self.targets[self.offsets[node]..self.offsets[node + 1]] {
                if target == node {
                    continue;
                }
                rows[node].push(target);
                rows[target].push(node);
            }
        }
        for row in &mut rows {
            row.sort_unstable();
            row.dedup();
        }
        rows
    }
}
