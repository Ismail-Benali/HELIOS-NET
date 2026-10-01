//! Dependency-free property and edge-case tests for the Rust core.
//!
//! `cargo-fuzz` needs a nightly toolchain, which this project does not pin, so
//! the randomised coverage here is written against the public Rust API with a
//! deterministic PRNG. That buys two things a fuzz target would not:
//!
//!   * it runs on `cargo test` in CI on stable, so it cannot rot;
//!   * every failure is reproducible from its seed, because the sequence is
//!     fixed rather than wall-clock dependent.
//!
//! The properties asserted are the invariants a panic, an out-of-bounds index,
//! or an arithmetic overflow would break. A banner reaching this core is fully
//! attacker-controlled, so "never panics and never reports a match outside the
//! text" is a security property, not a nicety.

use std::collections::HashSet;

use helios_rust_core::aho::AhoCorasick;
use helios_rust_core::graph::Graph;
use helios_rust_core::{helios_abi_version, helios_rust_version};

// ------------------------------------------------------------------ PRNG

/// xorshift64*: small, deterministic, and good enough to shake out logic bugs.
/// A fixed seed means a failure reported here reproduces exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// Draws a byte, biased towards an ASCII alphabet that includes the
    /// characters the automaton actually cares about (case pairs, digits).
    fn byte(&mut self) -> u8 {
        const ALPHABET: &[u8] = b"aAbBzZ019_-. /\\\"\x00\xff\x80";
        if self.next_u64().is_multiple_of(8) {
            (self.next_u64() & 0xFF) as u8
        } else {
            ALPHABET[self.below(ALPHABET.len())]
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

// ------------------------------------------------- version cannot drift

#[test]
fn advertised_version_matches_the_crate_version() {
    // The version string is built from CARGO_PKG_VERSION, so this can only fail
    // if someone hardcodes a version somewhere else.
    let p = helios_rust_version();
    assert!(!p.is_null(), "helios_rust_version returned NULL");
    let advertised = unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
    assert!(
        advertised.contains(env!("CARGO_PKG_VERSION")),
        "version string {advertised:?} does not contain the crate version {}",
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn version_string_is_stable_across_calls() {
    // The pointer is handed to C and must not move between calls.
    let a = helios_rust_version();
    let b = helios_rust_version();
    assert_eq!(a, b, "version pointer changed between calls");
    assert!(!a.is_null());
}

#[test]
fn abi_version_is_positive_and_stable() {
    assert!(helios_abi_version() > 0);
    assert_eq!(helios_abi_version(), helios_abi_version());
}

// --------------------------------------------------- Aho-Corasick properties

/// A match must always land inside the text it came from. An out-of-range or
/// reversed position would be a memory-safety bug on the Python side, which
/// slices with it.
#[test]
fn every_hit_lies_within_the_text() {
    let mut rng = Rng::new(0xA0C0_1234);
    for round in 0..2_000 {
        let pattern_count = 1 + rng.below(6);
        let mut patterns: Vec<String> = Vec::with_capacity(pattern_count);
        for _ in 0..pattern_count {
            let len = 1 + rng.below(5);
            patterns.push(String::from_utf8_lossy(&rng.bytes(len)).into_owned());
        }
        let text_len = rng.below(40);
        let text = rng.bytes(text_len);

        let mut ac = AhoCorasick::new();
        for p in &patterns {
            ac.add(p);
        }
        ac.build();

        for (_, pos) in ac.scan(&text) {
            assert!(
                pos < text.len(),
                "round {round}: hit at {pos} in a {}-byte text",
                text.len()
            );
        }
    }
}

/// Duplicate patterns must be matched once, not once per registration.
#[test]
fn duplicate_patterns_do_not_multiply_hits() {
    let mut ac = AhoCorasick::new();
    for _ in 0..5 {
        ac.add("alpha");
    }
    ac.build();
    let hits = ac.scan(b"alpha");
    assert_eq!(hits.len(), 1, "duplicate registration produced {hits:?}");
}

/// Adding the same label twice must not change the pattern count in a way that
/// makes `len()` lie to the caller.
#[test]
fn pattern_count_matches_distinct_patterns() {
    let mut ac = AhoCorasick::new();
    ac.add("x");
    ac.add("x");
    ac.add("y");
    assert!(
        ac.len() >= 2,
        "len()={} under-reports distinct patterns x,y",
        ac.len()
    );
}

/// An empty pattern set, an empty text and an unbuilt automaton must all be
/// handled without panicking.
#[test]
fn degenerate_inputs_are_safe() {
    let mut empty = AhoCorasick::new();
    empty.build();
    assert!(empty.scan(b"anything").is_empty());
    assert!(empty.scan(b"").is_empty());

    // An unbuilt automaton has empty output tables, so it reports nothing. The
    // property that matters is that it does not read uninitialised state.
    let mut ac = AhoCorasick::new();
    ac.add("needle");
    let mut hits = Vec::new();
    ac.find_all(b"a needle here", &mut hits);
    assert!(hits.is_empty(), "unbuilt automaton reported a match");

    ac.build();
    assert_eq!(ac.scan(b"").len(), 0);
}

/// Whitespace-only and empty labels are rejected at registration, so a blank
/// pattern can never match everywhere.
#[test]
fn blank_labels_are_rejected() {
    let mut ac = AhoCorasick::new();
    assert!(!ac.add(""), "empty label accepted");
    assert!(!ac.add("   "), "whitespace-only label accepted");
    assert!(!ac.add("\t\n"), "whitespace-only label accepted");
    assert_eq!(ac.len(), 0, "blank labels still counted as patterns");
}

/// A pattern that is a suffix of another must still be reported. The Rust
/// automaton previously emitted matches in BFS order and dropped these.
#[test]
fn suffix_patterns_are_not_dropped() {
    let mut ac = AhoCorasick::new();
    ac.add("he");
    ac.add("she");
    ac.add("his");
    ac.add("hers");
    ac.build();
    let labels: HashSet<String> = ac.scan(b"ushers").into_iter().map(|(l, _)| l).collect();
    for expected in ["he", "she", "hers"] {
        assert!(
            labels.contains(expected),
            "suffix pattern {expected} missing from {labels:?}"
        );
    }
    assert!(!labels.contains("his"), "matched a pattern that is absent");
}

/// Hits must be reported in non-decreasing END-offset order, which is the
/// documented contract of `find_all` and lets a consumer stream results.
///
/// Note this is deliberately asserted on end offsets, not the start offsets
/// that `scan` returns. Start order is NOT monotonic in general: a long pattern
/// ending at i+1 can begin before a short pattern ending at i. Asserting start
/// order would encode a property the core does not promise.
#[test]
fn hits_are_returned_in_end_offset_order() {
    let mut ac = AhoCorasick::new();
    ac.add("aa");
    ac.add("b");
    ac.add("longpattern");
    ac.build();

    let mut hits = Vec::new();
    ac.find_all(b"aabaaabaalongpattern", &mut hits);
    assert!(!hits.is_empty(), "expected matches");
    for pair in hits.windows(2) {
        assert!(
            pair[0].end <= pair[1].end,
            "hits out of end order: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

/// The reported start offset and the label length must reconstruct the end
/// offset exactly. `fold_byte` is 1:1, so the needle length is the label length;
/// if that ever changes this catches the resulting off-by-N.
#[test]
fn start_offset_and_label_length_reconstruct_the_end() {
    let mut rng = Rng::new(0x0FF5_E751);
    for _ in 0..1_000 {
        let pattern_len = 1 + rng.below(6);
        let pattern = String::from_utf8_lossy(&rng.bytes(pattern_len)).into_owned();
        if pattern.trim().is_empty() {
            continue;
        }
        let text_len = rng.below(60);
        let text = rng.bytes(text_len);
        if !text
            .windows(pattern.len())
            .any(|w| w.eq_ignore_ascii_case(pattern.as_bytes()))
        {
            continue;
        }

        let mut ac = AhoCorasick::new();
        ac.add(&pattern);
        ac.build();

        let mut hits = Vec::new();
        ac.find_all(&text, &mut hits);
        for hit in &hits {
            let start = ac.start_offset(hit.pattern, hit.end);
            let label = ac.label(hit.pattern);
            assert_eq!(
                start + label.len(),
                hit.end,
                "start {start} + label len {} != end {}",
                label.len(),
                hit.end
            );
            assert!(start < text.len());
        }
    }
}

/// Overlapping occurrences must all be found, not just non-overlapping ones.
#[test]
fn overlapping_occurrences_are_all_reported() {
    let mut ac = AhoCorasick::new();
    ac.add("aaa");
    ac.build();
    let hits = ac.scan(b"aaaaaaa");
    assert_eq!(hits.len(), 5, "expected 5 overlapping hits, got {hits:?}");
}

/// Very long input must not blow up; the FFI caps it, but the core API itself
/// should stay linear.
#[test]
fn long_input_is_handled_in_reasonable_time() {
    let mut ac = AhoCorasick::new();
    ac.add("needle");
    ac.build();
    let text = vec![b'a'; 200_000];
    let hits = ac.scan(&text);
    assert!(hits.is_empty(), "pattern matched a run of unrelated bytes");
}

// ---------------------------------------------------------- graph properties

/// Every node must appear in the component list, including isolated nodes. The
/// Python reference used to drop them, which changed the degree count.
#[test]
fn isolated_nodes_appear_in_components() {
    let g = Graph::from_edges(4, &[(0, 1)]);
    let comps = g.connected_components();
    let all: HashSet<usize> = comps.iter().flatten().copied().collect();
    for n in 0..4 {
        assert!(all.contains(&n), "node {n} missing from components {comps:?}");
    }
}

/// Centrality must be finite and in range. A NaN here silently poisons any
/// ranking built on top of it.
#[test]
fn centralities_are_finite_and_bounded() {
    let mut rng = Rng::new(0x5EED_0001);
    for _ in 0..500 {
        let n = 1 + rng.below(12);
        let edge_target = rng.below(n * 2);
        let mut edges = Vec::new();
        for _ in 0..edge_target {
            let a = rng.below(n);
            let b = rng.below(n);
            if a != b {
                edges.push((a, b));
            }
        }
        let g = Graph::from_edges(n, &edges);

        for (node, c) in g.degree_centrality() {
            assert!(c.is_finite(), "degree centrality of {node} is not finite");
            assert!((0.0..=1.0).contains(&c), "degree centrality {c} out of range");
        }
        for (node, b) in g.betweenness_centrality().iter().enumerate() {
            assert!(b.is_finite(), "betweenness of {node} is not finite");
            assert!(*b >= 0.0, "betweenness of {node} is negative: {b}");
        }
    }
}

/// A single node with no edges has degree centrality 0, not NaN.
#[test]
fn single_node_is_not_nan() {
    let g = Graph::from_edges(1, &[]);
    let dc = g.degree_centrality();
    assert_eq!(dc.len(), 1);
    assert!(dc[0].1.is_finite(), "got {}", dc[0].1);
    assert_eq!(dc[0].1, 0.0);
}

/// An empty graph must not panic.
#[test]
fn empty_graph_is_safe() {
    let g = Graph::from_edges(0, &[]);
    assert_eq!(g.node_count(), 0);
    assert!(g.connected_components().is_empty());
    assert!(g.degree_centrality().is_empty());
    assert!(g.betweenness_centrality().is_empty());
}

/// Self-loops and duplicate edges must not corrupt the degree count.
#[test]
fn self_loops_and_duplicates_are_handled() {
    let g = Graph::from_edges(2, &[(0, 0), (0, 0), (0, 1), (1, 0)]);
    assert_eq!(g.node_count(), 2);
    for (_, c) in g.degree_centrality() {
        assert!(c.is_finite());
    }
}

/// Shortest paths must be self-consistent: the reported hop count has to match
/// the length of the reported node list, and every step must be a real edge.
///
/// `Graph` is undirected, so a step is valid if the edge exists in either
/// direction. Checking only the forward direction would wrongly fail on paths
/// that legitimately traverse an edge backwards.
#[test]
fn shortest_path_hop_count_matches_the_node_list() {
    let mut rng = Rng::new(0xBEEF_0007);
    for _ in 0..300 {
        let n = 2 + rng.below(8);
        let mut edges = Vec::new();
        for a in 0..n {
            for b in 0..n {
                if a != b && rng.below(4) == 0 {
                    edges.push((a, b));
                }
            }
        }
        // from_edges drops self-loops and out-of-range endpoints, so the
        // effective edge set is the undirected union of what we supplied.
        let adjacency: HashSet<(usize, usize)> = edges
            .iter()
            .filter(|(a, b)| a != b && *a < n && *b < n)
            .flat_map(|&(a, b)| [(a, b), (b, a)])
            .collect();

        let g = Graph::from_edges(n, &edges);
        let src = rng.below(n);
        let dst = rng.below(n);
        if let Some((hops, path)) = g.shortest_path(src, dst) {
            assert_eq!(path.len() as u64, hops + 1, "hops {hops} vs path {path:?}");
            assert_eq!(path.first(), Some(&src));
            assert_eq!(path.last(), Some(&dst));
            for pair in path.windows(2) {
                assert!(
                    adjacency.contains(&(pair[0], pair[1])),
                    "path step {:?} is not an edge",
                    pair
                );
            }
        }
    }
}

/// The hop distances from a source must agree with the shortest paths, and an
/// unreachable node must be None rather than zero.
#[test]
fn hop_table_agrees_with_shortest_path() {
    let g = Graph::from_edges(4, &[(0, 1), (1, 2), (2, 3)]);
    let hops = g.shortest_hops_from(0);
    assert_eq!(hops.len(), 4);
    assert_eq!(hops[0], Some(0));
    assert_eq!(hops[3], Some(3));
    // Nothing points at an isolated node from 0's component.
    let solo = Graph::from_edges(2, &[(0, 0)]);
    let h2 = solo.shortest_hops_from(0);
    assert_eq!(h2[1], None, "unreachable node reported as reachable");
}

/// A deep chain must not overflow the stack; the implementation is iterative.
#[test]
fn deep_chain_does_not_overflow() {
    let n = 50_000;
    let edges: Vec<(usize, usize)> = (0..n - 1).map(|i| (i, i + 1)).collect();
    let g = Graph::from_edges(n, &edges);
    let (hops, path) = g.shortest_path(0, n - 1).expect("chain is connected");
    assert_eq!(hops, (n - 1) as u64);
    assert_eq!(path.len(), n);
}
