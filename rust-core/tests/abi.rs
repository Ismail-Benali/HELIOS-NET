//! Edge-case tests for the C ABI itself.
//!
//! `properties.rs` exercises the Rust API; this file drives the exported
//! `extern "C"` entry points the way `ctypes` does, because that boundary has
//! its own failure modes that the safe API cannot express: null pointers,
//! negative counts, out-of-range indices, and lengths that disagree with the
//! caller's buffer.
//!
//! Every returning function has an ownership rule the caller must honour, and
//! those rules are the most common source of real defects: a returned string
//! that the caller frees twice, or forgets to free. Each test that receives a
//! pointer frees it exactly once.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use helios_rust_core::{
    helios_abi_version, helios_abi_version as abi_v, helios_fnv1a32, helios_free_string,
    helios_graph_betweenness, helios_graph_centrality, helios_graph_components,
    helios_graph_shortest_path, helios_match_json, helios_match_signatures, helios_rust_version,
    helios_selftest,
};

/// Takes ownership of a returned `*mut c_char`, converts it, and frees it once.
/// Mirrors what `core/rust_bridge.py` does.
unsafe fn take_owned(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    helios_free_string(p);
    Some(s)
}

unsafe fn take_owned_const(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    Some(CStr::from_ptr(p).to_string_lossy().into_owned())
}

fn c(s: &str) -> CString {
    CString::new(s).expect("fixture contains no interior NUL")
}

// ------------------------------------------------------------------ identity

#[test]
fn identity_functions_are_well_formed() {
    assert!(abi_v() > 0);
    assert_eq!(abi_v(), helios_abi_version());

    unsafe {
        let p = helios_rust_version();
        assert!(!p.is_null());
        let first = take_owned_const(p).unwrap();
        // The pointer must be stable: the Python side caches nothing but holds
        // it, and a moving pointer would dangle.
        let second = take_owned_const(helios_rust_version()).unwrap();
        assert_eq!(first, second);
    }
}

/// The offline selftest must report success; build.py treats a non-zero here as
/// a broken core and blocks the native path.
#[test]
fn selftest_reports_success() {
    assert_eq!(helios_selftest(), 0, "helios_selftest reported a failure");
}

// -------------------------------------------------------------- null handling

#[test]
fn null_inputs_return_null_rather_than_dying() {
    unsafe {
        assert!(take_owned(helios_match_signatures(std::ptr::null(), std::ptr::null())).is_none());
        assert!(take_owned(helios_match_json(std::ptr::null(), std::ptr::null())).is_none());
        assert!(take_owned(helios_match_json(std::ptr::null(), c("x").as_ptr())).is_none());
        assert!(take_owned(helios_match_json(c("x").as_ptr(), std::ptr::null())).is_none());
        assert!(take_owned(helios_fnv1a32(std::ptr::null())).is_none());
    }
}

/// Freeing a null pointer must be a documented no-op, not a double free.
#[test]
fn freeing_null_is_a_no_op() {
    unsafe { helios_free_string(std::ptr::null_mut()) };
}

// ---------------------------------------------------------------- empty input

#[test]
fn empty_text_is_distinguishable_from_failure() {
    let empty = c("");
    let patterns = c("alpha");
    unsafe {
        // A successful scan of nothing is an empty result, not an error. The
        // Python bridge relies on this to tell "no match" from "core broken".
        assert_eq!(take_owned(helios_match_signatures(empty.as_ptr(), patterns.as_ptr())).as_deref(),
                   Some(""));
        assert_eq!(take_owned(helios_match_json(empty.as_ptr(), patterns.as_ptr())).as_deref(),
                   Some("[]"));
    }
}

#[test]
fn empty_pattern_set_matches_nothing() {
    let text = c("alpha beta gamma");
    let none = c("");
    unsafe {
        assert_eq!(take_owned(helios_match_json(text.as_ptr(), none.as_ptr())).as_deref(),
                   Some("[]"));
    }
}

// ---------------------------------------------------------- hostile pattern blob

/// The pattern blob is newline-separated text. Non-UTF-8 lines must be skipped
/// rather than aborting the whole scan, and must never produce a match.
#[test]
fn invalid_utf8_pattern_lines_are_skipped_not_fatal() {
    // "alpha\n" then an invalid byte, then "\nbeta". The text contains both
    // valid patterns, so a match for each proves the line AFTER the bad one
    // was still compiled.
    let text = c("alpha beta");
    let mut blob: Vec<u8> = b"alpha\n".to_vec();
    blob.extend_from_slice(&[0xFF, 0xFE]);
    blob.extend_from_slice(b"\nbeta");
    let blob = CString::new(blob).unwrap();

    unsafe {
        let out = take_owned(helios_match_json(text.as_ptr(), blob.as_ptr())).unwrap();
        assert!(out.contains("alpha"), "valid line before junk lost: {out}");
        assert!(out.contains("beta"), "valid line after junk lost: {out}");
        assert!(!out.contains('\u{FFFD}'), "invalid bytes leaked into JSON: {out}");
    }
}

/// A signature label containing a quote or a backslash must be escaped in the
/// JSON output, or the Python `json.loads` on the other end will fail.
#[test]
fn json_output_escapes_quote_and_backslash_in_labels() {
    let nasty = c(r#"evil","injected":"yes"#);
    let text = c(r#"say evil","injected":"yes now"#);
    unsafe {
        let out = take_owned(helios_match_json(text.as_ptr(), nasty.as_ptr())).unwrap();
        // Exactly one object, not two: an unescaped quote would split the JSON.
        assert!(out.starts_with('[') && out.ends_with(']'), "not an array: {out}");
        assert_eq!(out.matches('{').count(), 1, "JSON was split by a raw quote: {out}");
    }
}

/// A pattern longer than the input, and a pattern equal to the input, must both
/// behave without overrunning.
#[test]
fn pattern_longer_than_text_is_safe() {
    let text = c("ab");
    let long = c("abcdefghijklmnopqrstuvwxyz");
    unsafe {
        assert_eq!(take_owned(helios_match_json(text.as_ptr(), long.as_ptr())).as_deref(),
                   Some("[]"));
    }
}

// ------------------------------------------------------------------- hashing

#[test]
fn fnv1a32_matches_the_known_vector() {
    // FNV-1a 32 of the empty string is the offset basis. Confirms the engine
    // still agrees with the C core and the Python fallback.
    let empty = c("");
    unsafe {
        assert_eq!(take_owned(helios_fnv1a32(empty.as_ptr())).as_deref(), Some("0x811C9DC5"));
    }
    let a = c("a");
    unsafe {
        assert_eq!(take_owned(helios_fnv1a32(a.as_ptr())).as_deref(), Some("0xE40C292C"));
    }
}

#[test]
fn fnv1a32_is_case_sensitive() {
    let upper = c("HELLO");
    let lower = c("hello");
    unsafe {
        let u = take_owned(helios_fnv1a32(upper.as_ptr())).unwrap();
        let l = take_owned(helios_fnv1a32(lower.as_ptr())).unwrap();
        assert_ne!(u, l, "hash folded case, so banners could collide");
    }
}

// -------------------------------------------------------------------- graph

#[test]
fn graph_null_and_zero_edges_are_safe() {
    unsafe {
        for p in [
            helios_graph_components(0, std::ptr::null(), 0),
            helios_graph_centrality(0, std::ptr::null(), 0),
            helios_graph_betweenness(0, std::ptr::null(), 0),
            helios_graph_shortest_path(0, std::ptr::null(), 0, 0, 0),
        ] {
            let out = take_owned(p).expect("null/empty graph must still return a result");
            assert!(!out.is_empty());
        }
    }
}

/// A negative node count comes straight off the ABI. It must clamp to an empty
/// graph, not underflow into a huge allocation.
#[test]
fn graph_negative_node_count_is_treated_as_empty() {
    let edges: [u32; 2] = [0, 1];
    unsafe {
        let out = take_owned(helios_graph_components(-1, edges.as_ptr(), 1)).unwrap();
        assert!(out.contains("\"count\":0"), "negative n produced {out}");
    }
}

/// An edge endpoint beyond the declared node count is dropped, not indexed.
#[test]
fn graph_out_of_range_endpoints_are_dropped() {
    // 3 nodes declared, but every edge refers to node 99.
    let edges: [u32; 4] = [99, 98, 98, 99];
    unsafe {
        let comps = take_owned(helios_graph_components(3, edges.as_ptr(), 2)).unwrap();
        // Each of the 3 nodes is its own component once the edges are dropped.
        assert!(comps.contains("\"count\":3"), "out-of-range edges survived: {comps}");

        let c = take_owned(helios_graph_centrality(3, edges.as_ptr(), 2)).unwrap();
        assert!(c.contains("\"centrality\":0.000000"), "stale degree in {c}");
    }
}

/// A source or goal outside the graph must report unreachable, not panic or
/// index past the adjacency table.
#[test]
fn graph_shortest_path_rejects_out_of_range_endpoints() {
    let edges: [u32; 4] = [0, 1, 1, 2];
    unsafe {
        for (src, goal) in [(u32::MAX, 0), (0, u32::MAX), (99, 99)] {
            let out = take_owned(helios_graph_shortest_path(3, edges.as_ptr(), 2, src, goal))
                .unwrap();
            assert!(
                out.contains("unreachable"),
                "source {src} goal {goal} gave {out} instead of unreachable"
            );
        }
    }
}

/// A self-loop must not make a node unreachable from itself.
#[test]
fn graph_self_loop_still_reaches_itself() {
    let edges: [u32; 2] = [1, 1];
    unsafe {
        let out = take_owned(helios_graph_shortest_path(2, edges.as_ptr(), 1, 1, 1)).unwrap();
        assert!(!out.contains("unreachable"), "self-loop broke reachability: {out}");
    }
}

/// A connected chain reports the right hop count and path.
#[test]
fn graph_shortest_path_over_a_chain() {
    let edges: [u32; 6] = [0, 1, 1, 2, 2, 3];
    unsafe {
        let out = take_owned(helios_graph_shortest_path(4, edges.as_ptr(), 3, 0, 3)).unwrap();
        assert!(out.contains("\"hops\":3"), "wrong hop count: {out}");
        assert!(out.contains("\"path\":[0,1,2,3]"), "wrong path: {out}");
    }
}

/// Every graph entry point must emit parseable JSON. A truncated or malformed
/// document would surface as a confusing error in the Python bridge.
#[test]
fn all_graph_output_is_valid_json() {
    let edges: [u32; 4] = [0, 1, 1, 2];
    unsafe {
        let docs = [
            take_owned(helios_graph_components(3, edges.as_ptr(), 2)),
            take_owned(helios_graph_centrality(3, edges.as_ptr(), 2)),
            take_owned(helios_graph_betweenness(3, edges.as_ptr(), 2)),
            take_owned(helios_graph_shortest_path(3, edges.as_ptr(), 2, 0, 2)),
        ];
        for d in docs.into_iter().flatten() {
            let trimmed = d.trim();
            assert!(trimmed.starts_with('{') && trimmed.ends_with('}'),
                    "not a JSON object: {d}");
            assert!(!d.contains("NaN") && !d.contains("inf"),
                    "non-finite number serialised, which is invalid JSON: {d}");
        }
    }
}

/// A large but legal graph must not be clamped away or take absurd time.
#[test]
fn moderately_large_graph_is_handled() {
    let n: usize = 2_000;
    let mut edges: Vec<u32> = Vec::with_capacity(n * 2);
    for i in 0..n - 1 {
        edges.push(i as u32);
        edges.push((i + 1) as u32);
    }
    unsafe {
        let comps = take_owned(helios_graph_components(n as c_int, edges.as_ptr(), n as c_int - 1))
            .unwrap();
        assert!(comps.contains("\"count\":1"), "chain was not one component: {comps}");
    }
}

// ------------------------------------------------------- c_int boundary values

/// A huge `n` with no edges must be clamped, not obeyed. This one is a real
/// safety bound: `n` is a scalar that drives our own adjacency allocation, so
/// without MAX_NODES a caller passing `i32::MAX` would ask for ~48 GiB and abort
/// the process instead of returning.
#[test]
fn absurd_node_count_is_clamped_rather_than_allocated() {
    let out = unsafe { take_owned(helios_graph_components(c_int::MAX, std::ptr::null(), 0)) };
    assert!(out.is_some(), "oversized node count returned nothing");
    // Clamped to MAX_NODES, so every node is its own component; the exact number
    // is an implementation detail but it must be far below 2^31.
    let out = out.unwrap();
    let claimed: usize = out
        .split("\"count\":")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
        .expect("count field missing");
    assert!(
        claimed <= (1 << 20) + 1,
        "node count {claimed} was not clamped"
    );
}

// --------------------------------------------------------- trust boundary note
//
// There is deliberately NO test that passes an edge_count larger than the buffer
// it supplies. A `*const u32` carries no length, so such a call is undefined
// behaviour before any limit this library applies is reached: it segfaults, and
// clamping to MAX_EDGES only changes how far it reads. The invariant that makes
// the ABI usable is that the CALLER passes the true length, and the caller here
// is `core/rust_bridge.py`, which builds a ctypes array of exactly the edges it
// has. That pairing is covered end to end by the Python bridge tests and the
// build.py smoke run, not by a unit test that could only crash.

/// A null edge pointer with a positive count must be treated as no edges, not
/// dereferenced.
#[test]
fn null_edges_with_positive_count_is_safe() {
    unsafe {
        let out = take_owned(helios_graph_components(4, std::ptr::null(), 2)).unwrap();
        assert!(out.contains("\"count\":4"), "null edges produced {out}");
    }
}
