/*!
 * HELIOS-NET :: rust-core
 *
 * Native acceleration core exposed over a C ABI and consumed from Python via
 * ctypes (see `core/rust_bridge.py`).
 *
 * Design rules enforced here:
 *   - No external crates. The Windows App Control policy on this host blocks
 *     crates whose build scripts shell out, so the core is stdlib-only.
 *   - No panics may cross the FFI boundary; a Rust panic in an `extern "C"`
 *     function aborts the whole host process. Every entry point is wrapped in
 *     `catch_unwind`.
 *   - ASCII-only case folding, matching the C core and the Python fallback
 *     byte for byte.
 *   - Nothing returned across the ABI is heap-allocated unless the caller is
 *     required to release it with `helios_free_string`.
 */

pub mod aho;
pub mod graph;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

use aho::AhoCorasick;
use graph::Graph;

/// Version of the exported ABI, bumped on any breaking signature change.
const ABI_VERSION: c_int = 2;

/// Hard cap on an input banner, mirroring the C core's line limit.
const MAX_INPUT_BYTES: usize = 1 << 20; // 1 MiB
/// Hard cap on the number of patterns accepted in one call.
const MAX_PATTERNS: usize = 65_536;
/// Hard cap on graph nodes accepted from the ABI.
///
/// `node_count` arrives as a `c_int` straight off the FFI, and the adjacency
/// table allocates one `Vec` per node. Without a cap, a caller passing
/// `n = 2^31` would ask for ~48 GiB and abort the process rather than return an
/// error. Clamping keeps the call total and bounded.
const MAX_NODES: usize = 1 << 20; // 1,048,576
/// Hard cap on graph edges accepted from the ABI.
///
/// This is a RESOURCE limit, not a memory-safety boundary. A `*const u32`
/// carries no length, so `edge_count` is a value the caller asserts and this
/// library must trust, exactly like the length argument to `memcpy`. If a
/// caller claims more edges than its buffer holds, the resulting slice is out
/// of bounds whatever we do here; clamping to MAX_EDGES only bounds how far.
///
/// The trust boundary is the caller. `core/rust_bridge.py` builds a ctypes
/// array and passes its real length, so the pair is consistent in practice.
/// Clamping still earns its place: a wrong-but-inadvertent count cannot drive a
/// multi-gigabyte allocation or a multi-minute scan.
const MAX_EDGES: usize = 1 << 22; // 4,194,304

/// Cached version string. Returning a pointer into `CString` storage means
/// callers can never leak: there is nothing to free. The previous version of
/// this function allocated a fresh `CString` on every call and the Python side
/// never released it, which leaked once per call.
///
/// The product version is taken from `CARGO_PKG_VERSION` instead of being typed
/// out here. The crate used to advertise "3.0.0" in this string while
/// `Cargo.toml` said "1.0.0", so a consumer that trusted either number could be
/// wrong. Deriving one from the other makes that drift impossible.
static VERSION: OnceLock<CString> = OnceLock::new();

fn version_string() -> &'static CStr {
    VERSION.get_or_init(|| {
        CString::new(format!(
            "HELIOS-NET Rust Core {} (Pure Stdlib: Aho-Corasick + Graph)",
            env!("CARGO_PKG_VERSION")
        ))
        .expect("version string contains no interior NUL")
    })
}

/// Runs `f`, converting a panic into a null pointer instead of aborting.
fn guard<T, F: FnOnce() -> *mut T>(f: F) -> *mut T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Takes ownership of a `CString` and hands the raw pointer to the caller.
fn into_raw(s: CString) -> *mut c_char {
    s.into_raw()
}

/// Builds a `CString`, replacing any interior NUL with `_`.
fn to_cstring(s: &str) -> CString {
    match CString::new(s) {
        Ok(c) => c,
        Err(_) => CString::new(s.replace('\0', "_")).unwrap_or_else(|_| CString::new("").unwrap()),
    }
}

/// Safely reads a NUL-terminated C string as bytes. Returns `None` if null/invalid.
unsafe fn read_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_bytes().into()
}

fn clip(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_INPUT_BYTES)]
}

/// Compiles the newline-separated pattern blob into an automaton.
fn compile(patterns: &[u8]) -> AhoCorasick {
    let mut ac = AhoCorasick::new();
    for raw in patterns.split(|&b| b == b'\n') {
        if ac.len() >= MAX_PATTERNS {
            break;
        }
        if let Ok(line) = std::str::from_utf8(raw) {
            ac.add(line);
        }
    }
    ac.build();
    ac
}

/// Escapes a string for inclusion in a JSON string literal.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------- identity

/// Returns a static, NUL-terminated version string. Never free this.
#[no_mangle]
pub extern "C" fn helios_rust_version() -> *const c_char {
    version_string().as_ptr()
}

/// Returns the exported ABI version number.
#[no_mangle]
pub extern "C" fn helios_abi_version() -> c_int {
    ABI_VERSION
}

/// Runs the built-in self test. Returns 0 on success, non-zero on failure.
///
/// This exists so Python can prove the loaded library is actually functional
/// rather than merely present on disk.
#[no_mangle]
pub extern "C" fn helios_selftest() -> c_int {
    let ac = {
        let mut a = AhoCorasick::new();
        a.add("nginx");
        a.add("openssh");
        a.build();
        a
    };
    if ac.scan(b"Server: NGINX/1.24").len() != 1 {
        return 1;
    }
    let g = Graph::from_edges(3, &[(0, 1), (1, 2)]);
    if g.shortest_path(0, 2).map(|(c, _)| c) != Some(2) {
        return 2;
    }
    0
}

// ---------------------------------------------------------------- matching

/// Returns the matching signature labels, one per line.
///
/// Kept for backward compatibility with the previous release; new callers
/// should prefer `helios_match_json`, which also reports match positions.
/// Free the result with `helios_free_string`.
///
/// # Safety
/// `text` and `patterns` must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn helios_match_signatures(
    text: *const c_char,
    patterns: *const c_char,
) -> *mut c_char {
    guard(|| {
        let (Some(text), Some(patterns)) = (read_bytes(text), read_bytes(patterns)) else {
            return std::ptr::null_mut();
        };
        if text.is_empty() {
            return into_raw(to_cstring(""));
        }
        let ac = compile(clip(patterns));
        let mut joined = String::new();
        for (label, _) in ac.scan(clip(text)) {
            if !joined.is_empty() {
                joined.push('\n');
            }
            joined.push_str(&label);
        }
        into_raw(to_cstring(&joined))
    })
}

/// Returns matches as JSON: `[{"signature":"...","position":N}, ...]`.
///
/// Positions are byte offsets, identical to the C core's contract. Free the
/// result with `helios_free_string`.
///
/// # Safety
/// `text` and `patterns` must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn helios_match_json(
    text: *const c_char,
    patterns: *const c_char,
) -> *mut c_char {
    guard(|| {
        let (Some(text), Some(patterns)) = (read_bytes(text), read_bytes(patterns)) else {
            return std::ptr::null_mut();
        };
        let ac = compile(clip(patterns));
        if text.is_empty() {
            return into_raw(to_cstring("[]"));
        }
        let hits = ac.scan(clip(text));
        let mut json = String::from("[");
        for (i, (label, pos)) in hits.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                "{{\"signature\":\"{}\",\"position\":{}}}",
                json_escape(label),
                pos
            ));
        }
        json.push(']');
        into_raw(to_cstring(&json))
    })
}

/// Returns the FNV-1a 32-bit digest of `text` as a 10-char hex string.
///
/// Matches the C core and Python fallback so the three engines agree. Free with
/// `helios_free_string`.
///
/// # Safety
/// `text` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn helios_fnv1a32(text: *const c_char) -> *mut c_char {
    guard(|| {
        let Some(text) = read_bytes(text) else {
            return std::ptr::null_mut();
        };
        let mut hash: u32 = 0x811c_9dc5;
        for &b in clip(text) {
            hash ^= b as u32;
            hash = hash.wrapping_mul(0x0100_0193);
        }
        into_raw(to_cstring(&format!("0x{hash:08X}")))
    })
}

// ------------------------------------------------------------------- graph

/// Parses `n` and a flat `u32` edge array into a `Graph`.
///
/// `edges` is `edge_count * 2` consecutive `u32` node indices. The buffer is
/// only read, never retained.
///
/// `n` is clamped to MAX_NODES, which is a genuine safety bound: it is a
/// scalar that drives our own allocation, so an oversized value is refused
/// rather than trusted.
///
/// `edge_count` is clamped to MAX_EDGES, which is only a resource bound. A
/// raw pointer carries no length, so a count larger than the caller's buffer
/// is undefined behaviour before clamping is relevant; see MAX_EDGES.
/// Callers must pass the true length of the buffer they supply.
unsafe fn build_graph(n: c_int, edges: *const u32, edge_count: c_int) -> Graph {
    let node_count = if n <= 0 {
        0usize
    } else {
        (n as usize).min(MAX_NODES)
    };
    let mut list: Vec<(usize, usize)> = Vec::new();
    if !edges.is_null() && edge_count > 0 {
        let capped = (edge_count as usize).min(MAX_EDGES);
        let slice = std::slice::from_raw_parts(edges, capped * 2);
        list.reserve(capped);
        for pair in slice.as_chunks::<2>().0 {
            list.push((pair[0] as usize, pair[1] as usize));
        }
    }
    Graph::from_edges(node_count, &list)
}

/// Returns `{"count":N,"components":[[...],[...]]}`. Free with `helios_free_string`.
///
/// # Safety
/// `edges` must point to `edge_count * 2` readable `u32` values, or be null when `edge_count` is 0.
#[no_mangle]
pub unsafe extern "C" fn helios_graph_components(
    n: c_int,
    edges: *const u32,
    edge_count: c_int,
) -> *mut c_char {
    guard(|| {
        let g = build_graph(n, edges, edge_count);
        let comps = g.connected_components();
        let mut json = format!("{{\"count\":{},\"components\":[", comps.len());
        for (i, c) in comps.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push('[');
            for (j, &v) in c.iter().enumerate() {
                if j > 0 {
                    json.push(',');
                }
                json.push_str(&v.to_string());
            }
            json.push(']');
        }
        json.push_str("]}");
        into_raw(to_cstring(&json))
    })
}

/// Returns `{"count":N,"ranking":[{"node":I,"centrality":F}, ...]}`.
/// Free with `helios_free_string`.
///
/// # Safety
/// `edges` must point to `edge_count * 2` readable `u32` values, or be null when `edge_count` is 0.
#[no_mangle]
pub unsafe extern "C" fn helios_graph_centrality(
    n: c_int,
    edges: *const u32,
    edge_count: c_int,
) -> *mut c_char {
    guard(|| {
        let g = build_graph(n, edges, edge_count);
        let ranking = g.degree_centrality();
        let mut json = format!("{{\"count\":{},\"ranking\":[", ranking.len());
        for (i, (node, value)) in ranking.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                "{{\"node\":{},\"centrality\":{:.6}}}",
                node, value
            ));
        }
        json.push_str("]}");
        into_raw(to_cstring(&json))
    })
}

/// Returns `{"count":N,"values":[F, ...]}` (betweenness per node).
/// Free with `helios_free_string`.
///
/// # Safety
/// `edges` must point to `edge_count * 2` readable `u32` values, or be null when `edge_count` is 0.
#[no_mangle]
pub unsafe extern "C" fn helios_graph_betweenness(
    n: c_int,
    edges: *const u32,
    edge_count: c_int,
) -> *mut c_char {
    guard(|| {
        let g = build_graph(n, edges, edge_count);
        let values = g.betweenness_centrality();
        let mut json = format!("{{\"count\":{},\"values\":[", values.len());
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("{v:.6}"));
        }
        json.push_str("]}");
        into_raw(to_cstring(&json))
    })
}

/// Returns `{"hops":N,"path":[...]}`, or `{"error":"unreachable"}`.
/// Free with `helios_free_string`.
///
/// # Safety
/// `edges` must point to `edge_count * 2` readable `u32` values, or be null when `edge_count` is 0.
#[no_mangle]
pub unsafe extern "C" fn helios_graph_shortest_path(
    n: c_int,
    edges: *const u32,
    edge_count: c_int,
    source: u32,
    goal: u32,
) -> *mut c_char {
    guard(|| {
        let g = build_graph(n, edges, edge_count);
        match g.shortest_path(source as usize, goal as usize) {
            Some((hops, path)) => {
                let mut json = format!("{{\"hops\":{},\"path\":[", hops);
                for (i, v) in path.iter().enumerate() {
                    if i > 0 {
                        json.push(',');
                    }
                    json.push_str(&v.to_string());
                }
                json.push_str("]}");
                into_raw(to_cstring(&json))
            }
            None => into_raw(to_cstring("{\"error\":\"unreachable\"}")),
        }
    })
}

// ------------------------------------------------------------------ memory

/// Releases a string returned by this library. Null-safe.
///
/// # Safety
/// `s` must be null, or a pointer previously returned by this library and not
/// yet freed. Freeing the same pointer twice is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn helios_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}
