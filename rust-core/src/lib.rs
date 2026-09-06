// HELIOS-NET :: rust-core/src/lib.rs
// High-performance Rust Core Module with FFI C-ABI Exports, Dijkstra Pathfinding, TTL Analysis, and Secure Checksums.

use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;
use std::os::raw::{c_char, c_double, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

/// Represents a weighted directed graph for route planning and attack surface traversal.
#[derive(Default, Clone)]
pub struct RustAssetGraph {
    nodes: HashMap<String, HashMap<String, f64>>,
}

impl RustAssetGraph {
    /// Creates a new asset graph.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Adds a directed edge with a given impedance cost between source and target nodes.
    pub fn add_edge(&mut self, from: &str, to: &str, cost: f64) {
        self.nodes
            .entry(from.to_string())
            .or_default()
            .insert(to.to_string(), cost);
        self.nodes.entry(to.to_string()).or_default();
    }

    /// Computes the shortest path and total cost using Dijkstra's algorithm (pure stdlib).
    pub fn shortest_path(&self, start: &str, goal: &str) -> Option<(Vec<String>, f64)> {
        #[derive(Clone, Eq, PartialEq)]
        struct State {
            cost_bits: u64,
            node: String,
        }

        impl Ord for State {
            fn cmp(&self, other: &Self) -> Ordering {
                other.cost_bits.cmp(&self.cost_bits)
            }
        }

        impl PartialOrd for State {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut distances: HashMap<String, f64> = HashMap::new();
        let mut parents: HashMap<String, String> = HashMap::new();
        let mut heap = BinaryHeap::new();

        distances.insert(start.to_string(), 0.0);
        heap.push(State {
            cost_bits: 0.0_f64.to_bits(),
            node: start.to_string(),
        });

        while let Some(State { node, .. }) = heap.pop() {
            let current_cost = *distances.get(&node).unwrap_or(&f64::INFINITY);

            if node == goal {
                let mut path = vec![goal.to_string()];
                let mut curr = goal;
                while let Some(p) = parents.get(curr) {
                    path.push(p.to_string());
                    curr = p;
                }
                path.reverse();
                return Some((path, current_cost));
            }

            if let Some(neighbors) = self.nodes.get(&node) {
                for (neighbor, &weight) in neighbors {
                    let next_cost = current_cost + weight;
                    if next_cost < *distances.get(neighbor).unwrap_or(&f64::INFINITY) {
                        distances.insert(neighbor.clone(), next_cost);
                        parents.insert(neighbor.clone(), node.clone());
                        heap.push(State {
                            cost_bits: next_cost.to_bits(),
                            node: neighbor.clone(),
                        });
                    }
                }
            }
        }

        None
    }
}

/// Evaluates a Time-To-Live (TTL) value and returns the predicted operating system family.
pub fn ttl_family(ttl: i32) -> &'static str {
    match ttl {
        1..=64 => "Linux/Unix (TTL~64)",
        65..=128 => "Windows (TTL~128)",
        129..=255 => "Router/Network Device (TTL~255)",
        _ => "Unknown/Custom",
    }
}

/// Computes a lightweight checksum for state validation.
pub fn compute_checksum(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

// ============================================================================
// FFI C-ABI EXPORTS (Zero-Dependency Python ctypes Bridge)
// ============================================================================

#[no_mangle]
pub extern "C" fn helios_graph_new() -> *mut RustAssetGraph {
    Box::into_raw(Box::new(RustAssetGraph::new()))
}

#[no_mangle]
pub unsafe extern "C" fn helios_graph_free(ptr: *mut RustAssetGraph) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn helios_graph_add_edge(
    ptr: *mut RustAssetGraph,
    from: *const c_char,
    to: *const c_char,
    cost: c_double,
) {
    if ptr.is_null() || from.is_null() || to.is_null() {
        return;
    }
    let graph = &mut *ptr;
    let c_from = CStr::from_ptr(from);
    let c_to = CStr::from_ptr(to);
    if let (Ok(s_from), Ok(s_to)) = (c_from.to_str(), c_to.to_str()) {
        graph.add_edge(s_from, s_to, cost);
    }
}

#[no_mangle]
pub unsafe extern "C" fn helios_graph_shortest_path(
    ptr: *mut RustAssetGraph,
    start: *const c_char,
    goal: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if ptr.is_null() || start.is_null() || goal.is_null() || out_buf.is_null() {
        return -1;
    }
    let graph = &*ptr;
    let c_start = CStr::from_ptr(start);
    let c_goal = CStr::from_ptr(goal);

    let (s_start, s_goal) = match (c_start.to_str(), c_goal.to_str()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return -1,
    };

    if let Some((path, _cost)) = graph.shortest_path(s_start, s_goal) {
        let path_str = path.join(",");
        let bytes = path_str.as_bytes();
        if bytes.len() >= out_len {
            return -2;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
        *out_buf.add(bytes.len()) = 0;
        bytes.len() as c_int
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn helios_ttl_family(ttl: c_int) -> *const c_char {
    let family = ttl_family(ttl);
    CString::new(family).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn helios_compute_checksum(data: *const c_char, len: usize) -> u64 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(data as *const u8, len);
    compute_checksum(slice)
}

pub fn match_signatures(banner: &str, signatures: &[&str]) -> Vec<String> {
    let b_lower = banner.to_lowercase();
    let mut matches = Vec::new();
    for &sig in signatures {
        if b_lower.contains(&sig.to_lowercase()) {
            matches.push(sig.to_string());
        }
    }
    matches
}

#[no_mangle]
pub unsafe extern "C" fn helios_match_signatures(
    banner_ptr: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if banner_ptr.is_null() || out_buf.is_null() {
        return -1;
    }
    let c_banner = CStr::from_ptr(banner_ptr);
    let banner = match c_banner.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let signatures = [
        "openssh", "apache", "nginx", "microsoft-iis",
        "mariadb", "postgres", "redis", "vsftpd", "dropbear",
        "mysql", "postgresql", "rdp", "ssh", "http"
    ];

    let matched = match_signatures(banner, &signatures);
    let joined = matched.join(",");
    let bytes = joined.as_bytes();
    if bytes.len() >= out_len {
        return -2;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, bytes.len());
    *out_buf.add(bytes.len()) = 0;
    bytes.len() as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_families() {
        assert_eq!(ttl_family(64), "Linux/Unix (TTL~64)");
        assert_eq!(ttl_family(128), "Windows (TTL~128)");
        assert_eq!(ttl_family(255), "Router/Network Device (TTL~255)");
    }

    #[test]
    fn test_checksum() {
        let cs = compute_checksum(b"HELIOS-NET");
        assert_ne!(cs, 0);
    }

    #[test]
    fn test_dijkstra_path() {
        let mut graph = RustAssetGraph::new();
        graph.add_edge("A", "B", 1.5);
        graph.add_edge("B", "C", 2.0);
        graph.add_edge("A", "C", 5.0);

        let (path, cost) = graph.shortest_path("A", "C").unwrap();
        assert_eq!(path, vec!["A".to_string(), "B".to_string(), "C".to_string()]);
        assert_eq!(cost, 3.5);
    }
}
