// HELIOS-NET :: rust-core/src/pathfinder.rs
// Production-ready A* Pathfinding Engine with Multi-Factor Risk Scoring and C-Compatible FFI.

use std::collections::{BinaryHeap, HashMap};
use std::cmp::Ordering;
use std::os::raw::{c_char, c_double, c_int};
use std::ffi::{CStr, CString};
use std::ptr;

/// C-Compatible Node Risk Profile for FFI
#[repr(C)]
pub struct NodeRiskProfile {
    pub node_id: *const c_char,
    pub edr_presence_score: c_double,     // 0.0 - 1.0
    pub firewall_level: c_double,         // 0.0 - 1.0
    pub honeypot_probability: c_double,   // 0.0 - 1.0
    pub network_barrier: c_double,        // 0.0 - 1.0
    pub base_distance: c_double,          // Euclidean / topological distance
}

/// C-Compatible Optimal Path result struct for FFI
#[repr(C)]
pub struct OptimalPath {
    pub path_nodes: *mut *mut c_char,     // Array of null-terminated C strings
    pub path_length: c_int,
    pub total_risk_score: c_double,
    pub strategy: *const c_char,          // "stealth" | "speed" | "balanced"
}

#[derive(Clone, Debug)]
pub struct RiskWeights {
    pub edr: f64,
    pub firewall: f64,
    pub honeypot: f64,
    pub barrier: f64,
}

impl RiskWeights {
    pub fn for_strategy(strategy: &str) -> Self {
        match strategy {
            "stealth" => Self { edr: 0.5, firewall: 0.3, honeypot: 0.2, barrier: 0.0 },
            "speed" => Self { edr: 0.2, firewall: 0.1, honeypot: 0.1, barrier: 0.6 },
            _ => Self { edr: 0.25, firewall: 0.25, honeypot: 0.25, barrier: 0.25 }, // balanced
        }
    }
}

pub struct AStarPathfinder {
    nodes: HashMap<String, NodeRiskProfile>,
    edges: HashMap<String, Vec<(String, f64)>>, // adjacency list: from -> [(to, cost)]
}

impl AStarPathfinder {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, profile: NodeRiskProfile, id: String) {
        self.nodes.insert(id, profile);
    }

    pub fn add_edge(&mut self, from: &str, to: &str, weight: f64) {
        self.edges.entry(from.to_string()).or_default().push((to.to_string(), weight));
        self.edges.entry(to.to_string()).or_default();
    }

    pub fn calculate_path(&self, start: &str, target: &str, strategy: &str) -> Option<(Vec<String>, f64)> {
        if !self.nodes.contains_key(start) || !self.nodes.contains_key(target) {
            return None;
        }

        let weights = RiskWeights::for_strategy(strategy);

        #[derive(Clone)]
        struct State {
            f_score_bits: u64,
            g_score: f64,
            node: String,
        }

        impl PartialEq for State {
            fn eq(&self, other: &Self) -> bool {
                self.f_score_bits == other.f_score_bits
            }
        }
        impl Eq for State {}

        impl Ord for State {
            fn cmp(&self, other: &Self) -> Ordering {
                other.f_score_bits.cmp(&self.f_score_bits) // Min-heap via reverse ordering
            }
        }
        impl PartialOrd for State {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut g_scores: HashMap<String, f64> = HashMap::new();
        let mut came_from: HashMap<String, String> = HashMap::new();
        let mut open_set = BinaryHeap::new();

        g_scores.insert(start.to_string(), 0.0);
        
        let start_node = self.nodes.get(start)?;
        let h_start = start_node.base_distance;
        let f_start = h_start;

        open_set.push(State {
            f_score_bits: f_start.to_bits(),
            g_score: 0.0,
            node: start.to_string(),
        });

        while let Some(State { node, .. }) = open_set.pop() {
            if node == target {
                let mut path = vec![target.to_string()];
                let mut curr = target;
                while let Some(p) = came_from.get(curr) {
                    path.push(p.to_string());
                    curr = p;
                }
                path.reverse();
                let final_risk = *g_scores.get(target).unwrap_or(&0.0);
                return Some((path, final_risk));
            }

            let current_g = *g_scores.get(&node).unwrap_or(&f64::INFINITY);

            if let Some(neighbors) = self.edges.get(&node) {
                for (neighbor, edge_cost) in neighbors {
                    let n_profile = match self.nodes.get(neighbor) {
                        Some(p) => p,
                        None => continue,
                    };

                    let risk_penalty = (n_profile.edr_presence_score * weights.edr) +
                                       (n_profile.firewall_level * weights.firewall) +
                                       (n_profile.honeypot_probability * weights.honeypot) +
                                       (n_profile.network_barrier * weights.barrier);

                    let tentative_g = current_g + edge_cost + (risk_penalty * 2.0);

                    if tentative_g < *g_scores.get(neighbor).unwrap_or(&f64::INFINITY) {
                        came_from.insert(neighbor.clone(), node.clone());
                        g_scores.insert(neighbor.clone(), tentative_g);
                        let h = n_profile.base_distance;
                        let f = tentative_g + h;

                        open_set.push(State {
                            f_score_bits: f.to_bits(),
                            g_score: tentative_g,
                            node: neighbor.clone(),
                        });
                    }
                }
            }
        }

        None
    }
}

// ============================================================================
// FFI EXPORTS FOR PYTHON CONTROL PLANE
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn calculate_optimal_path(
    nodes_ptr: *const NodeRiskProfile,
    node_count: c_int,
    start_node: *const c_char,
    target_node: *const c_char,
    strategy: *const c_char,
) -> *mut OptimalPath {
    if nodes_ptr.is_null() || node_count <= 0 || start_node.is_null() || target_node.is_null() || strategy.is_null() {
        eprintln!(r#"{{"status": "error", "code": 400, "message": "Invalid null pointers or zero node count in A* pathfinder", "module": "pathfinder"}}"#);
        return ptr::null_mut();
    }

    let (s_start, s_target, s_strat) = unsafe {
        let c_start = CStr::from_ptr(start_node);
        let c_target = CStr::from_ptr(target_node);
        let c_strat = CStr::from_ptr(strategy);

        let s_start = match c_start.to_str() { Ok(s) => s, Err(_) => return ptr::null_mut() };
        let s_target = match c_target.to_str() { Ok(s) => s, Err(_) => return ptr::null_mut() };
        let s_strat = match c_strat.to_str() { Ok(s) => s, Err(_) => "balanced" };
        (s_start, s_target, s_strat)
    };

    let mut pathfinder = AStarPathfinder::new();
    let profiles = unsafe { std::slice::from_raw_parts(nodes_ptr, node_count as usize) };

    for p in profiles {
        if !p.node_id.is_null() {
            if let Ok(id_str) = unsafe { CStr::from_ptr(p.node_id) }.to_str() {
                pathfinder.add_node(NodeRiskProfile {
                    node_id: p.node_id,
                    edr_presence_score: p.edr_presence_score,
                    firewall_level: p.firewall_level,
                    honeypot_probability: p.honeypot_probability,
                    network_barrier: p.network_barrier,
                    base_distance: p.base_distance,
                }, id_str.to_string());
                
                pathfinder.add_edge(id_str, id_str, 1.0);
            }
        }
    }

    for i in 0..profiles.len() {
        if let Ok(id1) = unsafe { CStr::from_ptr(profiles[i].node_id) }.to_str() {
            for j in (i + 1)..profiles.len() {
                if let Ok(id2) = unsafe { CStr::from_ptr(profiles[j].node_id) }.to_str() {
                    pathfinder.add_edge(id1, id2, 1.0);
                    pathfinder.add_edge(id2, id1, 1.0);
                }
            }
        }
    }

    match pathfinder.calculate_path(s_start, s_target, s_strat) {
        Some((path, total_risk)) => {
            let len = path.len();
            let mut c_nodes: Vec<*mut c_char> = Vec::with_capacity(len);
            for node_name in path {
                if let Ok(c_str) = CString::new(node_name) {
                    c_nodes.push(c_str.into_raw());
                }
            }

            let path_nodes_ptr = c_nodes.as_mut_ptr();
            std::mem::forget(c_nodes);

            let strat_c_str = CString::new(s_strat).unwrap().into_raw();

            let optimal_path = Box::new(OptimalPath {
                path_nodes: path_nodes_ptr,
                path_length: len as c_int,
                total_risk_score: total_risk,
                strategy: strat_c_str,
            });

            Box::into_raw(optimal_path)
        }
        None => {
            eprintln!(r#"{{"status": "error", "code": 404, "message": "No safe path found between start and target nodes", "module": "pathfinder"}}"#);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_path(path_ptr: *mut OptimalPath) {
    if path_ptr.is_null() {
        return;
    }
    unsafe {
        let path = Box::from_raw(path_ptr);
        if !path.path_nodes.is_null() && path.path_length > 0 {
            let slice = std::slice::from_raw_parts_mut(path.path_nodes, path.path_length as usize);
            for &mut ptr in slice {
                if !ptr.is_null() {
                    let _ = CString::from_raw(ptr);
                }
            }
            let _ = Box::from_raw(path.path_nodes);
        }
        if !path.strategy.is_null() {
            let _ = CString::from_raw(path.strategy as *mut c_char);
        }
    }
}
