# HELIOS-NET :: engine/pathfinder.py
# Python ctypes wrapper for Rust A* Pathfinder FFI library.

import ctypes
import os
import sys
from typing import Dict, List, Optional, Tuple

class NodeRiskProfile(ctypes.Structure):
    _fields_ = [
        ("node_id", ctypes.c_char_p),
        ("edr_presence_score", ctypes.c_double),
        ("firewall_level", ctypes.c_double),
        ("honeypot_probability", ctypes.c_double),
        ("network_barrier", ctypes.c_double),
        ("base_distance", ctypes.c_double),
    ]

class OptimalPathC(ctypes.Structure):
    _fields_ = [
        ("path_nodes", ctypes.POINTER(ctypes.c_char_p)),
        ("path_length", ctypes.c_int),
        ("total_risk_score", ctypes.c_double),
        ("strategy", ctypes.c_char_p),
    ]

class PathfinderEngine:
    def __init__(self, lib_path: Optional[str] = None):
        if not lib_path:
            # Determine dynamic library extension based on platform
            if sys.platform == "win32":
                lib_name = "helios_core.dll"
            elif sys.platform == "darwin":
                lib_name = "libhelios_core.dylib"
            else:
                lib_name = "libhelios_core.so"
            
            # Search paths
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "rust-core", "target", "release", lib_name),
                os.path.join(os.path.dirname(__file__), "..", "rust-core", "target", "debug", lib_name),
                lib_name
            ]
            for p in possible_paths:
                if os.path.exists(p):
                    lib_path = p
                    break
            if not lib_path:
                lib_path = lib_name

        try:
            self.lib = ctypes.CDLL(lib_path)
        except OSError as e:
            raise RuntimeError(f"[pathfinder] Failed to load Rust core library from '{lib_path}': {e}")

        # Bind calculate_optimal_path
        self.lib.calculate_optimal_path.argtypes = [
            ctypes.POINTER(NodeRiskProfile),
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self.lib.calculate_optimal_path.restype = ctypes.POINTER(OptimalPathC)

        # Bind free_path
        self.lib.free_path.argtypes = [ctypes.POINTER(OptimalPathC)]
        self.lib.free_path.restype = None

    def find_safest_path(self, nodes: List[Dict], start: str, target: str, strategy: str = "balanced") -> Tuple[List[str], float]:
        """Calculates the optimal safest path through network nodes using Rust A*."""
        c_nodes = (NodeRiskProfile * len(nodes))()
        
        # Keep references alive for C strings
        encoded_ids = []
        for i, node in enumerate(nodes):
            nid = node["node_id"].encode('utf-8')
            encoded_ids.append(nid)
            c_nodes[i] = NodeRiskProfile(
                node_id=nid,
                edr_presence_score=float(node.get("edr_presence_score", 0.0)),
                firewall_level=float(node.get("firewall_level", 0.0)),
                honeypot_probability=float(node.get("honeypot_probability", 0.0)),
                network_barrier=float(node.get("network_barrier", 0.0)),
                base_distance=float(node.get("base_distance", 1.0)),
            )

        start_bytes = start.encode('utf-8')
        target_bytes = target.encode('utf-8')
        strat_bytes = strategy.encode('utf-8')

        result_ptr = self.lib.calculate_optimal_path(
            c_nodes,
            len(nodes),
            start_bytes,
            target_bytes,
            strat_bytes
        )

        if not result_ptr:
            return [], float('inf')

        res = result_ptr.contents
        path = [res.path_nodes[i].decode('utf-8') for i in range(res.path_length)]
        risk_score = res.total_risk_score

        # Cleanup memory allocated by Rust
        self.lib.free_path(result_ptr)

        return path, risk_score

if __name__ == "__main__":
    # Smoke test example
    sample_nodes = [
        {"node_id": "NodeA", "edr_presence_score": 0.1, "firewall_level": 0.2, "base_distance": 5.0},
        {"node_id": "NodeB", "edr_presence_score": 0.8, "firewall_level": 0.9, "base_distance": 2.0},
        {"node_id": "NodeC", "edr_presence_score": 0.2, "firewall_level": 0.1, "base_distance": 3.0},
    ]
    try:
        pf = PathfinderEngine()
        path, risk = pf.find_safest_path(sample_nodes, "NodeA", "NodeC", strategy="stealth")
        print(f"[+] Optimal Safe Path: {path} with Risk Score: {risk}")
    except Exception as e:
        print(f"[-] Pathfinder test note: {e}")
