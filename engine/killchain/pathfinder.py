"""HELIOS-NET :: engine/killchain/pathfinder.py
Least-Resistance Path & Planning Engine.

Features:
  - Applies Dijkstra's algorithm to compute the Least Resistance path.
  - Models multi-step engagement routes and pivoting.
  - Generates a structured, automated engagement plan.
"""

from __future__ import annotations

import heapq
from typing import Dict, List, Tuple
from engine.graph.core import AssetGraph


class KillChainEngine:
    """Least-resistance path and engagement-plan engine."""

    # Default resistance weights per service (lower weight = easier reach)
    SERVICE_COSTS = {
        "http": 2.0,
        "https": 2.5,
        "ftp": 3.0,
        "ssh": 5.0,
        "mysql": 4.0,
        "postgresql": 4.0,
        "rdp": 4.5,
        "unknown": 3.0
    }

    def __init__(self, graph: AssetGraph):
        self.graph = graph

    def find_attack_path(self, entry_node: str, crown_jewel: str) -> Tuple[List[str], float]:
        """Computes the shortest path (Least Resistance) using Dijkstra's algorithm."""
        if entry_node not in self.graph.nodes or crown_jewel not in self.graph.nodes:
            return [], float("inf")

        # Dijkstra priority queue: (cumulative_cost, current_node, path_history)
        pq: List[Tuple[float, str, List[str]]] = [(0.0, entry_node, [entry_node])]
        visited: Dict[str, float] = {entry_node: 0.0}

        while pq:
            cost, current, path = heapq.heappop(pq)

            if current == crown_jewel:
                return path, cost

            if cost > visited.get(current, float("inf")):
                continue

            for neighbor in self.graph.adj.get(current, []):
                if neighbor not in self.graph.nodes:
                    continue
                
                # compute transition cost to neighbor
                node_meta = self.graph.nodes[neighbor]
                kind = node_meta.get("kind", "unknown")
                name = node_meta.get("name", "unknown").lower()
                step_cost = self.SERVICE_COSTS.get(name, 2.0) if kind == "service" else 1.0

                new_cost = cost + step_cost

                if new_cost < visited.get(neighbor, float("inf")):
                    visited[neighbor] = new_cost
                    heapq.heappush(pq, (new_cost, neighbor, path + [neighbor]))

        return [], float("inf")

    def simulate_chaining(self, path: List[str]) -> List[dict]:
        """Models a step-by-step engagement route based on the computed path."""
        chain = []
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i+1]
            
            src_meta = self.graph.nodes.get(src, {})
            dst_meta = self.graph.nodes.get(dst, {})
            
            action = "Route to adjacent node"
            tactic = "Discovery"
            
            if src_meta.get("kind") == "host" and dst_meta.get("kind") == "service":
                svc_name = dst_meta.get("name", "service")
                action = f"Reach exposed service ({svc_name}) on target"
                tactic = "Reconnaissance"
            elif dst_meta.get("kind") == "database" or "sql" in str(dst_meta).lower():
                action = "Collect exposed data store output"
                tactic = "Assessment"

            chain.append({
                "step": i + 1,
                "from": src,
                "to": dst,
                "tactic": tactic,
                "action": action
            })
            
        return chain

    def generate_kill_chain_plan(self, entry_node: str, crown_jewel: str) -> str:
        """Generates a structured, automated engagement plan."""
        path, total_cost = self.find_attack_path(entry_node, crown_jewel)
        if not path:
            return f"[!] No reachable path found from '{entry_node}' to '{crown_jewel}'."

        chain = self.simulate_chaining(path)

        report = [
            "# HELIOS-NET :: ENGAGEMENT ROUTE PLAN",
            f"**Entry Point:** `{entry_node}`",
            f"**Priority Asset:** `{crown_jewel}`",
            f"**Calculated Resistance Cost:** `{total_cost}`",
            "",
            "## Route Steps",
        ]

        for step in chain:
            report.append(f"### Step {step['step']}: {step['tactic']}")
            report.append(f"- **Route:** `{step['from']}` -> `{step['to']}`")
            report.append(f"- **Action:** {step['action']}")
            report.append("")

        return "\n".join(report)
