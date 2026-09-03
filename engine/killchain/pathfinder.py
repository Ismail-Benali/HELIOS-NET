"""HELIOS-NET :: engine/killchain/pathfinder.py
محرك مسار الهجوم وسلاسل الثغرات (Autonomous Kill-Chain & Pathfinder Engine).

المميزات:
  - تطبيق خوارزمية Dijkstra لاحتساب مسار المقاومة الأدنى (Least Resistance Path).
  - محاكاة سلاسل الثغرات والحركة الجانبية (Lateral Movement & Pivoting).
  - توليد خطة هجوم آلية تفصيلية (Automated Kill-Chain Plan).
"""

from __future__ import annotations

import heapq
from typing import Dict, List, Tuple
from engine.graph.core import AssetGraph


class KillChainEngine:
    """محرك مسارات الاختراق وسلاسل القتل (Kill-Chain)."""

    # أوزان افتراضية لمقاومة الخدمات (كلما قل الوزن، زادت سهولة الاستغلال)
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
        """يحسب أقصر مسار هجوم (Least Resistance Path) باستخدام خوارزمية Dijkstra."""
        if entry_node not in self.graph.nodes or crown_jewel not in self.graph.nodes:
            return [], float("inf")

        # طابور أولوية لـ Dijkstra: (cumulative_cost, current_node, path_history)
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
                
                # حساب تكلفة الانتقال للجار
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
        """يحاكي سلسلة الثغرات والحركة الجانبية خطوة بخطوة بناءً على المسار."""
        chain = []
        for i in range(len(path) - 1):
            src = path[i]
            dst = path[i+1]
            
            src_meta = self.graph.nodes.get(src, {})
            dst_meta = self.graph.nodes.get(dst, {})
            
            action = "Pivot / Lateral Movement"
            tactic = "Access"
            
            if src_meta.get("kind") == "host" and dst_meta.get("kind") == "service":
                svc_name = dst_meta.get("name", "service")
                action = f"Exploit exposed service ({svc_name}) on target"
                tactic = "Initial Access"
            elif dst_meta.get("kind") == "database" or "sql" in str(dst_meta).lower():
                action = "Data Exfiltration & Credential Harvesting"
                tactic = "Collection"

            chain.append({
                "step": i + 1,
                "from": src,
                "to": dst,
                "tactic": tactic,
                "action": action
            })
            
        return chain

    def generate_kill_chain_plan(self, entry_node: str, crown_jewel: str) -> str:
        """يولّد خطة هجوم آلية تفصيلية (Automated Kill-Chain Plan)."""
        path, total_cost = self.find_attack_path(entry_node, crown_jewel)
        if not path:
            return f"[!] لا يمكن العثور على مسار هجوم متاح من '{entry_node}' إلى '{crown_jewel}'."

        chain = self.simulate_chaining(path)

        report = [
            "# HELIOS-NET :: AUTOMATED KILL-CHAIN PLAN",
            f"**Entry Point:** `{entry_node}`",
            f"**Crown Jewel (Target):** `{crown_jewel}`",
            f"**Calculated Risk / Resistance Cost:** `{total_cost}`",
            "",
            "## Tactical Attack Steps (Kill-Chain)",
        ]

        for step in chain:
            report.append(f"### Step {step['step']}: {step['tactic']}")
            report.append(f"- **Route:** `{step['from']}` ➔ `{step['to']}`")
            report.append(f"- **Execution:** {step['action']}")
            report.append("")

        return "\n".join(report)
