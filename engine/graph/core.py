"""HELIOS-NET :: engine/graph/core.py
المعمارية الرسومية للأصول — «عين الرأي» التي تحوّل الاكتشافات إلى شبكة.

المسؤولية:
  - تحويل الاكتشافات الخام (منافذ/خدمات/نطاقات/مضيفين) إلى رسم بياني:
    عقده = أصول، حوافه = علاقات (خدمة تُشغَّل على مضيف، نطاق فرعي→نطاق).
  - التحليل المركزيّ (Centrality) لترتيب الأصول حسب الأهمية — فيعرف القائد
    مَن يستحق التركيز إذن، لا أن يلمس كل شيء عشوائيًا.
  - البقاء خالصًا من أي تلامس شبكي: يعمل على صحائف البيانات وحدها.

العارض:
  - النمط (patron) خالٍ من المكتبات الخارجية — رسم بياني قائم على قواميس.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque


class AssetGraph:
    """رسم بياني موثّق للأصول والعلاقات."""

    def __init__(self):
        self.nodes: dict[str, dict] = {}      # node_id -> meta
        self.adj: dict[str, set[str]] = defaultdict(set)   # node_id -> neighboring ids
        self._edges: set[tuple[str, str]] = set()

    # -- العقد والحواف ------------------------------------------------------
    def add_node(self, node_id: str, kind: str, **meta) -> str:
        self.nodes[node_id] = {"id": node_id, "kind": kind, **meta}
        return node_id

    def add_edge(self, a: str, b: str, rel: str = "related") -> None:
        # يضمن وجود الطرفين أولًا.
        for n in (a, b):
            self.nodes.setdefault(n, {"id": n, "kind": "asset"})
            self.adj[n]  # يهيّئ المجموعة.
        self.adj[a].add(b)
        self.adj[b].add(a)
        self._edges.add((a, b))

    # -- التغذية من الاكتشافات -------------------------------------------------
    def ingest(self, findings: list[dict]) -> int:
        """يبني الرسم البياني من صحائف الاكتشافات الخام.

        يقرأ أنماطًا معروفة:
          - منفذ/خدمة على مضيف -> عقدة مضيف + عقدة خدمة (حافة).
          - نطاق فرعي -> عقدة نطاق فرعي + حافة إلى عقدة النطاق الأم (إن وُجد).
        أي نمط غير معروف يُتخطى بأمان (لا يوقِف البناء).

        Returns:
          عدد الحواف المضافة.
        """
        added = 0
        for f in findings:
            mid = f.get("module")
            if mid == "discovery" and f.get("host") and f.get("service"):
                host = f"host:{f['host']}"
                svc = f"svc:{f['host']}:{f.get('port', 0)}/{f['service']}"
                self.add_node(host, "host", ip=f["host"])
                self.add_node(svc, "service", port=f.get("port"), name=f["service"])
                self.add_edge(host, svc, "runs")
                added += 1
            elif mid == "dns_enum" and f.get("subdomain"):
                sub = f"sub:{f['subdomain']}"
                self.add_node(sub, "subdomain", fqdn=f["subdomain"])
                # يستهدف إن وجد نطاق أمّ ضمن الاكتشافات (لا حاجة، نبقي بلا).
                added += 1
        return added

    # -- التحليل المركزيّ ------------------------------------------------------
    def degree_centrality(self) -> list[tuple[str, float]]:
        """ترتيب بالأهمية: عدد العلاقات المباشرة (degree) لكل عقدة.

        أبسط معيار وأسرعه: الأصل ذو الرابطات الأكثر غالبًا هو الأهم
        (خدمات متعددة على مضيف واحد، نطاق يستضيف عدة).
        """
        if not self.nodes:
            return []
        n = len(self.nodes)
        ranked = []
        for nid, neighbors in self.adj.items():
            if nid not in self.nodes:
                continue
            score = len(neighbors) / max(1, n - 1)
            ranked.append((nid, round(score, 3)))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def top_targets(self, limit: int = 10) -> list[str]:
        """أهم الأصول المرتّبة — بما يستحق الحملة التركيز عليه."""
        return [nid for nid, _ in self.degree_centrality()[:limit]]

    def connected_components(self) -> list[list[str]]:
        """فصل المجموعات المتصلة: يبين نطاقات أصول مستقلة عن بعضها."""
        if not self.nodes:
            return []
        seen: set[str] = set()
        comps: list[list[str]] = []
        for start in self.nodes:
            if start in seen:
                continue
            # BFS
            comp, q = [], deque([start])
            seen.add(start)
            while q:
                cur = q.popleft()
                comp.append(cur)
                for nb in self.adj[cur]:
                    if nb not in seen and nb in self.nodes:
                        seen.add(nb)
                        q.append(nb)
            comps.append(comp)
        comps.sort(key=len, reverse=True)
        return comps

    # -- تصدير ---------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "adjacency": {k: sorted(v) for k, v in self.adj.items()},
            "edges": sorted(self._edges),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
