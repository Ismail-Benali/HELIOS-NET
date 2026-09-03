"""HELIOS-NET :: core/reporter.py
مولّد التقارير الاستخباراتية الشاملة (Executive Briefing).

يستخلص من حالة الحملة وتقارير المنسّق تقريرًا عالي المستوى يوضح:
  - الملخص التنفيذي والحالة.
  - أهم الأصول المستهدفة (Top Targets من الرسم البياني).
  - تفاصيل الاكتشافات والأحداث.
"""

from __future__ import annotations

import json
from .state import CampaignState


def generate_executive_briefing(state: CampaignState, report_data: dict) -> str:
    """يُصدر تقريرًا استخباراتيًا بصيغة Markdown نظيفة."""
    lines = [
        f"# HELIOS-NET :: BRIEFING REPORT",
        f"**Campaign ID:** `{state.campaign_id}`",
        f"**Target:** `{state.target}`",
        f"**Status:** `{state.status.upper()}`",
        f"**Findings Count:** {state.meta.get('findings_count', 0)}",
        f"**Graph Nodes / Edges:** {state.meta.get('graph_nodes', 0)} / {state.meta.get('graph_edges', 0)}",
        "",
        "## Top Priority Targets (Centrality Ranked)",
    ]

    top = state.meta.get("top_targets", [])
    if top:
        for idx, t in enumerate(top, 1):
            lines.append(f"{idx}. `{t}`")
    else:
        lines.append("- (No high-centrality assets isolated)")

    lines.extend([
        "",
        "## Campaign Timeline / Events",
    ])

    timeline = report_data.get("timeline", [])
    for ev in timeline[-10:]:  # آخر 10 أحداث
        lines.append(f"- `[{round(ev.get('ts', 0), 2)}]` **{ev.get('event')}**: `{ev.get('module', 'core')}`")

    return "\n".join(lines)
