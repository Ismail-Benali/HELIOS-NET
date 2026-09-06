"""
HELIOS-NET :: core/reporter_html.py
Generates self-contained, professional dark-mode HTML executive briefing reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any


def generate_html_report(briefing_dict: Dict[str, Any], output_path: str | Path) -> Path:
    """Generates a standalone dark-mode HTML executive report from a briefing dictionary."""
    out = Path(output_path)
    
    campaign_id = briefing_dict.get("campaign_id", "N/A")
    target = briefing_dict.get("target", "N/A")
    status = briefing_dict.get("status", "N/A")
    findings_count = briefing_dict.get("findings_count", 0)
    events = briefing_dict.get("events", [])
    top_targets = briefing_dict.get("top_targets", [])

    events_html = "".join(f"<li><code>[{round(e.get('ts', 0), 2)}]</code> <strong>{e.get('event', 'EVENT')}</strong>: <code>{e.get('module', 'core')}</code></li>" for e in events)
    targets_html = "".join(f"<li><code>{t}</code></li>" for t in top_targets) if top_targets else "<li>(No high-centrality assets isolated)</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HELIOS-NET :: Executive Briefing Report</title>
    <style>
        body {{ background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 40px; }}
        .container {{ max-width: 900px; margin: auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; font-size: 24px; }}
        h2 {{ color: #8abeb7; font-size: 18px; margin-top: 25px; border-bottom: 1px solid #21262d; padding-bottom: 5px; }}
        .meta {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; background: #21262d; padding: 15px; border-radius: 6px; margin: 20px 0; }}
        .meta div {{ font-size: 14px; }}
        .meta strong {{ color: #f0f6fc; }}
        ul {{ padding-left: 20px; }}
        li {{ margin-bottom: 8px; font-size: 14px; }}
        code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; color: #79c0ff; font-family: monospace; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #8b949e; border-top: 1px solid #30363d; padding-top: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ HELIOS-NET :: EXECUTIVE BRIEFING REPORT</h1>
        <div class="meta">
            <div><strong>Campaign ID:</strong> <code>{campaign_id}</code></div>
            <div><strong>Target:</strong> <code>{target}</code></div>
            <div><strong>Status:</strong> <span style="color: #3fb950;">{status}</span></div>
            <div><strong>Findings Count:</strong> {findings_count}</div>
        </div>

        <h2>🎯 Priority Assets (Centrality Ranked)</h2>
        <ul>
            {targets_html}
        </ul>

        <h2>⏱️ Campaign Timeline & Events</h2>
        <ul>
            {events_html if events_html else "<li>No timeline events recorded.</li>"}
        </ul>

        <div class="footer">
            Generated autonomously by HELIOS-NET :: Red Teaming & Attack Surface Management Orchestrator
        </div>
    </div>
</body>
</html>
"""
    out.write_text(html_content, encoding="utf-8")
    return out
