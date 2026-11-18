"""Offline, single-file interactive report over an exported typed asset graph.

The HTML carries the graph as embedded JSON and renders it with plain
JavaScript: no server, no CDN, no build step. Every value reaches the DOM
through ``textContent``, and the embedded JSON escapes ``<`` so an asset value
containing markup cannot close the script element.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

_STYLE = """
:root{--bg:#201d1d;--surface:#302c2c;--fg:#fdfcfc;--fg2:#c8c6c4;--muted:#9a9898;
--border:#464343;--accent:#007aff;--warn:#ff9f0a;--danger:#ff3b30;--ok:#30d158}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 "Berkeley Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:24px 32px;border-bottom:1px solid var(--border)}
h1{margin:0 0 4px;font-size:20px;font-weight:600}
.sub{color:var(--muted);font-size:12px}
main{padding:24px 32px;max-width:1200px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
gap:12px;margin-bottom:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:4px;
padding:12px 14px}
.card b{display:block;font-size:22px;font-weight:600}
.card span{color:var(--muted);font-size:11px;text-transform:uppercase;
letter-spacing:.06em}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
input,select{background:var(--surface);color:var(--fg);
border:1px solid var(--border);border-radius:6px;padding:7px 10px;
font:inherit;font-size:13px;min-width:180px}
input:focus,select:focus{outline:1px solid var(--accent);border-color:var(--accent)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;
color:var(--fg2);margin:28px 0 10px}
table{width:100%;border-collapse:collapse;background:var(--surface);
border:1px solid var(--border);border-radius:4px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);
vertical-align:top;font-size:12.5px}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:10.5px;
letter-spacing:.06em}
tr:last-child td{border-bottom:0}
tbody tr:hover{background:#383434}
code{color:var(--fg2)}
.empty{color:var(--muted);padding:14px}
.type{color:var(--accent)}
.meta{color:var(--muted);max-width:340px;overflow-wrap:anywhere}
footer{padding:20px 32px;color:var(--muted);font-size:11px;
border-top:1px solid var(--border)}
"""

_SCRIPT = """
"use strict";
const GRAPH = JSON.parse(document.getElementById("graph-data").textContent);
const assets = Array.isArray(GRAPH.assets) ? GRAPH.assets : [];
const relationships = Array.isArray(GRAPH.relationships) ? GRAPH.relationships : [];

function text(value) {
  if (value === null || value === undefined) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}
function cell(row, value, cls) {
  const td = document.createElement("td");
  if (cls) td.className = cls;
  td.textContent = text(value);
  row.appendChild(td);
  return td;
}
function fillSelect(select, values) {
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  }
}
function countBy(rows, key) {
  const counts = new Map();
  for (const row of rows) {
    const value = text(row[key]) || "(none)";
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}
function degreeMap() {
  const degree = new Map();
  for (const edge of relationships) {
    for (const id of [edge.source, edge.target]) {
      degree.set(id, (degree.get(id) || 0) + 1);
    }
  }
  return degree;
}
const degree = degreeMap();
const assetTypes = [...new Set(assets.map(a => text(a.type)).filter(Boolean))].sort();
const edgeTypes = [...new Set(relationships.map(r => text(r.type)).filter(Boolean))].sort();

const assetSearch = document.getElementById("asset-search");
const assetType = document.getElementById("asset-type");
const edgeSearch = document.getElementById("edge-search");
const edgeType = document.getElementById("edge-type");
fillSelect(assetType, assetTypes);
fillSelect(edgeType, edgeTypes);

function renderAssets() {
  const query = assetSearch.value.trim().toLowerCase();
  const type = assetType.value;
  const body = document.getElementById("asset-rows");
  body.replaceChildren();
  let shown = 0;
  for (const asset of assets) {
    const typeValue = text(asset.type);
    const haystack = (text(asset.id) + " " + text(asset.value) + " " +
      text(asset.metadata)).toLowerCase();
    if (type && typeValue !== type) continue;
    if (query && !haystack.includes(query)) continue;
    const row = document.createElement("tr");
    cell(row, asset.id);
    cell(row, typeValue, "type");
    cell(row, asset.value);
    cell(row, degree.get(asset.id) || 0);
    cell(row, (asset.evidence || []).length);
    cell(row, asset.metadata, "meta");
    body.appendChild(row);
    shown += 1;
  }
  document.getElementById("asset-empty").hidden = shown !== 0;
  document.getElementById("asset-count").textContent = String(shown);
}
function renderEdges() {
  const query = edgeSearch.value.trim().toLowerCase();
  const type = edgeType.value;
  const body = document.getElementById("edge-rows");
  body.replaceChildren();
  let shown = 0;
  for (const edge of relationships) {
    const typeValue = text(edge.type);
    const haystack = (text(edge.source) + " " + text(edge.target) + " " +
      text(edge.metadata)).toLowerCase();
    if (type && typeValue !== type) continue;
    if (query && !haystack.includes(query)) continue;
    const row = document.createElement("tr");
    cell(row, edge.source);
    cell(row, typeValue, "type");
    cell(row, edge.target);
    cell(row, (edge.evidence || []).length);
    cell(row, edge.metadata, "meta");
    body.appendChild(row);
    shown += 1;
  }
  document.getElementById("edge-empty").hidden = shown !== 0;
  document.getElementById("edge-count").textContent = String(shown);
}

document.getElementById("asset-count").textContent = String(assets.length);
document.getElementById("edge-count").textContent = String(relationships.length);
document.getElementById("types").textContent = String(assetTypes.length);
document.getElementById("evidence").textContent = String(
  [...assets, ...relationships].reduce(
    (total, row) => total + (row.evidence || []).length, 0
  )
);
assetSearch.addEventListener("input", renderAssets);
assetType.addEventListener("change", renderAssets);
edgeSearch.addEventListener("input", renderEdges);
edgeType.addEventListener("change", renderEdges);
renderAssets();
renderEdges();
"""


def _embedded_json(payload: Any) -> str:
    """JSON safe to place inside a script element."""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return (
        text.replace("<", "\\u003c")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _validate(payload: Any) -> tuple[list[Any], list[Any]]:
    if not isinstance(payload, dict):
        raise ValueError("the graph must be a JSON object")
    assets = payload.get("assets")
    relationships = payload.get("relationships")
    if not isinstance(assets, list) or not isinstance(relationships, list):
        raise ValueError("the graph needs 'assets' and 'relationships' arrays")
    return assets, relationships


def generate_interactive_report(
    payload: dict[str, Any], output_path: str | Path, *, title: str = "HELIOS-NET"
) -> Path:
    """Writes a self-contained, filterable report for a typed asset graph."""
    assets, relationships = _validate(payload)
    safe_title = html.escape(title)
    schema = html.escape(str(payload.get("schema_version", "unknown")))
    destination = Path(output_path)
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{safe_title} - HELIOS-NET</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
<h1>{safe_title}</h1>
<div class="sub">Offline report generated by HELIOS-NET. Every value is rendered
as text; no network requests are made.</div>
</header>
<main>
<section class="stats">
<div class="card"><b>{len(assets)}</b><span>assets</span></div>
<div class="card"><b>{len(relationships)}</b><span>relationships</span></div>
<div class="card"><b id="types">0</b><span>asset types</span></div>
<div class="card"><b id="evidence">0</b><span>evidence records</span></div>
</section>

<h2>Assets <span class="sub">(<span id="asset-count">0</span> shown)</span></h2>
<div class="controls">
<input id="asset-search" type="search" placeholder="search id, value or metadata">
<select id="asset-type"><option value="">all types</option></select>
</div>
<table>
<thead><tr><th>ID</th><th>Type</th><th>Value</th><th>Degree</th>
<th>Evidence</th><th>Metadata</th></tr></thead>
<tbody id="asset-rows"></tbody>
</table>
<p id="asset-empty" class="empty" hidden>No asset matches this filter.</p>

<h2>Relationships <span class="sub">(<span id="edge-count">0</span> shown)</span></h2>
<div class="controls">
<input id="edge-search" type="search" placeholder="search source, target or metadata">
<select id="edge-type"><option value="">all types</option></select>
</div>
<table>
<thead><tr><th>Source</th><th>Type</th><th>Target</th><th>Evidence</th>
<th>Metadata</th></tr></thead>
<tbody id="edge-rows"></tbody>
</table>
<p id="edge-empty" class="empty" hidden>No relationship matches this filter.</p>

<noscript><p class="empty">This report needs JavaScript for filtering. The graph
data is embedded in the page and can be read in the source.</p></noscript>
</main>
<footer>Schema {schema} -
single file, no external assets.</footer>
<script id="graph-data" type="application/json">{_embedded_json(payload)}</script>
<script>{_SCRIPT}</script>
</body>
</html>
"""
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(document, encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot write {destination}: {exc}") from exc
    return destination
