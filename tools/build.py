#!/usr/bin/env python3
"""Extension ATT&CK build pipeline.

Validates the matrix against the JSON schema and emits machine-consumable
artifacts:

  build/matrix.json          - full corpus (tactics + techniques)
  build/navigator-layer.json - MITRE ATT&CK Navigator layer (coverage overlay)
  build/heatmap/index.html   - static matrix / heatmap view

Integrity checks (build fails on any):
  - schema validation of every technique and of tactics.yaml
  - unique technique IDs; ID prefix matches its tactic
  - every extyara_rule resolves to a rule in rules/*.yar
  - every detection_rules id resolves to an id in detections/*.yaml
  - every related/id reference resolves

Usage:
  python tools/build.py            # validate + build
  python tools/build.py --check    # validate only (no artifacts)

Dependencies: PyYAML, jsonschema (see tools/requirements.txt). The script
degrades to structural checks if jsonschema is unavailable.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from copy import deepcopy
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: python -m pip install -r tools/requirements.txt")

try:
    from jsonschema import Draft202012Validator
    HAVE_JSONSCHEMA = True
except Exception:  # ImportError, or native-dep load failure under app-control policies
    HAVE_JSONSCHEMA = False

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "matrix"
SCHEMA = ROOT / "schema"
RULES = ROOT / "rules"
DETECTIONS = ROOT / "detections"
BUILD = ROOT / "build"

PREFIX_BY_TACTIC = {
    "Initial Access": "INITACC",
    "Execution": "EXEC",
    "Persistence": "PERS",
    "Privilege/Scope Escalation": "PRIVESC",
    "Defense Evasion": "DEFEV",
    "Credential Access": "CRED",
    "Collection": "COLL",
    "Command & Control": "C2",
    "Exfiltration": "EXFIL",
    "Impact": "IMPACT",
}
ID_RE = re.compile(r"^EXT-(INITACC|EXEC|PERS|PRIVESC|DEFEV|CRED|COLL|C2|EXFIL|IMPACT)-\d{3}$")


class BuildError(Exception):
    pass


def mini_schema_errors(instance, schema, path=""):
    """Dependency-free subset JSON-Schema checker.

    Supports the keywords our schemas use: type, required, properties,
    additionalProperties(False), enum, pattern, minLength, minItems, items.
    Used when the jsonschema package (or its native deps) is unavailable.
    """
    errs: list[str] = []
    t = schema.get("type")
    type_map = {
        "object": dict, "array": list, "string": str,
        "integer": int, "number": (int, float), "boolean": bool,
    }
    if t and t in type_map and not isinstance(instance, type_map[t]):
        # bool is an int subclass; guard integers
        if not (t in ("integer", "number") and isinstance(instance, bool)):
            errs.append(f"{path or '<root>'}: expected {t}")
            return errs
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: {instance!r} not in enum")
    if "pattern" in schema and isinstance(instance, str):
        if not re.search(schema["pattern"], instance):
            errs.append(f"{path}: {instance!r} does not match pattern")
    if "minLength" in schema and isinstance(instance, str) and len(instance) < schema["minLength"]:
        errs.append(f"{path}: shorter than minLength {schema['minLength']}")
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errs.append(f"{path}: missing required '{req}'")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props and not key.startswith("_"):
                    errs.append(f"{path}: unexpected property '{key}'")
        for key, sub in props.items():
            if key in instance:
                errs += mini_schema_errors(instance[key], sub, f"{path}.{key}" if path else key)
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errs.append(f"{path}: fewer than minItems {schema['minItems']}")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(instance):
                errs += mini_schema_errors(item, item_schema, f"{path}[{i}]")
    return errs


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_tactics() -> list[dict]:
    data = load_yaml(MATRIX / "tactics.yaml")
    return data["tactics"]


def load_techniques() -> list[dict]:
    techs: list[dict] = []
    for path in sorted((MATRIX / "techniques").glob("*.yaml")):
        data = load_yaml(path) or {}
        for t in data.get("techniques", []):
            t["_source"] = path.name
            techs.append(t)
    return techs


def collect_rule_names() -> set[str]:
    names: set[str] = set()
    for path in RULES.glob("*.yar"):
        text = path.read_text(encoding="utf-8")
        names.update(re.findall(r"\brule\s+([A-Za-z0-9_]+)", text))
    return names


def collect_detection_ids() -> set[str]:
    ids: set[str] = set()
    for path in DETECTIONS.glob("*.yaml"):
        data = load_yaml(path) or {}
        for det in data.get("detections", []):
            if "id" in det:
                ids.add(det["id"])
    return ids


def validate(techniques: list[dict], tactics: list[dict]) -> list[str]:
    errors: list[str] = []

    # Schema validation
    tech_schema = json.loads((SCHEMA / "technique.schema.json").read_text(encoding="utf-8"))
    tac_schema = json.loads((SCHEMA / "tactics.schema.json").read_text(encoding="utf-8"))
    tactics_doc = load_yaml(MATRIX / "tactics.yaml")
    if HAVE_JSONSCHEMA:
        tech_v = Draft202012Validator(tech_schema)
        for err in Draft202012Validator(tac_schema).iter_errors(tactics_doc):
            errors.append(f"tactics.yaml: {err.message}")
        for t in techniques:
            payload = {k: v for k, v in t.items() if not k.startswith("_")}
            for err in tech_v.iter_errors(payload):
                errors.append(f"{t.get('id', '?')} ({t['_source']}): {err.message}")
    else:
        errors.append("WARN: jsonschema package unavailable; using built-in schema checker.")
        for e in mini_schema_errors(tactics_doc, tac_schema):
            errors.append(f"tactics.yaml: {e}")
        for t in techniques:
            payload = {k: v for k, v in t.items() if not k.startswith("_")}
            for e in mini_schema_errors(payload, tech_schema):
                errors.append(f"{t.get('id', '?')} ({t['_source']}): {e}")

    # Structural / referential integrity
    ids: set[str] = set()
    for t in techniques:
        tid = t.get("id", "")
        if not ID_RE.match(tid):
            errors.append(f"{tid or '<missing id>'} ({t['_source']}): malformed or missing id")
            continue
        if tid in ids:
            errors.append(f"{tid}: duplicate id")
        ids.add(tid)
        want = PREFIX_BY_TACTIC.get(t.get("tactic"))
        if want and f"-{want}-" not in tid:
            errors.append(f"{tid}: prefix does not match tactic '{t.get('tactic')}' (expected {want})")

    rule_names = collect_rule_names()
    det_ids = collect_detection_ids()
    for t in techniques:
        tid = t.get("id", "?")
        rule = t.get("extyara_rule")
        if rule and rule_names and rule not in rule_names:
            errors.append(f"{tid}: extyara_rule '{rule}' not found in rules/*.yar")
        for d in t.get("detection_rules", []) or []:
            if det_ids and d not in det_ids:
                errors.append(f"{tid}: detection_rules id '{d}' not found in detections/*.yaml")
        for rel in t.get("related", []) or []:
            if rel not in ids:
                errors.append(f"{tid}: related id '{rel}' does not resolve")
        if t.get("status") == "active" and not (t.get("real_world_examples") or []):
            errors.append(f"{tid}: status 'active' requires at least one real_world_examples entry")

    return errors


def build_matrix_json(techniques: list[dict], tactics: list[dict]) -> dict:
    clean = [deepcopy({k: v for k, v in t.items() if not k.startswith("_")}) for t in techniques]
    clean.sort(key=lambda t: t["id"])
    # Make `related` links bidirectional so every technique page shows all of its neighbours.
    by_id = {t["id"]: t for t in clean}
    for t in clean:
        for rel in t.get("related", []) or []:
            other = by_id.get(rel)
            if other is not None and t["id"] not in (other.get("related") or []):
                other.setdefault("related", []).append(t["id"])
    for t in clean:
        if t.get("related"):
            t["related"] = sorted(set(t["related"]))
    return {
        "name": "Extension ATT&CK",
        "version": "1.1",
        "generated": date.today().isoformat(),
        "tactics": tactics,
        "techniques": clean,
        "counts": {
            "techniques": len(clean),
            "by_status": _tally(clean, "status"),
            "by_tactic": _tally(clean, "tactic"),
        },
    }


def build_stix_bundle(techniques: list[dict], tactics: list[dict]) -> dict:
    """Experimental STIX-style export; consumer compatibility is not yet verified."""
    import uuid
    ns = uuid.UUID("7a1f7b0e-3c6e-4f0c-9a55-0e7e7a6a2b10")
    ts = "2026-01-01T00:00:00.000Z"
    sid = lambda kind, key: f"{kind}--{uuid.uuid5(ns, key)}"
    common = {"created": ts, "modified": ts, "spec_version": "2.0"}
    objs: list[dict] = []
    tactic_ids = []
    for ta in sorted(tactics, key=lambda x: x.get("order", 0)):
        tid = sid("x-mitre-tactic", ta["name"])
        tactic_ids.append(tid)
        objs.append({**common, "type": "x-mitre-tactic", "id": tid, "name": ta["name"],
                     "description": ta.get("description", ta["name"]),
                     "x_mitre_shortname": ta["attack_shortname"],
                     "external_references": [{"source_name": "extension-attack",
                                              "external_id": ta["id"]}]})
    for t in sorted(techniques, key=lambda x: x["id"]):
        shortname = next(ta["attack_shortname"] for ta in tactics if ta["name"] == t["tactic"])
        objs.append({**common, "type": "attack-pattern", "id": sid("attack-pattern", t["id"]),
                     "name": t["name"], "description": " ".join(str(t.get("description", "")).split()),
                     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": shortname}],
                     "x_mitre_platforms": t.get("platforms", []),
                     "x_mitre_is_subtechnique": False,
                     "external_references": [{"source_name": "extension-attack", "external_id": t["id"]}]
                     + [{"source_name": e["publisher"] if e.get("publisher") else "source", "url": e["url"],
                         "description": e["title"]} for e in t.get("real_world_examples", []) or []]})
    objs.append({**common, "type": "x-mitre-matrix", "id": sid("x-mitre-matrix", "extension-attack"),
                 "name": "Extension ATT&CK", "description": "Browser-extension tradecraft matrix.",
                 "tactic_refs": tactic_ids,
                 "external_references": [{"source_name": "extension-attack", "external_id": "extension-attack"}]})
    return {"type": "bundle", "id": sid("bundle", "extension-attack-v1"), "spec_version": "2.0", "objects": objs}


def _tally(items: list[dict], key: str) -> dict:
    out: dict[str, int] = {}
    for it in items:
        out[it.get(key, "?")] = out.get(it.get(key, "?"), 0) + 1
    return out


def build_navigator_layer(techniques: list[dict], tactics: list[dict]) -> dict:
    shortname = {t["name"]: t["attack_shortname"] for t in tactics}
    entries = []
    for t in techniques:
        entries.append({
            "techniqueID": t["id"],
            "tactic": shortname.get(t["tactic"], ""),
            "score": 2 if t.get("status") == "active" else 1,
            "comment": t.get("name", ""),
            "enabled": True,
            "metadata": [
                {"name": "status", "value": t.get("status", "")},
                {"name": "platforms", "value": ",".join(t.get("platforms", []))},
            ],
        })
    return {
        "name": "Extension ATT&CK v1.1",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Experimental Extension ATT&CK overlay (score 2 = active, 1 = proposed). "
                       "EXT-* IDs require custom data; Navigator compatibility is not yet verified.",
        "techniques": entries,
        "gradient": {"colors": ["#ffffff", "#d29922", "#3fb950"], "minValue": 0, "maxValue": 2},
        "sorting": 0,
        "layout": {"layout": "side"},
    }


def build_heatmap(matrix: dict) -> str:
    tactics = matrix["tactics"]
    by_tactic: dict[str, list[dict]] = {t["name"]: [] for t in tactics}
    for tech in matrix["techniques"]:
        by_tactic.setdefault(tech["tactic"], []).append(tech)
    cols = []
    for ta in sorted(tactics, key=lambda x: x.get("order", 0)):
        tlist = sorted(by_tactic.get(ta["name"], []), key=lambda x: x["id"])
        cells = "".join(
            f'<div class="cell {t["status"]}" data-id="{t["id"]}" tabindex="0" role="button">'
            f'<span class="tid">{t["id"]}</span>'
            f'{esc_html(t["name"])}</div>'
            for t in tlist
        )
        act = sum(1 for t in tlist if t["status"] == "active")
        cols.append(
            f'<div class="col"><div class="hdr">{esc_html(ta["name"])}'
            f'<span class="cnt" title="active / total">{act}/{len(tlist)}</span></div>{cells}</div>'
        )
    body = "".join(cols)
    counts = matrix["counts"]
    # Embed the full corpus so the page is a self-contained, GitHub-Pages-ready app.
    data_json = json.dumps(matrix, separators=(",", ":")).replace("</", "<\\/")
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Extension ATT&CK v__VERSION__</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font: 13px/1.45 system-ui, sans-serif; margin: 0; background:#0f1115; color:#e6e6e6; }
  a { color:#6ea8fe; }
  header { padding: 16px 20px; border-bottom: 1px solid #222; position:sticky; top:0; background:#0f1115; z-index:5; }
  h1 { margin: 0 0 4px; font-size: 18px; }
  .meta { color:#9aa; font-size:12px; }
  .controls { margin-top:10px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .controls input, .controls select { background:#141821; color:#e6e6e6; border:1px solid #2a2f3a; border-radius:6px; padding:6px 8px; font:inherit; }
  .controls input[type=search] { min-width:240px; }
  .legend { color:#9aa; font-size:12px; margin-left:auto; }
  .legend b { font-weight:600; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:2px; margin:0 3px 0 10px; vertical-align:middle; }
  .dot.active { background:#3fb950; } .dot.proposed { background:#d29922; }
  .board { display:flex; gap:8px; overflow-x:auto; padding:16px; align-items:flex-start; }
  .col { min-width: 210px; flex: 0 0 auto; }
  .hdr { font-weight:600; padding:8px; background:#1a1d24; border:1px solid #2a2f3a; border-radius:6px 6px 0 0; display:flex; justify-content:space-between; position:sticky; top:0; }
  .cnt { color:#9aa; }
  .cell { padding:8px; border:1px solid #2a2f3a; border-top:0; background:#141821; cursor:pointer; }
  .cell:hover, .cell:focus { background:#1b2130; outline:none; }
  .cell .tid { display:block; font-size:11px; color:#89f; }
  .bdg { float:right; margin-left:4px; font-size:9px; font-weight:700; padding:0 4px; border-radius:3px; background:#1f3b57; color:#8cc8ff; }
  .cell.active { border-left:3px solid #3fb950; }
  .cell.proposed { border-left:3px solid #d29922; }
  .cell.deprecated { opacity:.5; border-left:3px solid #6e7681; }
  .cell.hidden { display:none; }
  footer { padding:12px 20px; color:#9aa; border-top:1px solid #222; }
  /* detail drawer */
  .backdrop { position:fixed; inset:0; background:rgba(0,0,0,.55); display:none; z-index:10; }
  .backdrop.open { display:block; }
  .drawer { position:fixed; top:0; right:0; height:100%; width:min(560px,100%); background:#12151c; border-left:1px solid #2a2f3a; transform:translateX(100%); transition:transform .18s ease; z-index:11; overflow:auto; }
  .drawer.open { transform:translateX(0); }
  .drawer .d-head { padding:16px 20px; border-bottom:1px solid #222; position:sticky; top:0; background:#12151c; }
  .drawer .d-body { padding:16px 20px; }
  .pill { display:inline-block; font-size:11px; padding:2px 8px; border-radius:999px; border:1px solid #2a2f3a; margin:0 6px 6px 0; }
  .pill.active { color:#3fb950; border-color:#2e6b39; }
  .pill.proposed { color:#d29922; border-color:#6b5420; }
  .close { float:right; background:none; border:0; color:#9aa; font-size:22px; cursor:pointer; line-height:1; }
  h2 { font-size:16px; margin:0 6px 0 0; display:inline; }
  h3 { font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:#9aa; margin:18px 0 6px; }
  code { background:#1b2130; padding:1px 5px; border-radius:4px; font-size:12px; }
  .kv { margin:2px 0; } .kv b { color:#c8c8c8; }
  .ex { border:1px solid #2a2f3a; border-radius:6px; padding:10px; margin:8px 0; background:#141821; }
  .ex .t { font-weight:600; } .ex .m { color:#9aa; font-size:12px; margin:3px 0; }
  ul { margin:6px 0; padding-left:18px; } li { margin:3px 0; }
</style></head>
<body>
<header>
  <h1>Extension ATT&amp;CK <small>v__VERSION__</small></h1>
  <div class="meta">__COUNT__ techniques &middot; generated __GENERATED__ &middot; status: __BYSTATUS__</div>
  <div class="controls">
    <input id="q" type="search" placeholder="Search id, name, API, source, text…" autocomplete="off">
    <select id="st">
      <option value="">All statuses</option>
      <option value="active">Active only</option>
      <option value="proposed">Proposed only</option>
    </select>
    <span class="legend"><span class="dot active"></span><b>active</b> (verified example)
      <span class="dot proposed"></span><b>proposed</b> &middot; column count = active/total</span>
  </div>
</header>
<div class="board">__BODY__</div>
<footer>Click any technique for its full details, APIs, detections, and verified real-world sources. Generated by tools/build.py.<br>&copy; 2026 <a href="https://meltedinhex.com" target="_blank" rel="noopener">Melted in Hex</a> &middot; Extension ATT&amp;CK is not affiliated with or endorsed by MITRE.</footer>

<div class="backdrop" id="bd"></div>
<aside class="drawer" id="dw" aria-live="polite"></aside>

<script id="data" type="application/json">__DATA__</script>
<script>
const M = JSON.parse(document.getElementById('data').textContent);
const BY = {}; M.techniques.forEach(t => BY[t.id] = t);
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const list = a => (a&&a.length) ? '<ul>'+a.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul>' : '';
const pills = a => (a&&a.length) ? a.map(x=>'<span class="pill">'+esc(x)+'</span>').join('') : '';
const safeUrl = u => /^https?:[/][/]/i.test(u) ? esc(u) : '#';

function render(t){
  let h = '<div class="d-head"><button class="close" aria-label="Close">&times;</button>'
    + '<h2>'+esc(t.name)+'</h2> <span class="pill '+t.status+'">'+t.status+'</span>'
    + '<div class="meta"><code>'+esc(t.id)+'</code> &middot; '+esc(t.tactic)+'</div></div><div class="d-body">';
  h += '<p>'+esc(t.description)+'</p>';
  if(t.platforms) h += '<div class="kv"><b>Platforms:</b> '+pills(t.platforms)+'</div>';
  if(t.apis) h += '<div class="kv"><b>APIs:</b> '+pills(t.apis)+'</div>';
  if(t.permissions) h += '<div class="kv"><b>Permissions:</b> '+pills(t.permissions)+'</div>';
  if(t.manifest_fingerprint) h += '<div class="kv"><b>Manifest fingerprint:</b> '+pills(t.manifest_fingerprint)+'</div>';
  if(t.mitre_attack_xref) h += '<div class="kv"><b>MITRE ATT&CK:</b> '+pills(t.mitre_attack_xref)+'</div>';
  if(t.scope_note) h += '<h3>Scope note</h3><p>'+esc(t.scope_note)+'</p>';
  if(t.real_world_examples && t.real_world_examples.length){
    h += '<h3>Cited real-world examples</h3>';
    t.real_world_examples.forEach(e=>{
      h += '<div class="ex"><div class="t"><a href="'+safeUrl(e.url)+'" target="_blank" rel="noopener">'+esc(e.title)+'</a></div>'
        + '<div class="m">'+esc(e.publisher||'')+(e.date?' &middot; '+esc(e.date):'')+'</div>'
        + (e.attribution?'<div>'+esc(e.attribution)+'</div>':'') + '</div>';
    });
  }
  if(t.detection_ideas) h += '<h3>Detection ideas</h3>'+list(t.detection_ideas);
  if(t.store_policy_violations){
    h += '<h3>Store-policy violations</h3>';
    for(const k in t.store_policy_violations) h += '<div class="kv"><b>'+esc(k.toUpperCase())+':</b> '+esc(t.store_policy_violations[k])+'</div>';
  }
  h += '<p><a href="techniques/'+esc(t.id)+'.html">Permalink page</a></p>';
  if(t.related && t.related.length){
    h += '<h3>Related</h3>'+t.related.map(r=>'<span class="pill" data-rel="'+esc(r)+'" style="cursor:pointer">'+esc(r)+'</span>').join('');
  }
  if(t.references) h += '<h3>References</h3><ul>'+t.references.map(r=>'<li><a href="'+safeUrl(r)+'" target="_blank" rel="noopener">'+esc(r)+'</a></li>').join('')+'</ul>';
  h += '</div>';
  return h;
}
const dw = document.getElementById('dw'), bd = document.getElementById('bd');
function open(id){ const t=BY[id]; if(!t) return; dw.innerHTML=render(t); dw.classList.add('open'); bd.classList.add('open');
  location.hash = id; }
function close(){ dw.classList.remove('open'); bd.classList.remove('open'); if(location.hash) history.replaceState(null,'',location.pathname); }
document.querySelectorAll('.cell').forEach(c=>{
  c.addEventListener('click',()=>open(c.dataset.id));
  c.addEventListener('keydown',e=>{ if(e.key==='Enter'||e.key===' '){e.preventDefault();open(c.dataset.id);} });
});
bd.addEventListener('click', close);
document.addEventListener('keydown', e=>{ if(e.key==='Escape') close(); });
dw.addEventListener('click', e=>{
  if(e.target.classList.contains('close')) close();
  const rel = e.target.getAttribute && e.target.getAttribute('data-rel'); if(rel) open(rel);
});
// filter
const q=document.getElementById('q'), st=document.getElementById('st');
function hay(t){ return (t.id+' '+t.name+' '+(t.description||'')+' '+(t.apis||[]).join(' ')+' '
  +(t.real_world_examples||[]).map(e=>e.title+' '+(e.publisher||'')).join(' ')).toLowerCase(); }
function apply(){ const term=q.value.trim().toLowerCase(), s=st.value;
  document.querySelectorAll('.cell').forEach(c=>{ const t=BY[c.dataset.id];
    const ok=(!term||hay(t).includes(term))     && (!s||t.status===s); c.classList.toggle('hidden',!ok); }); }
q.addEventListener('input',apply); st.addEventListener('change',apply);
// deep-link: open technique from #hash
if(location.hash){ const id=location.hash.slice(1); if(BY[id]) open(id); }
</script>
</body></html>
""".replace("__VERSION__", esc_html(str(matrix["version"]))) \
   .replace("__COUNT__", str(counts["techniques"])) \
   .replace("__GENERATED__", esc_html(str(matrix["generated"]))) \
   .replace("__BYSTATUS__", esc_html(json.dumps(counts["by_status"]))) \
   .replace("__BODY__", body) \
   .replace("__DATA__", data_json)


def esc_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")



def _li(items) -> str:
    return "<ul>" + "".join(f"<li>{esc_html(str(i))}</li>" for i in items) + "</ul>"


def _safe_url(u: str) -> str:
    return esc_html(u) if re.match(r"^https?://", u or "", re.I) else "#"


def build_technique_page(t: dict) -> str:
    h = [f"<h1>{esc_html(t['name'])}</h1>",
         f'<p class="meta"><code>{esc_html(t["id"])}</code> &middot; {esc_html(t["tactic"])} &middot; '
         f'<span class="st {t["status"]}">{esc_html(t["status"])}</span></p>',
         f"<p>{esc_html((t.get('description') or '').strip())}</p>"]
    for label, key in (("Platforms", "platforms"), ("APIs", "apis"), ("Permissions", "permissions"),
                       ("Manifest fingerprint", "manifest_fingerprint"),
                       ("Install vectors", "install_vectors"), ("MITRE ATT&amp;CK cross-reference", "mitre_attack_xref")):
        if t.get(key):
            h.append(f"<h2>{label}</h2><p>" + " ".join(f"<code>{esc_html(str(x))}</code>" for x in t[key]) + "</p>")
    if t.get("scope_note"):
        h.append("<h2>Scope note</h2><p>" + esc_html(t["scope_note"]) + "</p>")
    if t.get("store_policy_violations"):
        h.append("<h2>Store policy</h2><ul>" + "".join(
            f"<li><b>{esc_html(k.upper())}</b>: {esc_html(str(v))}</li>" for k, v in t["store_policy_violations"].items()) + "</ul>")
    if t.get("detection_ideas"):
        h.append("<h2>Detection ideas</h2>" + _li(t["detection_ideas"]))
    if t.get("real_world_examples"):
        h.append("<h2>Real-world examples</h2>")
        for e in t["real_world_examples"]:
            h.append(f'<div class="ex"><a href="{_safe_url(e.get("url"))}" rel="noopener">{esc_html(e.get("title", ""))}</a>'
                     f'<div class="meta">{esc_html(e.get("publisher", ""))} {esc_html(str(e.get("date", "")))}</div>'
                     f'<div>{esc_html(e.get("attribution", ""))}</div></div>')
    if t.get("references"):
        h.append("<h2>References</h2><ul>" + "".join(
            f'<li><a href="{_safe_url(r)}" rel="noopener">{esc_html(r)}</a></li>' if str(r).startswith("http")
            else f"<li>{esc_html(str(r))}</li>" for r in t["references"]) + "</ul>")
    if t.get("related"):
        h.append("<h2>Related</h2><p>" + " ".join(
            f'<a href="{esc_html(r)}.html"><code>{esc_html(r)}</code></a>' for r in t["related"]) + "</p>")
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{esc_html(t['id'])} {esc_html(t['name'])} - Extension ATT&amp;CK</title>"
            "<style>body{font:15px/1.55 system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;"
            "background:#0d1117;color:#e6edf3}a{color:#58a6ff}code{background:#161b22;padding:1px 5px;border-radius:4px}"
            ".meta{color:#8b949e}.st{padding:1px 8px;border-radius:10px;border:1px solid #30363d}"
            ".st.active{color:#3fb950}.st.proposed{color:#d29922}.ex{border-left:3px solid #30363d;padding-left:10px;margin:.8rem 0}"
            "h2{margin-top:1.6rem;font-size:1.05rem;color:#8b949e}</style></head><body>"
            '<p><a href="../index.html">&larr; Matrix</a></p>' + "".join(h) +
            '<hr><p class="meta">&copy; 2026 Melted in Hex &middot; Extension ATT&amp;CK is not affiliated with or endorsed by MITRE.</p>'
            "</body></html>")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Extension ATT&CK matrix.")
    ap.add_argument("--check", action="store_true", help="validate only; do not write artifacts")
    args = ap.parse_args()

    tactics = load_tactics()
    techniques = load_techniques()
    errors = validate(techniques, tactics)

    hard = [e for e in errors if not e.startswith("WARN:")]
    for e in errors:
        print(("warning: " if e.startswith("WARN:") else "error: ") + e, file=sys.stderr)
    if hard:
        print(f"\nFAILED: {len(hard)} error(s), {len(techniques)} techniques checked.", file=sys.stderr)
        return 1

    print(f"OK: {len(techniques)} techniques, {len(tactics)} tactics validated.")
    if args.check:
        return 0

    matrix = build_matrix_json(techniques, tactics)
    BUILD.mkdir(exist_ok=True)
    (BUILD / "matrix.json").write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    (BUILD / "navigator-layer.json").write_text(
        json.dumps(build_navigator_layer(techniques, tactics), indent=2), encoding="utf-8"
    )
    (BUILD / "extension-attack-stix.json").write_text(
        json.dumps(build_stix_bundle(matrix["techniques"], tactics), indent=2), encoding="utf-8"
    )
    heat = BUILD / "heatmap"
    heat.mkdir(exist_ok=True)
    (heat / "index.html").write_text(build_heatmap(matrix), encoding="utf-8")
    pages = heat / "techniques"
    pages.mkdir(exist_ok=True)
    for t in matrix["techniques"]:
        (pages / f"{t['id']}.html").write_text(build_technique_page(t), encoding="utf-8")
    for name in ("matrix.json", "navigator-layer.json", "extension-attack-stix.json"):
        (heat / name).write_bytes((BUILD / name).read_bytes())
    print(f"Techniques: {matrix['counts']['techniques']} ({matrix['counts']['by_status']}).")
    print(f"Wrote {BUILD/'matrix.json'}, {BUILD/'navigator-layer.json'}, "
          f"{BUILD/'extension-attack-stix.json'}, {heat/'index.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
