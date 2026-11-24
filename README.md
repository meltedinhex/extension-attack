# Extension ATT&CK

A MITRE ATT&CK–style taxonomy of **browser-extension tradecraft**, scoped to the extension execution environment. It mirrors ATT&CK's *tactics-as-columns, techniques-as-cells* model but is built for the browser-extension platform (Chromium, Gecko, WebKit).

**[Explore the interactive matrix](https://meltedinhex.com/extension-attack/)** — select a technique for its details and individual page.

**80 techniques across 10 tactics** — 47 `active` (with cited public examples) and 33 `proposed` (open for community contribution). The build requires at least one example record for each `active` technique; it does not verify that links resolve or substantiate the claims.

The focus is the **taxonomy**: machine-consumable technique entries (`matrix/`), each with a stable `EXT-<TACTIC>-NNN` ID and detection ideas. Active entries include public examples; proposed entries need further evidence. Signatures and runtime detections are planned as separate companion work and are not part of this repository yet.

## Repository layout

```
matrix/
  tactics.yaml              # the 10 tactic columns (ATT&CK names, EXT prefixes)
  techniques/*.yaml         # technique entries, one file per tactic
schema/
  technique.schema.json     # validates each technique entry
  tactics.schema.json       # validates tactics.yaml
tools/build.py              # validate + emit matrix.json, Navigator layer, STIX, heatmap
build/                      # generated (gitignored)
.github/skills/             # domain knowledge skills that ground this project
CONTRIBUTING.md             # how to submit a technique
```

## Tactics

Initial Access · Execution · Persistence · Privilege/Scope Escalation · Defense Evasion · Credential Access · Collection · Command & Control · Exfiltration · Impact

## Build

```bash
python -m pip install -r tools/requirements.txt
python tools/build.py
python -m unittest discover -s tools -p "test_*.py"
```

Outputs to `build/`:
- `matrix.json` — the full corpus (machine-consumable).
- `navigator-layer.json` — experimental Navigator-format overlay (score 2 = active, 1 = proposed). Its `EXT-*` IDs are not in MITRE's dataset; interoperability with a custom data source has not yet been verified.
- `extension-attack-stix.json` — experimental STIX 2.0-style bundle (tactics, techniques, matrix); compatibility with STIX consumers and Navigator has not yet been verified.
- `heatmap/index.html` — an interactive matrix; `heatmap/techniques/<ID>.html` are per-technique pages. GitHub Pages deploys the validated site on pushes to `main`.

The build **validates** every entry against the schema and fails on duplicate IDs or dangling `related` references.

## Status

**v1.1.** 80 techniques span all ten tactics: 47 `active`, 33 `proposed`. See the [CHANGELOG](CHANGELOG.md). Active entries cite public examples; proposed entries need additional validation. Citation accuracy and browser-specific details require ongoing review; see [CONTRIBUTING](CONTRIBUTING.md).

## Scope & safety

This is a **defensive** knowledge base. Entries describe capabilities and detections, not weaponized build steps. Analyze extension packages as malware samples in isolation (see the `extension-forensics` skill).

## License

Dual-licensed by content type (see [LICENSE](LICENSE)):
- **Taxonomy, skills, docs** — CC-BY-4.0.
- **Tooling + schema** (`tools/`, `schema/`) — Apache-2.0.

---

© 2026 [Melted in Hex](https://meltedinhex.com) · built and maintained by [@meltedinhex](https://github.com/meltedinhex). Not affiliated with or endorsed by MITRE.
