# ATT&CK Navigator Layer Export

The matrix renders into a MITRE ATT&CK Navigator layer so defenders can overlay their coverage. Generate from the technique YAML.

## Layer format (v4.5)
```json
{
  "name": "Extension ATT&CK v1.0",
  "versions": { "attack": "15", "navigator": "4.9.1", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Browser-extension tradecraft taxonomy (Extension ATT&CK).",
  "techniques": [
    {
      "techniqueID": "EXT-COLL-001",
      "tactic": "collection",
      "score": 1,
      "comment": "Browsing-history capture via history API",
      "metadata": [
        { "name": "extyara", "value": "EXTYARA-COLL-001" },
        { "name": "platforms", "value": "chrome,edge,firefox" }
      ]
    }
  ],
  "gradient": { "colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 1 },
  "sorting": 0,
  "layout": { "layout": "side" }
}
```

## Mapping rules
- `techniqueID` ← technique `id` (EXT-*). Navigator renders custom IDs even though they aren't official ATT&CK STIX; a custom tactics manifest keeps columns aligned.
- `tactic` ← lowercase ATT&CK tactic shortname: `initial-access`, `execution`, `persistence`, `privilege-escalation` (used for Privilege/Scope Escalation), `defense-evasion`, `credential-access`, `collection`, `command-and-control`, `exfiltration`, `impact`.
- Put ExtYARA rule id and platforms into `metadata` for cross-linkage.
- Coverage overlays: a defender sets `score` per technique they detect; the gradient shows the heatmap.

## Build pipeline (suggested)
1. Load all `matrix/**/*.yaml`.
2. Validate against the schema.
3. Emit `build/matrix.json` (full corpus) and `build/navigator-layer.json` (Navigator subset).
4. Render `build/heatmap/` static site from `matrix.json`.
5. CI: fail on schema errors, duplicate ids, or dangling `extyara_rule` / `detection_ideas` xrefs.

## Custom tactics manifest
Because these are extension-scoped techniques, ship an optional custom tactics JSON so Navigator shows the ten columns with the EXT prefixes; otherwise load as a standalone layer with `domain: enterprise-attack` and rely on tactic shortnames above.
