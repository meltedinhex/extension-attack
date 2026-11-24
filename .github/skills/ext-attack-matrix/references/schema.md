# Technique Schema

Canonical schema for Extension ATT&CK technique entries. YAML is the single source of truth; JSON Schema below validates it and the generated `matrix.json`.

## Field spec
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | `EXT-<PREFIX>-NNN`, prefix ∈ tactic set, NNN zero-padded, never reused |
| `name` | string | yes | Human title, Title Case |
| `tactic` | enum | yes | One of the 10 ATT&CK tactic names below |
| `status` | enum | yes | `active` \| `proposed` \| `deprecated` |
| `description` | string | yes | What the technique does; defensive framing, no weaponized steps |
| `platforms` | string[] | yes | subset of `[chrome, edge, firefox, safari]` |
| `apis` | string[] | no | MV3 API/manifest keys (from `mv3-extension-apis`) |
| `permissions` | string[] | no | Required extension permissions |
| `manifest_fingerprint` | string[] | no | Strings a signature can match in `manifest.json`/code |
| `install_vectors` | string[] | no | e.g. `store`, `sideload`, `policy_forcelist`, `dev_mode`, `update_trojan` |
| `store_policy_violations` | object | no | keys `cws`/`amo`/`edge` → clause string (from `extension-store-policies`) |
| `real_world_examples` | object[] | recommended | `{title, url}`; **public** sources only |
| `detection_ideas` | string[] | yes | ≥1; link to `extension-detection-rules` rule ids |
| `extyara_rule` | string | recommended | id of a rule in the ExtYARA pack |
| `related` | string[] | no | other technique ids (cross-tactic links) |
| `mitre_attack_xref` | string[] | no | analogous ATT&CK technique ids (e.g. `T1176` Browser Extensions) |
| `references` | string[] | no | Supporting links |

## Enums
`tactic`: Initial Access, Execution, Persistence, Privilege/Scope Escalation, Defense Evasion, Credential Access, Collection, Command & Control, Exfiltration, Impact.
Prefixes: INITACC, EXEC, PERS, PRIVESC, DEFEV, CRED, COLL, C2, EXFIL, IMPACT.

## JSON Schema (draft 2020-12)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.org/ext-attack/technique.schema.json",
  "type": "object",
  "required": ["id","name","tactic","status","description","platforms","detection_ideas"],
  "properties": {
    "id": { "type": "string", "pattern": "^EXT-(INITACC|EXEC|PERS|PRIVESC|DEFEV|CRED|COLL|C2|EXFIL|IMPACT)-[0-9]{3}$" },
    "name": { "type": "string", "minLength": 3 },
    "tactic": { "enum": ["Initial Access","Execution","Persistence","Privilege/Scope Escalation","Defense Evasion","Credential Access","Collection","Command & Control","Exfiltration","Impact"] },
    "status": { "enum": ["active","proposed","deprecated"] },
    "description": { "type": "string", "minLength": 20 },
    "platforms": { "type": "array", "items": { "enum": ["chrome","edge","firefox","safari"] }, "minItems": 1 },
    "apis": { "type": "array", "items": { "type": "string" } },
    "permissions": { "type": "array", "items": { "type": "string" } },
    "manifest_fingerprint": { "type": "array", "items": { "type": "string" } },
    "install_vectors": { "type": "array", "items": { "enum": ["store","sideload","policy_forcelist","dev_mode","update_trojan","ownership_transfer"] } },
    "store_policy_violations": { "type": "object", "properties": { "cws": {"type":"string"}, "amo": {"type":"string"}, "edge": {"type":"string"} } },
    "real_world_examples": { "type": "array", "items": { "type": "object", "required": ["title","url"], "properties": { "title": {"type":"string"}, "url": {"type":"string","format":"uri"} } } },
    "detection_ideas": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
    "extyara_rule": { "type": "string" },
    "related": { "type": "array", "items": { "type": "string", "pattern": "^EXT-" } },
    "mitre_attack_xref": { "type": "array", "items": { "type": "string" } },
    "references": { "type": "array", "items": { "type": "string" } }
  },
  "additionalProperties": false
}
```

## Validation
- Enforce unique `id` across the corpus; CI fails on duplicates or recycled deprecated ids.
- Lint that every `extyara_rule` id exists in the ExtYARA pack and every `detection_ideas` xref resolves.
