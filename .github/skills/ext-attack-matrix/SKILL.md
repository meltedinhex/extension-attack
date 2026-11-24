---
name: ext-attack-matrix
description: 'Author and maintain the "Extension ATT&CK" matrix — a MITRE ATT&CK-style taxonomy of browser-extension tradecraft scoped to the extension execution environment. Use when adding or editing techniques, assigning EXT-<TACTIC>-NNN IDs, writing technique entries (description, platforms, APIs, real-world public example, detection ideas, sample ExtYARA rule), validating the YAML/JSON schema, generating the MITRE ATT&CK Navigator layer, rendering the heatmap, or reviewing CONTRIBUTING submissions. Keeps tactics aligned with ATT&CK names (Initial Access, Execution, Persistence, Privilege/Scope Escalation, Defense Evasion, Credential Access, Collection, Command & Control, Exfiltration, Impact). Keywords: extension ATT&CK, technique ID, Navigator layer, taxonomy, EXT-COLL-001.'
argument-hint: '<add-technique | validate | build-navigator | review-pr> [technique name or tactic]'
---

# Extension ATT&CK Matrix

The taxonomy that ties together signatures (ExtYARA) and detections. Tactics-as-columns, techniques-as-cells, scoped to the browser-extension execution environment but reusing ATT&CK tactic names for familiarity and cross-reference.

## When to Use
- Add / edit a technique and assign its `EXT-<TACTIC>-NNN` ID.
- Validate a technique entry against the schema ([schema](./references/schema.md)).
- Generate the ATT&CK Navigator layer JSON or the static heatmap.
- Review a `CONTRIBUTING` submission (new technique PR).

## Tactics & ID Prefixes
Use ATT&CK tactic names; each has a stable ID prefix (see [tactics](./references/tactics.md) for scope + seed techniques).
| Tactic | Prefix |
|--------|--------|
| Initial Access | `EXT-INITACC` |
| Execution | `EXT-EXEC` |
| Persistence | `EXT-PERS` |
| Privilege / Scope Escalation | `EXT-PRIVESC` |
| Defense Evasion | `EXT-DEFEV` |
| Credential Access | `EXT-CRED` |
| Collection | `EXT-COLL` |
| Command & Control | `EXT-C2` |
| Exfiltration | `EXT-EXFIL` |
| Impact | `EXT-IMPACT` |

IDs are zero-padded, sequential, **never reused** (deprecate, don't recycle). Example: `EXT-COLL-001`.

## Technique Entry (required fields)
Every technique carries the three-way linkage **taxonomy ↔ signature ↔ detection**:
```yaml
- id: EXT-COLL-001
  name: Browsing History Capture
  tactic: Collection
  status: active            # active | deprecated | proposed
  description: >
    Extension reads the user's browsing history via the history API and
    transmits it off-device.
  platforms: [chrome, edge, firefox]      # + safari where applicable
  apis: [history.search, history.getVisits]   # from mv3-extension-apis skill
  permissions: [history]
  manifest_fingerprint: ["history"]
  store_policy_violations:               # from extension-store-policies skill
    cws: "Privacy: Limited Use"
    amo: "§6 Data Collection"
    edge: "§1.5 Personal information"
  real_world_examples:                   # PUBLIC references only
    - title: "<vendor> writeup"
      url: "https://..."
  detection_ideas:                       # link to detection-rules (Idea 13)
    - "EDR: extension calls history.search then fetch to non-allowlisted host"
  extyara_rule: EXTYARA-COLL-001         # id of rule in the extyara pack (Idea 9)
  references: [ ... ]
```
Full field spec + enums in [schema](./references/schema.md).

## Authoring Procedure
1. **Classify** the behavior into exactly one primary tactic (sub-behaviors can cross-reference).
2. **Assign** the next free `EXT-<PREFIX>-NNN`.
3. **Ground** it: pull API/permission/fingerprint from the `mv3-extension-apis` skill; pull the violated clause from `extension-store-policies`; add force-install/sideload context from `browser-enterprise-policies` where relevant.
4. **Cite** at least one *public* real-world example (blog, CVE, vendor report). No private/sensitive data.
5. **Link** a sample ExtYARA rule id (`extyara` skill) and ≥1 detection idea (`extension-detection-rules` skill).
6. **Validate** with the schema; keep the YAML the single source of truth.
7. **Build** the Navigator layer + heatmap from the YAML.

## Delivery Artifacts
- `matrix/techniques/*.yaml` (or one `matrix.yaml`) — machine-consumable source of truth.
- `build/navigator-layer.json` — ATT&CK Navigator layer (see [navigator-layer](./references/navigator-layer.md)) so defenders overlay coverage.
- `build/heatmap/` — generated static site/heatmap.
- `CONTRIBUTING.md` — submission template mirroring the technique schema.

## Sequencing (project guidance)
Draft the first release (20–25 techniques across all tactics) before anything else, then expand.

## Review Checklist (PRs)
- [ ] ID unique, correct prefix, sequential, not reused.
- [ ] Exactly one primary tactic; valid enums.
- [ ] API/permission/fingerprint grounded in `mv3-extension-apis`.
- [ ] ≥1 store-policy citation and ≥1 public example (safe, non-operational).
- [ ] Linked ExtYARA rule id + ≥1 detection idea.
- [ ] Schema-valid; Navigator layer rebuilds cleanly.
- [ ] Defensive framing only — no step-by-step weaponization.

## See also
This is the hub skill; every technique draws on the others:
- [mv3-extension-apis](../mv3-extension-apis/SKILL.md) — ground `apis`/`permissions`/`manifest_fingerprint` fields.
- [browser-ecosystem-landscape](../browser-ecosystem-landscape/SKILL.md) — set each technique's `platforms` and `install_vectors`.
- [extension-store-policies](../extension-store-policies/SKILL.md) — supply the required store-policy `references`.
- [extension-threat-intel](../extension-threat-intel/SKILL.md) — source and vet the `real_world_examples`.
- [extyara](../extyara/SKILL.md) — author the linked `extyara_rule`.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — author the linked `detection_ideas`/`detection_rules`.
- [extension-forensics](../extension-forensics/SKILL.md) — map the artifacts behind detection/response.
- [browser-enterprise-policies](../browser-enterprise-policies/SKILL.md) — managed-install and policy-abuse context.
- [safari-web-extensions](../safari-web-extensions/SKILL.md) — re-map techniques to the Safari/WebKit model.
