---
name: extension-detection-rules
description: 'Author runtime/behavioral detections for malicious browser-extension activity that map to Extension ATT&CK technique IDs: EDR/Sysmon telemetry, browser management (chrome.management / enterprise reporting), network egress analytics, policy/registry monitoring for force-install, and native-messaging host detection. Use when writing the detection ideas or detection pack (Idea 13) for a matrix technique, or converting an ExtYARA static signature into runtime coverage. Keywords: Sigma rule, EDR, Sysmon, extension force-install detection, native messaging host, ExtensionInstallForcelist registry, DNS exfil, cookies exfil, service worker C2, detection engineering.'
argument-hint: '<write-detection | review-detection> [technique id or behavior]'
---

# Extension Detection Rules

Runtime/behavioral detections that complete the triad: ExtYARA catches the **package** statically; these catch the **behavior** at runtime. Every detection is tagged to an Extension ATT&CK technique id.

## When to Use
- Write the `detection_ideas` / detection-pack entries (Idea 13) for a matrix technique.
- Convert an ExtYARA static rule into runtime coverage (defense-in-depth).
- Advise on telemetry sources needed to observe a technique.

See [detection-patterns](./references/detection-patterns.md) for per-tactic detections, telemetry sources, and Sigma-style skeletons.

## Telemetry Sources
| Source | What it gives you |
|--------|-------------------|
| **Policy / registry monitoring** | `ExtensionInstallForcelist`, `ExtensionSettings`, `policies.json` changes (force-install, sideload enable) |
| **Browser enterprise reporting** (Chrome Browser Cloud Mgmt / Edge mgmt / `chrome.management`) | Installed-extension inventory, permissions, versions, install source |
| **EDR / Sysmon** | Process creation (native-host binaries), registry writes, file writes to extension/user dirs, DNS queries |
| **Network / proxy / DNS logs** | Egress from browser to non-allowlisted hosts, DNS TXT lookups, WebSocket upgrades, image beacons |
| **Browser extension logs** | DevTools/enterprise extension event logs where available |

## Detection Design Principles
- **Pair install + behavior**: a new force-installed extension *plus* egress to a new host is far higher-signal than either alone.
- **Baseline + drift**: maintain an approved-extension allowlist; alert on inventory drift (new IDs, permission widening on update → EXT-PRIVESC-001).
- **Egress anchoring**: allowlist store/update hosts (`clients2.google.com`, `edge.microsoft.com`, `addons.mozilla.org`); treat other `update_url`/`install_url` as suspicious (EXT-PERS-001).
- **Native-host chain**: browser process → `connectNative` → child process from a user-writable native-host manifest (EXT-PERS-004).
- Keep detections **defensive** and tagged to an EXT id and an ATT&CK xref (`T1176`).

## Detection Entry Format
```yaml
- id: DET-COLL-001
  technique: EXT-COLL-001          # matrix linkage
  title: History read followed by egress to new host
  telemetry: [edr_dns, network_egress, browser_inventory]
  logic: >
    Extension with 'history' permission observed; browser egress to a host
    not seen in prior 30d and not on store/update allowlist within 60s.
  severity: medium
  false_positives: ["sync/telemetry extensions", "new legitimate service"]
  response: ["isolate profile", "review extension id + permissions", "block host"]
  attack_xref: [T1176]
```

## Authoring Procedure
1. Take the matrix technique; read its `apis`/`install_vectors`/`manifest_fingerprint`.
2. Pick the telemetry that actually observes it (install-time vs runtime vs network).
3. Write logic that pairs a capability signal with an action signal to cut FPs.
4. Set `technique` to the EXT id; add `attack_xref`; list realistic false positives + response.
5. Register the detection id in the technique's `detection_ideas`.

## Review Checklist
- [ ] `technique` resolves to a real matrix id; `attack_xref` present.
- [ ] Telemetry source actually captures the behavior.
- [ ] Capability + action paired (FP-aware); false positives listed.
- [ ] Response guidance included; severity justified.
- [ ] Defensive framing only.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — `technique` must resolve to a matrix id.
- [extyara](../extyara/SKILL.md) — static package-signature counterpart to these telemetry detections.
- [mv3-extension-apis](../mv3-extension-apis/SKILL.md) — the runtime API surface each rule observes.
- [browser-enterprise-policies](../browser-enterprise-policies/SKILL.md) — policy/registry signals for install-time rules.
- [extension-forensics](../extension-forensics/SKILL.md) — artifacts behind the response guidance.
