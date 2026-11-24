---
name: extyara
description: 'Author ExtYARA signatures — YARA-style static rules that match browser-extension packages (manifest.json keys, permissions, host_permissions, JS/WASM strings, API call patterns) and link back to Extension ATT&CK technique IDs. Use when writing or reviewing a sample rule for a matrix technique, fingerprinting a malicious CRX/XPI, or building the seed rule pack (Idea 9). Each rule tags its EXT-<TACTIC>-NNN technique and target store/platform. Keywords: YARA rule, CRX, XPI, manifest fingerprint, executeScript, cookies.getAll, declarativeNetRequest, web_accessible_resources, static signature, rule metadata technique id.'
argument-hint: '<write-rule | review-rule> [technique id or behavior]'
---

# ExtYARA — Extension Static Signatures

ExtYARA = YARA-style static rules tuned for browser-extension packages (the unzipped CRX/XPI tree: `manifest.json`, bundled JS/CSS/HTML, `.wasm`, DNR rulesets). Every rule is **tagged to an Extension ATT&CK technique id** so taxonomy ↔ signature ↔ detection stay linked.

## When to Use
- Write the sample ExtYARA rule referenced by a matrix technique (`extyara_rule` field).
- Fingerprint a suspicious CRX/XPI during triage.
- Build / extend the seed rule pack (Idea 9) that ships with the matrix.

See [rule-patterns](./references/rule-patterns.md) for ready-to-adapt rules per tactic and a scanning harness note.

## Package Surface to Match
- `manifest.json`: `manifest_version`, `permissions`, `host_permissions`, `content_scripts`, `web_accessible_resources`, `externally_connectable`, `declarative_net_request`, `update_url`, `chrome_settings_overrides`, `chrome_url_overrides`, `nativeMessaging`, `content_security_policy`.
- JS/HTML: API call strings (`executeScript`, `cookies.getAll`, `connectNative`, `sendBeacon`, `WebSocket`, `captureVisibleTab`), `eval`/`new Function`, obfuscation markers.
- `.wasm`, packed bundles, DNR rule JSON.

## Rule Conventions
- **Rule name**: `EXTYARA_<TACTIC>_NNN_<slug>` (e.g. `EXTYARA_COLL_001_history_exfil`).
- **Required meta**: `technique` (EXT id), `tactic`, `platform`, `confidence` (low/medium/high), `author`, `date`, `description`, `reference`.
- Match on **manifest + behavior together** to cut false positives (a permission alone is often benign).
- Scope by store/platform where the manifest differs (Firefox `browser_specific_settings`, Chrome `key`).
- Keep rules **descriptive/defensive** — they identify capability combinations, not instructions to build malware.

## Template
```yara
rule EXTYARA_COLL_001_history_exfil
{
    meta:
        technique   = "EXT-COLL-001"
        tactic      = "Collection"
        platform    = "chrome,edge,firefox"
        confidence  = "medium"
        author      = "ext-attack"
        date        = "2026-10-13"
        description = "Extension requests history permission and transmits data off-device"
        reference   = "https://github.com/<org>/extension-attack"
    strings:
        $perm_history = "\"history\""
        $api_history  = "history.search"
        $exfil_fetch  = "fetch("
        $exfil_beacon = "sendBeacon("
    condition:
        $perm_history and $api_history and 1 of ($exfil_fetch, $exfil_beacon)
}
```

## Authoring Procedure
1. Start from the matrix technique: read its `apis`, `permissions`, `manifest_fingerprint`.
2. Choose 2–4 strings that co-occur in the technique but rarely together in benign extensions.
3. Write a `condition` requiring the manifest signal AND the behavior signal.
4. Set `meta.technique` to the EXT id; set `confidence` honestly (capability overlap with benign tools).
5. Test against a benign corpus (popular extensions) to measure FPs; tune.
6. Register the rule id back in the technique's `extyara_rule` field.

## Review Checklist
- [ ] `meta.technique` resolves to a real matrix id.
- [ ] Manifest + behavior combined (not a lone permission).
- [ ] Platform scoping correct (CRX vs XPI differences).
- [ ] Tested for FPs on a benign set; `confidence` matches evidence.
- [ ] Defensive framing; no weaponization aid.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — `meta.technique` must resolve to a matrix id.
- [mv3-extension-apis](../mv3-extension-apis/SKILL.md) — source of the manifest/API strings rules match on.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — runtime/telemetry counterpart to these static package rules.
- [extension-forensics](../extension-forensics/SKILL.md) — acquire and hash the CRX/XPI the rules run against.
