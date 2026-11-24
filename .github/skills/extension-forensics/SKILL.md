---
name: extension-forensics
description: 'Guide to acquiring, unpacking, and triaging browser extensions for analysis in the Extension ATT&CK project: on-disk artifact locations per browser (Chrome/Edge/Brave/Opera, Firefox, Safari) and OS (Windows/macOS/Linux), Preferences/Secure Preferences and extension state files, CRX3/XPI package format, signing and extension-ID derivation, update manifests (updates.xml / updates.json), and live inventory via chrome.management or enterprise reporting. Use when explaining how an analyst obtains the package an ExtYARA rule scans, where a host stores installed extensions, how to confirm a force-install, or how to reconstruct an extension incident. Keywords: extension forensics, CRX3, XPI, Secure Preferences, Local Extension Settings, LevelDB, extension ID public key hash, updates.xml, acquisition, triage, unpack CRX.'
argument-hint: '<locate-artifacts | unpack-package | triage-host> [browser/OS or extension id]'
---

# Extension Forensics & Acquisition

Bridges "how do I get the thing" between the matrix (what to look for), ExtYARA (scans an unpacked tree), and detection-rules (runtime telemetry). Covers where extensions live on a host, how packages are structured/signed, and how to acquire them.

## When to Use
- Explain how an analyst obtains the CRX/XPI an ExtYARA rule scans.
- Locate installed-extension artifacts on a live or imaged host.
- Confirm a policy force-install or a non-store install source.
- Reconstruct an extension incident (what was installed, when, from where).

Detail: [on-disk-artifacts](./references/on-disk-artifacts.md) (paths + state files), [package-format-signing](./references/package-format-signing.md) (CRX3/XPI/update manifests/ID derivation).

## Acquisition Paths
| Source | How | Yields |
|--------|-----|--------|
| Live host disk | Copy the extension profile dirs (table in on-disk-artifacts) | Unpacked tree → ExtYARA |
| Store CRX | Download `.crx` (dev dashboard / CRX-pull endpoints) and unzip (skip CRX3 header) | Signed package + key → ID derivation |
| Firefox XPI | XPI is a ZIP; unzip; check `META-INF` Mozilla signature | Unpacked tree + signature |
| Live inventory | `chrome.management.getAll()` / enterprise reporting / `about:extensions` | IDs, versions, permissions, install source |
| Policy state | Registry / `policies.json` / MDM profile | Force-install + update_url evidence |
| Memory / network | Service-worker artifacts, egress logs | Runtime C2/exfil corroboration |

## On-Disk Locations (summary; full table in reference)
- **Chromium (Chrome/Edge/Brave/Opera/Vivaldi)**: unpacked extensions under the profile `Extensions/<id>/<version>/`; install metadata in `Preferences` and tamper-resistant `Secure Preferences` (HMAC-protected); per-extension storage in `Local Extension Settings/<id>/` and `IndexedDB` (LevelDB).
- **Firefox**: XPIs in the profile `extensions/` (`<id>.xpi`); state in `extensions.json`, `addonStartup.json.lz4`; managed installs via `policies.json`.
- **Safari**: inside the containing app bundle + `~/Library/Containers/…` app group; state via `SFSafariExtensionManager` (see `safari-web-extensions`).
- Paths differ by OS (Win `%LOCALAPPDATA%`, macOS `~/Library/Application Support`, Linux `~/.config`) — see reference.

## Triage Workflow
1. **Inventory**: list installed extension IDs + versions + permissions (live `chrome.management`/enterprise report, or parse `Preferences`/`extensions.json`).
2. **Classify install source**: store vs sideload vs policy force-install (check `Secure Preferences` `was_installed_by_default`/`install_source`, policy keys, non-store `update_url`).
3. **Acquire** the unpacked tree (copy profile dir, or pull+unzip CRX/XPI).
4. **Scan** with ExtYARA; map hits to matrix technique IDs.
5. **Corroborate at runtime** with detection-rules telemetry (egress, native-host spawns, DNS).
6. **Derive the extension ID** from the public key to confirm identity / spot forked-clone/ownership-transfer (see package-format-signing).
7. **Timeline**: file mtimes, `Secure Preferences`, update history, policy change times.

## High-signal forensic indicators
- `update_url` host ∉ {clients2.google.com, edge.microsoft.com, addons.mozilla.org} → off-store update channel (EXT-PERS-001).
- Extension present in `Extensions/` but **absent** from CWS/AMO (pulled/unlisted) → removed-but-resident trojan.
- Policy-forced ID with attacker `update_url` (EXT-INITACC-005 / EXT-PERS-003).
- Permission set widened across versions in `Secure Preferences` history (EXT-PRIVESC-001).
- Native-host manifest in a user-writable dir + `NativeMessagingUserLevelHosts` (EXT-PERS-004).

## Safety / integrity
- Treat extension packages as **malware samples**: analyze in an isolated VM, never load unpacked into a real browser profile.
- `Secure Preferences` is HMAC-signed with a per-profile seed; edits by malware may invalidate the MAC — a tamper signal.
- Preserve hashes (SHA-256) of the CRX/XPI and of each file for the `extyara`/matrix evidence trail.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — artifacts become the evidence behind technique detection/response.
- [extyara](../extyara/SKILL.md) — run package signatures against acquired CRX/XPI samples.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — on-disk/runtime artifacts feed telemetry detections.
- [mv3-extension-apis](../mv3-extension-apis/SKILL.md) — interpret manifest keys/permissions found in samples.
- [safari-web-extensions](../safari-web-extensions/SKILL.md) — macOS/Safari-specific artifact locations.
