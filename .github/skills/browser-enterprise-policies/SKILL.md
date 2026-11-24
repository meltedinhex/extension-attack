---
name: browser-enterprise-policies
description: 'Reference for browser admin/enterprise extension-management policies across Chrome, Chromium, Microsoft Edge, and Firefox: force-install, allowlist/blocklist, install sources, developer-mode controls, native-messaging host controls, and policy storage locations (Windows registry/GPO, Intune OMA-URI, macOS plist, Linux JSON, policies.json). Use when documenting policy force-install as an Initial Access / Persistence technique, explaining how admins deploy or block extensions, how force-installed extensions bypass store consent, or how attackers abuse managed-policy install. Keywords: ExtensionInstallForcelist, ExtensionInstallAllowlist, ExtensionInstallBlocklist, ExtensionSettings, NativeMessagingAllowlist, policies.json, force_installed, update_url, HKLM Software Policies.'
---

# Browser Enterprise Extension Policies

## When to Use
- Documenting **policy force-install** and **sideload/dev-mode** as Extension ATT&CK techniques (Initial Access / Persistence).
- Explaining how force-installed extensions **bypass store install prompts and data-collection consent**, cannot be user-removed, and may gain extra scope silently.
- Writing detections that inspect policy keys (registry/GPO/plist/`policies.json`) for unexpected extension installs.
- Advising defenders on allowlist/blocklist hardening.

## Security Framing (important)
Google explicitly states: using Chrome enterprise policies **outside your own organization** (e.g., bundled with publicly distributed software) is treated as **malware**. Force-install via policy is a legitimate admin capability that is also a documented abuse path (bundled installers writing `ExtensionInstallForcelist`, LOLBin/registry tampering). Treat policy-driven installs as high-signal: managed extensions show a "managed by your organization" banner and skip the store consent UX.

See [policy-reference](./references/policy-reference.md) for exact keys, formats, and storage paths per browser.

## Chrome / Chromium / Edge (same key names)
- **`ExtensionInstallForcelist`** — silently installs + pins extensions the user cannot remove. Value format: `"<extension_id>;<update_url>"` (CWS: `https://clients2.google.com/service/update2/crx`; Edge store has its own URL; self-hosted = attacker-controlled CRX).
- **`ExtensionInstallAllowlist` / `ExtensionInstallBlocklist`** — allow/deny specific IDs; `"*"` in blocklist blocks everything except allowlisted.
- **`ExtensionInstallSources`** — URL patterns from which off-store `.crx` installs are permitted (sideload enabler).
- **`ExtensionSettings`** — full per-ID management dict: `installation_mode` (`force_installed`/`normal_installed`/`blocked`/`allowed`), `update_url`, `install_sources`, `allowed_types`, `runtime_blocked_hosts`, `blocked_install_message`. The most powerful single key.
- **`BlockExternalExtensions`**, **`ExtensionInstallTypeBlocklist`**, **`ExtensionManifestV2Availability`**, **`ExtensionDeveloperModeSettings`** (controls dev-mode/unpacked loading), **`ExtensionUnpublishedAvailability`**.
- **Native messaging**: `NativeMessagingAllowlist`, `NativeMessagingBlocklist`, `NativeMessagingUserLevelHosts`, `NativeHostsExecutablesLaunchDirectly` — govern the native-host bridge (Persistence / Execution).

Storage: Windows registry `HKLM\Software\Policies\Google\Chrome\…` / `…\Microsoft\Edge\…` (GPO ADMX), Intune OMA-URI, macOS managed plist (`com.google.Chrome` / `com.microsoft.Edge`), Linux `/etc/opt/chrome/policies/managed/*.json`.

## Firefox
- **`ExtensionSettings`** (recommended; Chrome-like) per-ID: `installation_mode` (`force_installed`/`normal_installed`/`blocked`/`allowed`), `install_url` (XPI), `install_sources`, `allowed_types`, `blocked_install_message`, `restricted_domains`, `updates_disabled`, `private_browsing`. `"*"` default; `blocked` takes precedence.
- **`Extensions`** — `Install` (XPI URLs/paths), `Uninstall` (IDs), `Locked` (IDs user can't remove).
- **`InstallAddonsPermission`** (`Allow` origins, `Default`), **`ExtensionUpdate`**, **`DisableSystemAddonUpdate`**, **`3rdparty > Extensions`** (feeds `chrome.storage.managed` → remote-config vector).

Storage: `policies.json` under `distribution/` next to the Firefox binary (Windows), `Firefox.app/Contents/Resources/distribution/` (macOS), `/etc/firefox/policies/` (Linux); or GPO `HKLM\Software\Policies\Mozilla\Firefox\…`.

## Abuse → Technique Mapping
| Policy mechanism | Extension ATT&CK angle |
|------------------|------------------------|
| `ExtensionInstallForcelist` / `ExtensionSettings: force_installed` with attacker `update_url` | Initial Access (force-install via policy); Persistence |
| `ExtensionInstallSources` / `ExtensionSettings: install_sources` loosened | Initial Access (sideload) |
| `ExtensionDeveloperModeSettings` enabling unpacked | Initial Access (sideload/dev-mode) |
| Self-hosted `update_url` outside store | Persistence (auto-update channel) |
| `NativeMessaging*` allowing a host | Persistence / Execution (native-messaging host) |
| `3rdparty > Extensions` managed storage | Command & Control (remote config via managed policy) |

## Detection Ideas (link to detection-rules skill)
- Alert on new/changed values under the extension-policy registry keys / `policies.json` with non-store `update_url`.
- Flag `installation_mode: force_installed` whose `update_url` host ∉ {clients2.google.com, edge.microsoft.com, addons.mozilla.org}.
- Inventory managed extensions vs. an approved allowlist (drift detection).
- Watch `NativeMessagingUserLevelHosts=1` + new native-host manifests in user-writable paths.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — policy abuse maps to persistence/privilege techniques.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — convert the policy-key signals above into detections.
- [extension-forensics](../extension-forensics/SKILL.md) — where managed-policy and native-host artifacts live on disk.
- [browser-ecosystem-landscape](../browser-ecosystem-landscape/SKILL.md) — per-engine policy stores and cross-store controls.
