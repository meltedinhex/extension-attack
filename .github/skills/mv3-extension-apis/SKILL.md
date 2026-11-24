---
name: mv3-extension-apis
description: 'Reference for Manifest V3 (MV3) browser-extension development: manifest keys, permissions/host_permissions, service workers, content scripts, the scripting/declarativeNetRequest (DNR)/offscreen APIs, web_accessible_resources, native messaging, and the cross-browser browser.* namespace. Use when mapping extension capabilities or abuse techniques to concrete MV3/Chromium APIs, documenting how a technique is implemented, writing ExtYARA signatures against manifest/API usage, or explaining which permission a behavior requires. Covers Chrome, Edge, Firefox, Safari differences. Keywords: manifest.json, executeScript, DNR, offscreen document, WASM, cookies.getAll, tabCapture, chrome.scripting, MV3 migration.'
---

# Manifest V3 Extension APIs

## When to Use
- Mapping an Extension ATT&CK technique to the concrete API(s)/manifest keys that enable it.
- Determining which permission/host permission a behavior requires (for detection and scoping).
- Writing or reviewing ExtYARA rules that match on `manifest.json` keys or API call patterns.
- Explaining capability differences between Chrome/Edge (Chromium), Firefox, and Safari.

## Source of Truth
Primary: `developer.chrome.com/docs/extensions` (MV3). Firefox: `developer.mozilla.org/.../WebExtensions`. Cross-check version gates with `minimum_chrome_version` / `strict_min_version`. See [api-capability-map](./references/api-capability-map.md) for the full technique↔API table.

## Platform Model (MV3)
- **`manifest_version: 3`** is the only supported version in Chrome/Edge. Firefox supports MV3 (with an event-page/persistent-background option); Safari supports MV3 via Xcode conversion.
- **Service worker** (`background.service_worker`) replaces persistent background pages — ephemeral, no DOM, terminates when idle. Abuse: re-registration persistence, `chrome.alarms` wake-ups.
- **No remotely hosted code** — all executable JS must ship in the package (CWS/AMO/Edge enforce). Pushes attackers to `eval`-free evasion: remote *config/data* driving packaged logic, WASM, `userScripts`, DNR.
- **`browser.*` namespace** is standardized; Chrome supports `browser.*` from Chrome 148 (previously `chrome.*`). Firefox has always used `browser.*` with promises. Treat `chrome.*` and `browser.*` as equivalent when signature-writing.

## Key Manifest Fields (abuse-relevant)
| Key | Capability it unlocks |
|-----|-----------------------|
| `permissions` | API access: `cookies`, `scripting`, `tabs`, `webRequest`, `declarativeNetRequest`, `nativeMessaging`, `offscreen`, `history`, `downloads`, `desktopCapture`, `tabCapture`, `debugger`, `management`, `proxy`, `storage` |
| `host_permissions` / `optional_host_permissions` | Which origins content scripts & fetch can touch. `<all_urls>` / `*://*/*` = broadest scope. |
| `content_scripts` | Auto-injected JS/CSS with `matches`, `run_at`, `world` (ISOLATED/MAIN), `all_frames` |
| `web_accessible_resources` | Extension files exposed to web pages / other extensions (fingerprinting, bridge) |
| `externally_connectable` | Which sites/extensions can `sendMessage` in (web↔extension C2 bridge) |
| `declarative_net_request` | Static rulesets (`rule_resources`) for block/redirect/modifyHeaders |
| `content_security_policy` | Relaxing CSP for extension pages / sandbox |
| `update_url` | Non-store auto-update channel (self-hosted) |
| `key` | Pins extension ID (forked-clone / impersonation) |
| `nativeMessaging` perm + host manifest | Bridge to a native host binary on disk |

## Execution Surfaces
- **`chrome.scripting.executeScript`** — inject `func`/`files` into a `tabId`; `world: "MAIN"` runs in the page's JS realm (escapes the isolated world → DOM/credential access, prototype hooking). Needs `scripting` + host perms or `activeTab`.
- **`chrome.scripting.registerContentScripts`** — dynamic, `persistAcrossSessions: true` for persistence.
- **`chrome.userScripts`** (MV3) — run arbitrary user-provided scripts; Firefox restricts to user-script-manager extensions by policy.
- **Offscreen documents** (`chrome.offscreen`, Chrome 109+) — hidden DOM doc; reasons incl. `DOM_SCRAPING`, `DOM_PARSER`, `IFRAME_SCRIPTING`, `BLOBS`, `CLIPBOARD`, `USER_MEDIA`, `WEB_RTC`, `WORKERS`. Enables DOM work + evasion off the main thread; one per extension.
- **WASM** — packaged `.wasm` for obfuscated logic (permitted; a packing/evasion vector).

## Network / C2 / Exfil Surfaces
- **`declarativeNetRequest` (DNR)** — declarative `block`/`redirect`/`allow`/`upgradeScheme`/`modifyHeaders`/`allowAllRequests`. Can strip/add headers (incl. remove `cookie`), redirect via `transform`/`regexSubstitution`. Abuse: hide C2 traffic, inject headers, redirect search. Limits: 30k static (guaranteed), 30k dynamic (5k "unsafe"), 5k session, 1000 regex.
- **`fetch` / `sendBeacon`** from service worker or content script → exfil to C2.
- **`chrome.proxy`** — route traffic (residential-proxy node).
- **`chrome.dns` / DoH** — DNS TXT config / DNS exfil patterns.
- **WebSocket** from service worker → persistent C2.

## Collection / Credential Surfaces
- `chrome.cookies.getAll({})` — bulk cookie/session theft (needs `cookies` + host perms).
- Content-script DOM read / form & keystroke listeners on authed pages.
- `chrome.history`, `chrome.tabs` (url/title), `chrome.tabCapture` / `chrome.desktopCapture` (screenshots/screen), `chrome.downloads`.
- `chrome.webRequest` (observe-only in MV3) + headers for token capture.

## Cross-Browser Notes
- Firefox: `browser.*`, event pages allowed, `userScripts` gated to user-script managers, no `offscreen` (uses background DOM), different DNR limits.
- Safari: MV3 subset, stricter native bridge, App-Store-gated distribution.
- Edge: Chromium — same APIs as Chrome; separate store + policies.

## Procedure (mapping a technique)
1. Identify the observable behavior (e.g., "reads all cookies").
2. Look up the API + required `permissions`/`host_permissions` in [api-capability-map](./references/api-capability-map.md).
3. Record the manifest fingerprint (keys/strings a signature can match).
4. Feed the API/manifest fingerprint into the `extyara` and `ext-attack-matrix` skills.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — consumes the API/manifest fingerprint as technique fields.
- [extyara](../extyara/SKILL.md) — turns the manifest fingerprint into package signatures.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — turns the runtime API surface into telemetry detections.
- [browser-ecosystem-landscape](../browser-ecosystem-landscape/SKILL.md) — which engines expose each API.
- [safari-web-extensions](../safari-web-extensions/SKILL.md) — Safari/WebKit API deltas vs. Chromium/Gecko.
