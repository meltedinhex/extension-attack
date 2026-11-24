# MV3 API ↔ Capability ↔ Technique Map

Machine-friendly table linking observable extension behaviors to the concrete MV3 API, the manifest permissions/keys required, the signature fingerprint, and the draft Extension ATT&CK tactic. Keep IDs in sync with the `ext-attack-matrix` skill.

| Behavior | API / manifest | Required perms | Fingerprint strings | Draft tactic |
|----------|----------------|----------------|---------------------|--------------|
| Inject JS into pages | `scripting.executeScript`, `content_scripts` | `scripting` + host, or `activeTab` | `executeScript`, `"world":"MAIN"`, `registerContentScripts` | Execution |
| Run code in page realm | `executeScript({world:"MAIN"})` | `scripting` + host | `"MAIN"`, `func:` | Execution / Defense Evasion |
| Arbitrary user scripts | `userScripts` | `userScripts` | `userScripts.register`, `configureWorld` | Execution |
| Hidden DOM work | `offscreen.createDocument` | `offscreen` | `offscreen`, `DOM_SCRAPING`, `IFRAME_SCRIPTING` | Execution / Collection |
| Packed logic | bundled `.wasm` | — | `.wasm`, `WebAssembly.instantiate` | Defense Evasion |
| Block/redirect/modify traffic | `declarativeNetRequest` | `declarativeNetRequest[WithHostAccess]` | `declarative_net_request`, `modifyHeaders`, `regexSubstitution` | Defense Evasion / C2 |
| Observe requests | `webRequest` (non-blocking MV3) | `webRequest` + host | `onBeforeSendHeaders`, `onCompleted` | Credential Access |
| Bulk cookie theft | `cookies.getAll` | `cookies` + host | `cookies.getAll`, `getAll({})` | Credential Access |
| DOM/form/keystroke capture | content script listeners | host perms | `addEventListener("keydown"`, `input`, `form` | Credential Access / Collection |
| Browsing history | `history.search` | `history` | `history.search`, `history.getVisits` | Collection |
| Tab/screen capture | `tabCapture`, `desktopCapture`, `tabs.captureVisibleTab` | `tabCapture`/`desktopCapture`/`<all_urls>` | `captureVisibleTab`, `getDisplayMedia` | Collection |
| Exfil over HTTP | `fetch`, `sendBeacon` | host perms / CSP `connect-src` | `sendBeacon(`, `fetch(` to non-ext origin | Exfiltration |
| Proxy / relay node | `proxy` | `proxy` | `proxy.settings.set`, `pacScript` | Impact / C2 |
| DNS config/exfil | `dns`, DoH fetch | `dns` | `dns.resolve`, `TXT` | C2 / Exfiltration |
| Native host bridge | `runtime.connectNative` | `nativeMessaging` + host manifest | `connectNative`, `sendNativeMessage` | Persistence / Execution |
| Web↔ext bridge | `externally_connectable`, `runtime.onMessageExternal` | manifest key | `externally_connectable`, `onMessageExternal` | C2 |
| Self-hosted update | `update_url` | manifest key | `update_url` not clients2.google.com | Persistence |
| Search hijack | `chrome_settings_overrides.search_provider` | manifest key | `chrome_settings_overrides`, `search_provider` | Impact |
| New-tab hijack | `chrome_url_overrides.newtab` | manifest key | `chrome_url_overrides`, `newtab` | Impact |
| Inventory/disable other exts | `management` | `management` | `management.setEnabled`, `management.getAll` | Defense Evasion |
| Debugger-based control | `debugger` | `debugger` | `chrome.debugger.attach`, `Runtime.evaluate` | Execution / Defense Evasion |
| Permission widening on update | manifest diff | — | new `permissions`/`host_permissions` in update | Privilege/Scope Escalation |
| Expose ext files to web | `web_accessible_resources` | manifest key | `web_accessible_resources`, `matches` | Privilege/Scope Escalation |

## Permission warning tiers (Chrome)
- High-risk warnings: `<all_urls>`/broad host perms, `nativeMessaging`, `debugger`, `management`, `proxy`, `cookies`+broad host, `tabCapture`, `desktopCapture`, `webRequest`.
- `declarativeNetRequest` shows an install warning; `declarativeNetRequestWithHostAccess` defers to host perms.
- `activeTab` grants temporary host access with no broad warning (stealthy scoping).

## Version gates to record
`offscreen` Chrome 109+. DNR safe-dynamic 30k Chrome 121+. `userScripts` MV3 Chrome 120+. `browser.*` Chrome 148+. Use these to scope a technique's applicability.
