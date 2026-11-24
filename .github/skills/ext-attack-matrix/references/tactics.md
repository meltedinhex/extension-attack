# Tactics: Scope & Seed Techniques

Ten columns using ATT&CK tactic names, scoped to the browser-extension execution environment. Use this as the initial seed (20–25 techniques). IDs are suggestions; confirm sequence at authoring time. Ground each against the `mv3-extension-apis`, `extension-store-policies`, and `browser-enterprise-policies` skills.

## Initial Access (EXT-INITACC)
How the extension lands in the browser.
- EXT-INITACC-001 Store-published trojan (clean-looking listing, malicious intent)
- EXT-INITACC-002 Ownership-transfer / update trojan (clean ext sold or auto-updated to add payload)
- EXT-INITACC-003 Forked-clone of a popular extension (copy + payload)
- EXT-INITACC-004 Sideload / developer-mode (unpacked, off-store CRX/XPI)
- EXT-INITACC-005 Force-install via enterprise policy (ExtensionInstallForcelist / ExtensionSettings force_installed)

## Execution (EXT-EXEC)
- EXT-EXEC-001 `scripting.executeScript` dynamic injection
- EXT-EXEC-002 `eval` / `new Function` in-package dynamic eval
- EXT-EXEC-003 Remote-config-driven logic (packaged code, remote feature flags)
- EXT-EXEC-004 Offscreen document execution
- EXT-EXEC-005 WASM module execution

## Persistence (EXT-PERS)
- EXT-PERS-001 Auto-update channel (self-hosted `update_url`)
- EXT-PERS-002 Service-worker re-registration / alarms keep-alive
- EXT-PERS-003 Policy force-install (survives user removal)
- EXT-PERS-004 Native-messaging host (on-disk bridge persists)

## Privilege / Scope Escalation (EXT-PRIVESC)
- EXT-PRIVESC-001 Permission widening on update
- EXT-PRIVESC-002 Broad host permissions (`<all_urls>`)
- EXT-PRIVESC-003 `web_accessible_resources` exposure / web↔ext bridge via `externally_connectable`

## Defense Evasion (EXT-DEFEV)
- EXT-DEFEV-001 Obfuscation / packing (incl. WASM, minified) 
- EXT-DEFEV-002 Geofenced / time-bombed activation
- EXT-DEFEV-003 Benign-at-review, server-gated payload
- EXT-DEFEV-004 DNR used to hide/alter C2 traffic & headers
- EXT-DEFEV-005 Disable/inventory other extensions via `management`

## Credential Access (EXT-CRED)
- EXT-CRED-001 `cookies.getAll` session/cookie theft
- EXT-CRED-002 Reading authenticated page DOM
- EXT-CRED-003 Form / keystroke capture in content scripts
- EXT-CRED-004 Token theft via `webRequest` header observation

## Collection (EXT-COLL)
- EXT-COLL-001 Browsing-history capture
- EXT-COLL-002 Page-content scraping (content script / offscreen DOM scrape)
- EXT-COLL-003 Screenshot / tab capture (`tabCapture`, `captureVisibleTab`)

## Command & Control (EXT-C2)
- EXT-C2-001 Remote config via Sheets / DNS TXT / pastebin / gist
- EXT-C2-002 WebSocket C2 from service worker
- EXT-C2-003 DNR-based redirection channel
- EXT-C2-004 Managed-storage config (`3rdparty > Extensions` / `storage.managed`)

## Exfiltration (EXT-EXFIL)
- EXT-EXFIL-001 `fetch` / `sendBeacon` to C2
- EXT-EXFIL-002 DNS exfiltration
- EXT-EXFIL-003 Image-beacon exfiltration

## Impact (EXT-IMPACT)
- EXT-IMPACT-001 Search hijack (`chrome_settings_overrides`)
- EXT-IMPACT-002 Affiliate / cookie-stuffing
- EXT-IMPACT-003 Ad injection
- EXT-IMPACT-004 Residential-proxy node (`proxy` API / relay)

## Cross-tactic notes
- Many techniques cross-reference (e.g. offscreen = Execution + Collection + Defense Evasion). Pick one primary tactic; use `related` for the rest.
- Map to ATT&CK `T1176` (Browser Extensions) via `mitre_attack_xref` where relevant.
