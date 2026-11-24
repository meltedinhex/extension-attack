---
name: extension-store-policies
description: 'Reference for browser extension store review and publishing policies across the Chrome Web Store (CWS), Mozilla Add-ons (AMO), and Microsoft Edge Add-ons: prohibited/malicious behavior, deceptive installation, single-purpose, no-remote-code, obfuscation bans, permission minimization, data-collection consent, affiliate/ad injection, ownership-transfer and forked-clone rules, and enforcement/blocking. Use when attributing an Extension ATT&CK technique to the specific store policy it violates, explaining how trojans pass review then server-gate, or grounding detections in publishing rules. Keywords: Chrome Web Store program policies, AMO add-on policies, Edge developer policies, deceptive installation tactics, remotely hosted code, single purpose, limited use, code readability, repeat abuse.'
---

# Extension Store Policies (CWS / AMO / Edge)

## When to Use
- Mapping an Extension ATT&CK technique to the **store policy clause it violates** (the "why it's abuse" citation).
- Explaining review-evasion tradecraft: **benign-at-review then server-gated**, geofenced/time-bombed activation, obfuscation/packing, ownership-transfer and forked-clone, bulk submission.
- Grounding detections and the matrix in authoritative publishing rules.

See [store-policy-reference](./references/store-policy-reference.md) for clause-by-clause detail and citations.

## The Three Stores at a Glance
| Theme | Chrome Web Store | Firefox AMO | Edge Add-ons |
|-------|------------------|-------------|--------------|
| Malware/unwanted | Malicious and Prohibited Products | §8 Security/Blocking; Acceptable Use | §1.2.2 Unwanted & malicious software (instant suspension) |
| Remote code | No remotely hosted code (MV3 + policy) | §4 self-contained, no remote code | §1.2.1 CSP; no remote script execution |
| Obfuscation | Code Readability Requirements (no obfuscation) | §3 no obfuscated code; reviewable source | §1.1.7 Obfuscation banned (incl. fetched code) |
| Single purpose | Single purpose + Use of Permissions | §1 No Surprises | §1.1.1 Single purpose |
| Min permissions | Use of Permissions / Limited Use | §4.1 only necessary perms | §1.6 only necessary; no "future-proofing" |
| Deceptive install | Deceptive Installation Tactics | §1 No Surprises; §2.5 no install-only add-ons | §1.2 no deceptive install promotion |
| Data/consent | Privacy: Limited Use, Disclosure, Handling | §6 Data Collection consent/control | §1.5 Personal info; no data brokering |
| Ads/affiliate | Ads; Affiliate Ads (only on real action) | §7 label injected ads; no affiliate-tag injection; no miners | §1.10 Advertising; no crypto mining |
| Impersonation/fork | Impersonation & IP | §2 forks must differ materially | §1.1.2 no similar name/icon; no false rep |
| Enforcement | Enforcement, Repeat Abuse, Appeals | §8 block affected versions/add-ons | Suspension + 7-day appeal window |

## Key Shared Prohibitions (anchor the matrix against these)
- **No remotely hosted executable code** — all three. Pushes attackers to remote *config/data*, WASM, DNR, `userScripts`.
- **No obfuscation / must be reviewable** — including code fetched from the web; reviewers may demand refactor. (Packing/obfuscation = Defense Evasion that violates policy.)
- **Single purpose + least privilege** — broad `host_permissions`/`<all_urls>` beyond stated purpose is a violation (Privilege/Scope Escalation signal).
- **Deceptive installation** banned — bundling, forced installs, misleading flows (Initial Access).
- **No deceptive/affiliate/cookie-stuffing monetization** — affiliate tags only on genuine user action; injected ads must be labeled; no cookie stuffing (Impact).
- **Data minimization + consent** — AMO has a formal data-collection consent taxonomy (FF 140+); CWS Limited Use; Edge prohibits data brokering.

## Review-Evasion Tradecraft (policy-violating, map to Defense Evasion)
- **Benign-at-review, server-gated** — payload enabled later via remote config/feature flag (violates no-surprises + single-purpose).
- **Geofencing / time-bomb** — activate only for target geos or after a delay.
- **Ownership transfer / update trojan** — a clean extension is sold or auto-updated to add malicious code (violates update/ownership + malware clauses).
- **Forked clone of a popular extension** — copy + add payload (impersonation/IP + malware).
- **Obfuscation/packing/WASM** to hide logic from reviewers.
Each should carry the specific store clause it breaks in its matrix `references`.

## Enforcement Realities (for the matrix's "detection/response" context)
- CWS: Enforcement Circumvention, Repeat Abuse, Notification & Appeals.
- AMO: may block affected versions or whole add-ons; immediate blocks for intentional/repeat violations; can delete developer accounts.
- Edge: malware → **immediate account suspension**, 7-day appeal window; decisions final.

## Procedure (attributing a technique to policy)
1. Describe the technique behavior.
2. Find the violated clause per store in [store-policy-reference](./references/store-policy-reference.md).
3. Record citations in the technique's matrix entry (`references`), one per applicable store.
4. Note whether it is review-time detectable vs. runtime-only (informs the detection-rules skill).

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — every technique needs ≥1 store-policy citation.
- [extension-threat-intel](../extension-threat-intel/SKILL.md) — real campaigns that violated these clauses.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — review-time vs. runtime detectability drives rule placement.
- [browser-ecosystem-landscape](../browser-ecosystem-landscape/SKILL.md) — which store governs which engine/fork.
