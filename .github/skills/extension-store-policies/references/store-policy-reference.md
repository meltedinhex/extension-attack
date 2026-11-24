# Store Policy Reference (clause-level)

Citations for attributing Extension ATT&CK techniques to the publishing rule they violate. Verified Oct 2026.

## Chrome Web Store — Program Policies
Source: `https://developer.chrome.com/docs/webstore/program-policies`
- **Fostering a Safe Ecosystem**: Malicious and Prohibited Products; Mature/Explicit; Hate & Violence; Regulated Goods.
- **Protecting User Privacy**: Privacy Policy; **Limited Use**; **Use of Permissions**; Disclosure Requirements; Handling Requirements; User Data FAQ.
- **Responsible Marketing & Monetization**: Impersonation & Intellectual Property; **Deceptive Installation Tactics** (+FAQ); Accepting Payment; Misleading or Unexpected Behavior; Ads; **Affiliate Ads** (+FAQ) — affiliate codes only on a related, user-initiated action with visible benefit.
- **Building Quality Products**: Spam and Abuse; Quality Guidelines; Listing Requirements; Minimum Functionality.
- **Technical Requirements**: **Code Readability** (no obfuscation; reviewable), API Use, **Additional Requirements for Manifest V3** (no remotely hosted code), 2-Step Verification.
- **Enforcement**: Enforcement Circumvention; Notification and Appeals; Repeat Abuse.

## Mozilla AMO — Add-on Policies
Source: `https://extensionworkshop.com/documentation/publish/add-on-policies/`
1. **No Surprises** — unexpected features must be opt-in and disclosed; permissions prompt ≠ consent.
2. **Content** — Acceptable Use; **forks must materially differ** in name, function, and/or code; no install-only/launcher-only add-ons; no duplicate themes.
3. **Submission Guidelines** — reviewable **source code** required; **no obfuscation**; minification OK; only official package managers; release-version third-party libs only.
4. **Development Practices** — only necessary permissions; **self-contained, no remote code**; no remote new-tab; **must not relax CSP**; encrypt data in transit.
5. **User Scripts** — `userScripts` API only for user-script-manager extensions; explicit user install action.
6. **Data Collection** — disclose + consent/control; FF140+ built-in consent taxonomy (personal=opt-in, technical=opt-out); no transmitting ancillary data; no leaking local info via native messaging; private-browsing data must not persist/cross sessions.
7. **Monetization** — label injected ads as from the add-on; **no crypto miners**; **no affiliate-tag injection** into web content/redirects (UI affiliate links OK).
8. **Security, Compliance & Blocking** — Mozilla may reject/block versions or whole add-ons; immediate block for intentional/repeat violations; may delete accounts.

## Microsoft Edge Add-ons — Developer Policies
Source: `https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/store-policies/developer-policies`
- **1.1 Distinct function** — 1.1.1 single purpose; 1.1.2 accurate representation, no similar name/icon, no false company/gov rep; **1.1.7 Obfuscation banned** (incl. external/fetched code); 1.1.8 no altering browser settings (search/home/newtab/favorites) without consent + easy reversal.
- **1.2 Security** — 1.2.1 CSP (no remote script run inconsistent with stated function); **1.2.2 Unwanted & malicious software** → immediate account suspension; 1.2.4 updates only via Partner Center; declare all perms; DNR rules declared (not remote); **no deceptive install promotion**; crypto wallets only by verified companies; no bulk identical submissions.
- **1.5 Personal information** — necessary-only; privacy policy; opt-in third-party sharing; **no data brokering** regardless of consent; secure transmission.
- **1.6 Permissions** — only necessary; **no "future-proofing."**
- **1.10 Advertising** — ads not the primary purpose; **no crypto mining**; no paywall circumvention / unauthorized copyrighted content.
- **Enforcement** — malware → immediate suspension; 7-day appeal; decisions final.

## Technique → clause quick map
| Technique theme | CWS | AMO | Edge |
|-----------------|-----|-----|------|
| Store-published trojan | Malicious & Prohibited | §8 / Acceptable Use | §1.2.2 |
| Remote-config server-gating | MV3 no remote code + Unexpected Behavior | §4 | §1.2.1 |
| Obfuscation/packing | Code Readability | §3 | §1.1.7 |
| Broad host perms beyond purpose | Use of Permissions | §4.1 | §1.6 |
| Search/newtab hijack | Misleading/Unexpected Behavior | §1 | §1.1.8 |
| Affiliate / cookie stuffing | Affiliate Ads | §7 | §1.10 |
| Ad injection | Ads | §7 | §1.10 |
| Forked-clone / impersonation | Impersonation & IP | §2 | §1.1.2 |
| Deceptive/force install | Deceptive Installation | §1 | §1.2 deceptive promotion |
| Undisclosed data collection | Limited Use / Disclosure | §6 | §1.5 |
| Crypto mining / proxy node | Minimum Functionality / Unwanted | §7 | §1.10 / §2.8 |
