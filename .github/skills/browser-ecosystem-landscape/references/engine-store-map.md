# Engine / Store / Platform Map (detail)

Verified Oct 2026. Pair with the `browser-ecosystem-landscape` SKILL. Facts sourced from developer.chrome.com, extensionworkshop.com, learn.microsoft.com/deployedge, developer.apple.com.

## Chromium family
| Browser | Engine | Default store | Also installs from | MV status | Notes |
|---------|--------|---------------|--------------------|-----------|-------|
| Google Chrome | Blink/V8 | Chrome Web Store | Self-host (Linux manual; Win/macOS policy-only) | MV3 only; MV2 fully removed | Reference implementation |
| Microsoft Edge | Blink/V8 | Edge Add-ons | CWS (toggle `ControlDefaultStateOfAllowExtensionFromOtherStoresSettingEnabled`) | MV3; Chromium-aligned sunset | Separate review + policies |
| Brave | Blink/V8 | Chrome Web Store | Self-host via policy | MV3 | Privacy fork; its own adblock is built-in (not an extension) |
| Opera | Blink/V8 | Opera addons | CWS via "Install Chrome Extensions" bridge | MV3 | Own catalog + CWS bridge |
| Vivaldi | Blink/V8 | Chrome Web Store | — | MV3 | Uses CWS directly |
| Arc / other Chromium | Blink/V8 | Chrome Web Store | — | MV3 | Inherit Chromium model |
| Samsung Internet (Android) | Blink/V8 | Galaxy/Samsung add-ons | limited | MV3-ish | Mobile, curated |
| Kiwi (Android) | Blink/V8 | Chrome Web Store | CWS | historically MV2/MV3 | Mobile Chromium that exposed CWS |

Implication for the matrix: a Chromium technique is engine-wide. Prefer tagging `chrome,edge` and add a scope note "applies to all Chromium browsers" rather than enumerating every fork.

## Gecko family
| Browser | Store | Self-distribution | MV status | Notes |
|---------|-------|-------------------|-----------|-------|
| Firefox / ESR | AMO | Signed XPI (Mozilla signature required) | MV3 + retains blocking `webRequest` | Divergence: content-blocking tradecraft still viable |
| Firefox for Android | AMO (GeckoView) | — | MV3 | Mobile extension surface |
| Tor Browser | bundled set | discouraged | MV2/MV3 (Firefox ESR base) | Hardened; extra add-ons increase fingerprint |
| LibreWolf | AMO-compatible | signed XPI | Firefox base | Privacy fork |

Gecko note: `browser.*` is promise-based natively; blocking `webRequest` and `userScripts` (restricted to user-script managers) remain — see `extension-store-policies` §5 and `mv3-extension-apis`.

## WebKit / Safari
See the `safari-web-extensions` skill. Summary: web extensions packaged as macOS/iOS/iPadOS/visionOS **app extensions** via Xcode, distributed through the **App Store only** (or bundled inside a containing app), native messaging via **app groups**, content blocking via declarativeNetRequest. Safari 14+ (macOS), iOS/iPadOS 15+, visionOS 1+. No self-hosting; MDM for managed deployment.

## Manifest V2 sunset timeline (Chrome) — historical reference
- Jan 2022: CWS stops new public/unlisted MV2.
- Jun 2022: CWS stops new private MV2.
- Jun 2024: phase-out begins in pre-stable; MV2 loses Featured badge.
- Oct 2024: disabling begins in stable.
- Mar 2025: disabled by default, user re-enable still possible.
- **Jul 24 2025: MV2 disabled everywhere; users cannot re-enable.**
- **Chrome 139: `ExtensionManifestV2Availability` policy removed** (enterprise exemption ends).
- **Aug 31 2026: all remaining MV2 removed from the Chrome Web Store.**
Chrome 138 was the last version to run MV2 (with the policy). For the matrix: treat Chromium MV2-only techniques as `status: deprecated` or historical; keep them for Gecko where still applicable.

## Distribution security facts (anti-abuse context)
- CWS-signed extensions are the only ones Chrome users can install directly on Win/macOS; off-store = enterprise policy (or Linux manual). This makes `ExtensionInstallForcelist`/policy a key abuse pathway on Win/macOS.
- Self-host update flow: `update_url` in manifest → `updates.xml` (gupdate/Omaha), `appid` = hash of the extension's public key, `codebase` = HTTPS `.crx`, new CRX must be signed with the **same** private key. Chrome sends no cookies on update checks.
- Firefox self-distributed XPIs must still be Mozilla-signed; unsigned load only on Dev/Nightly/unbranded.
- Safari cannot self-host at all — App Store review is the gate.
