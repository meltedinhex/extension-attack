---
name: browser-ecosystem-landscape
description: 'Map of the whole browser-extension ecosystem for the Extension ATT&CK project: engine families (Chromium, Gecko, WebKit), the browsers in each (Chrome, Edge, Brave, Opera, Vivaldi, Arc, Firefox, Tor, LibreWolf, Safari), their extension stores and self-hosting options, desktop vs mobile support (Firefox Android, Safari iOS, Kiwi), and the Manifest V2→V3 status per engine. Use when deciding which platforms a matrix technique applies to, scoping cross-browser coverage, explaining where an extension can be published or sideloaded, or grounding the platforms[] field. Keywords: Chromium family, Gecko, WebKit, Chrome Web Store, AMO, Edge Add-ons, Opera addons, self-hosting, MV2 sunset, Firefox Android, Safari iOS, browser engine.'
---

# Browser Extension Ecosystem Landscape

The "where does this run and ship" map. Use it to set a technique's `platforms` accurately and to reason about cross-browser scope. Deep per-area detail lives in [engine-store-map](./references/engine-store-map.md).

## When to Use
- Decide the `platforms: [chrome, edge, firefox, safari]` set for a matrix technique.
- Explain distribution/sideload options for a given browser (store vs self-host vs policy).
- Scope coverage: which browsers share an engine and therefore an API/abuse surface.
- Ground the MV2/MV3 applicability of a technique in the current timeline.

## Engine Families (share API surface → share tradecraft)
| Engine | Browsers | Extension model | Primary store(s) |
|--------|----------|-----------------|------------------|
| **Chromium (Blink/V8)** | Chrome, Edge, Brave, Opera, Vivaldi, Arc, Samsung Internet | MV3 WebExtensions (`chrome.*`/`browser.*`) | Chrome Web Store (CWS), Edge Add-ons, Opera addons; CWS reused by Brave/Vivaldi/Arc |
| **Gecko (SpiderMonkey)** | Firefox, Firefox ESR, Tor Browser, LibreWolf, Firefox for Android | MV3 + event pages; `browser.*` promises | addons.mozilla.org (AMO) + self-distribution (signed XPI) |
| **WebKit (JavaScriptCore)** | Safari (macOS/iOS/iPadOS/visionOS) | Web Extensions packaged as app extensions | App Store **only** (see `safari-web-extensions` skill) |

Key implication: a Chromium technique usually applies to **all** Chromium browsers; tag `chrome` + `edge` as primary and note "all Chromium" where relevant. Gecko techniques apply to Firefox + hardened forks. WebKit/Safari is its own column.

## Manifest Version Status (verified Oct 2026)
- **Chrome/Chromium**: MV3 only. MV2 **fully removed** — disabled everywhere since Jul 24 2025, `ExtensionManifestV2Availability` enterprise policy removed in Chrome 139, all remaining MV2 extensions pulled from CWS Aug 31 2026. Treat MV2-only techniques (e.g. blocking `webRequest`) as **historical** for Chromium.
- **Edge**: follows Chromium MV3; still exposes some MV2 availability controls but aligned to Chromium sunset.
- **Firefox**: supports both MV3 and MV2-style capabilities (keeps blocking `webRequest`); `browser.*` promises; this is a real present-day divergence — content-blocking/`webRequest` tradecraft still lives on Gecko.
- **Safari**: MV2/MV3 web extensions, Apple-reviewed; DNR-based content blocking.

## Distribution / Install Vectors (feeds matrix `install_vectors`)
| Vector | Chromium | Gecko | WebKit |
|--------|----------|-------|--------|
| Official store | CWS / Edge Add-ons / Opera | AMO | App Store |
| Self-hosting | Linux manual CRX; Win/macOS **policy-only** | Signed XPI self-distribution allowed | Not allowed (App Store only) |
| Sideload / dev mode | Unpacked (developer mode) | Temporary/unsigned (Dev/Nightly) | Temporary via Xcode (dev) |
| Enterprise force-install | `ExtensionInstallForcelist`/`ExtensionSettings` | `ExtensionSettings`/`Extensions` | MDM profiles |
See the `browser-enterprise-policies` skill for exact keys.

## Mobile
- **Firefox for Android**: supports a curated/expanding set of AMO extensions (GeckoView) — a real mobile extension attack surface.
- **Safari iOS/iPadOS**: web extensions since iOS 15, App-Store-distributed inside a container app.
- **Kiwi/Edge/Samsung Internet (Android, Chromium)**: varying extension support; Kiwi historically allowed CWS installs.
- Desktop-only assumption is wrong — tag mobile where the technique's API exists on mobile.

## Store ↔ Policy ↔ Engine quick reference
- Chrome Web Store serves Chrome **and** most Chromium forks (Brave/Vivaldi/Arc) and (historically) Kiwi.
- Edge Add-ons is Edge's default but Edge can also allow CWS installs (controlled by `ControlDefaultStateOfAllowExtensionFromOtherStoresSettingEnabled`).
- Opera has its own addons catalog + a CWS bridge extension.
- AMO is the sole first-party Gecko store; self-distributed XPIs must still be Mozilla-signed.

## Procedure (setting a technique's scope)
1. Identify the API/manifest key the technique uses (from `mv3-extension-apis`).
2. Determine the engine(s) that expose it (table above). Chromium API ⇒ all Chromium browsers.
3. Check MV2/MV3 applicability (is it a Gecko-only `webRequest`-blocking behavior? historical on Chrome?).
4. Add mobile platforms where the API exists there.
5. Record the realistic `install_vectors` per engine.
6. Write `platforms` + a one-line scope note; cite the relevant store/policy skill.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — consumes `platforms`/`install_vectors` scope decisions.
- [mv3-extension-apis](../mv3-extension-apis/SKILL.md) — which engine exposes each API/manifest key.
- [safari-web-extensions](../safari-web-extensions/SKILL.md) — the WebKit outlier in the engine table.
- [extension-store-policies](../extension-store-policies/SKILL.md) — store governance per engine/fork.
- [browser-enterprise-policies](../browser-enterprise-policies/SKILL.md) — managed-install paths per engine.
