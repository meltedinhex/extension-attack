---
name: safari-web-extensions
description: 'Reference for the Safari Web Extension model (WebKit/JavaScriptCore) and how it differs from Chromium/Gecko for the Extension ATT&CK project: extensions shipped as macOS/iOS/iPadOS/visionOS app extensions packaged with Xcode, App-Store-only distribution (no self-hosting), a native containing app, native messaging via app groups, SFSafariExtension APIs, per-site/per-day permission model, and declarative content blocking. Use when tagging a technique for the safari platform, explaining why a Chromium technique does or does not port to Safari, or scoping iOS/visionOS extension abuse. Keywords: Safari web extension, app extension, App Store review, SFSafariExtensionManager, native messaging app group, content blocker, iOS 15 extension, Xcode convert, WebKit.'
---

# Safari Web Extensions

Safari's extension model reuses WebExtension JS/HTML/CSS but wraps it in Apple's app-extension + App Store security model. This changes the threat surface meaningfully vs Chromium/Gecko. Use this when a technique touches the `safari` platform.

## When to Use
- Set/justify `platforms: [... safari]` on a matrix technique.
- Explain why a Chromium/Gecko technique **does or doesn't** port to Safari.
- Scope iOS/iPadOS/visionOS extension abuse (different from desktop).

## Core Model (verified, developer.apple.com)
- A Safari web extension is implemented as a **macOS / iOS / iPadOS / visionOS app extension** bundled inside a **native containing app**. The JS/HTML/CSS is the WebExtension; the app is the delivery + native bridge.
- **Packaged and signed with Xcode**; `safari-web-extension-converter` CLI converts an existing CRX/XPI-style extension. Requires Apple Developer Program membership.
- **Distribution is App Store only** (or bundled with a Mac/iOS/visionOS/Catalyst app). **No self-hosting, no off-store CRX/XPI, no `update_url` side-channel.** Managed deployment is via **MDM** profiles.
- Availability: macOS Safari 14+, iOS/iPadOS 15+, visionOS 1+; Mac web apps 15+. Can **sync across the user's devices**.
- `browser.*` namespace (promise-based), MV2 and MV3 manifests supported; **declarative content blocking** via declarativeNetRequest.

## What's Different (abuse-relevant)
| Dimension | Chromium/Gecko | Safari |
|-----------|----------------|--------|
| Distribution | Store **or** self-host/policy | **App Store only** + MDM |
| Review gate | CWS/AMO/Edge automated+human | **Apple App Review** (app + extension) |
| Native bridge | `nativeMessaging` host manifest + on-disk binary | Native messaging to the **containing app** via **app groups** (`SFSafariExtensionHandler`/`SFExtensionMessageKey`); no arbitrary on-disk host |
| Permissions | install-time + optional | **per-site / per-day** user grants; more granular, re-prompts |
| Force-install | enterprise policy keys | **MDM** configuration profiles |
| Update channel | store or self `update_url` | App Store only |
| State inspection | `chrome.management` | `SFSafariExtensionManager` / `SFSafariExtensionState` |

## Technique Portability Guidance
- **Ports to Safari** (API exists): content-script DOM read, page scraping, `cookies`/`history` (where permitted), DNR-based redirection/content blocking, messaging to the containing app.
- **Does NOT port / weaker on Safari**:
  - Self-hosted `update_url` auto-update channel (EXT-PERS-001) — App Store only.
  - Off-store sideload / CRX drop (EXT-INITACC-004) — only Xcode dev-install or App Store.
  - Arbitrary `nativeMessaging` host binary (EXT-PERS-004) — replaced by app-group messaging to the signed containing app (still a bridge, but code-signed + sandboxed).
  - Enterprise `ExtensionInstallForcelist` — use MDM instead; document as the Safari-equivalent of policy force-install.
- **Review-evasion still applies**: benign-at-review then server-gated logic, obfuscation — but Apple App Review + sandbox + per-site prompts raise the bar; note this in the technique's detection/evasion context.

## Native Messaging on Safari (detail)
- The extension talks to its **containing app**, not an arbitrary executable, via `runtime.sendNativeMessage` / `connectNative`-style flow handled by `SFSafariExtensionHandler`; messages keyed by `SFExtensionMessageKey`; data shared through **app groups**. The native side is code-signed and sandboxed. For the matrix, model this as a constrained variant of the native-messaging bridge.

## Forensics / Detection Notes (link to extension-forensics & detection-rules)
- Installed Safari extensions live inside their containing app bundles and Safari's extension state (queried via `SFSafariExtensionManager`); on macOS inspect `~/Library/Containers/…` for the app group and Safari's AppExtensions state.
- Managed deployment artifacts are MDM profiles, not registry/policies.json.
- Because distribution is App-Store-gated, the strongest Safari supply-chain risks are **malicious or hijacked App Store apps** carrying extensions and **compromised developer accounts** — align with `extension-threat-intel`.

## Procedure
1. Check whether the technique's API exists in Safari web extensions.
2. Re-map its install/persistence/native-bridge vectors to Safari equivalents (table above).
3. If a vector has no Safari analog, say so explicitly in the technique (`platforms` excludes safari, with a note).
4. Capture MDM (not policy-registry) as the managed-install path for Safari.

## See also
- [browser-ecosystem-landscape](../browser-ecosystem-landscape/SKILL.md) — where Safari/WebKit sits among the engines.
- [mv3-extension-apis](../mv3-extension-apis/SKILL.md) — Chromium/Gecko API baseline to diff Safari against.
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — re-map each technique's vectors to Safari equivalents.
- [extension-forensics](../extension-forensics/SKILL.md) — macOS container/AppExtensions artifact locations.
- [extension-threat-intel](../extension-threat-intel/SKILL.md) — App-Store supply-chain and hijacked-developer risks.
