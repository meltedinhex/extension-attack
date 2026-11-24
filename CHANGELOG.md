# Changelog

IDs are never reused. Removed techniques are deprecated, not deleted.

## Unreleased

- Corrected ownership-transfer attribution and removed an unverified publication date.
- Included full license texts for public distribution.
- Removed signature/detection coverage metadata from taxonomy exports.
- Added generated-output tests and scope notes to individual technique pages.
- Labeled Navigator/STIX integration experimental pending consumer testing.

## 1.1 - 2026-11-23

- 80 techniques (47 active, 33 proposed), up from 51 at launch.
- Added: install-source / ad-gated activation, shadow-DOM overlay injection, cross-extension shared identifier (from Microsoft Edge's SleeperWidget research).
- Added proposed techniques: passkey/WebAuthn interception, autofill clickjacking, security-extension tampering, anti-removal, clipboard address swap, new-tab hijack, browser-sync propagation, cross-extension messaging.
- New outputs: STIX 2.0 bundle, status-scored Navigator layer, per-technique pages, GitHub Pages deployment.
- Heatmap hardening (escaped embedded data, http(s)-only links).
- Signatures and detections removed from the repository; the repo is taxonomy-only.

## 1.0

- Initial release: 10 tactics, `EXT-<TACTIC>-NNN` IDs, schema-validated YAML, Navigator layer, interactive heatmap.
