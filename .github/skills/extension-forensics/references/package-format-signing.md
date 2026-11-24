# Package Format, Signing & Extension-ID Derivation

How CRX/XPI packages are structured and signed, how an extension's identity is derived, and how update manifests work. Underpins ExtYARA scanning and forked-clone / ownership-transfer analysis.

## CRX3 (Chromium `.crx`)
- A `.crx` is a **CRX3 header followed by a ZIP archive**. To scan with ExtYARA, strip the header and unzip (most ZIP tools can open a CRX directly; or parse the CRX3 magic `Cr24`, version `3`, then the protobuf header with signatures, then the ZIP payload).
- The CRX3 header carries **signatures + the signing public key(s)** (proto `CrxFileHeader`). The CRX is signed with the developer's **private key (`.pem`)**; the matching public key is embedded.
- Chrome packs CRX via the Extensions page "Pack extension" or `chrome.exe --pack-extension=DIR --pack-extension-key=KEY.pem`. First pack generates a `.pem` private key — losing it means you can no longer publish updates under the same ID.

## Extension ID derivation (identity)
- The extension **ID is derived from the signing public key**: SHA-256 of the DER public key; take the first 16 bytes; map each nibble `0–f` to `a–p` (the "mpdecimal" alphabet). Result is a 32-char `a–p` ID.
- Consequences for the matrix:
  - **Same key → same ID across updates.** An update must be signed with the original key (ownership-transfer trojans keep the ID; the *code* changes — EXT-INITACC-002).
  - **Different key → different ID.** A forked-clone gets a new ID even if code is copied (EXT-INITACC-003); detect by code similarity + icon/name reuse, not ID.
  - CWS-published IDs are assigned at upload; self-hosted IDs come from the local key. `appid` in the update manifest must match.

## Update manifest (Chromium self-host / off-store)
`manifest.json` → `update_url` points to an XML update manifest (gupdate/Omaha protocol):
```xml
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'>
    <updatecheck codebase='https://host/ext_v2.crx' version='2.0' prodversionmin='3.0.193.0'/>
  </app>
</gupdate>
```
- `appid` = extension ID (public-key hash). `codebase` = HTTPS `.crx`. New `.crx` must be signed with the **same** private key.
- Chrome sends **no cookies** on update checks and ignores `Set-Cookie`. Checks run every few hours.
- Hosting: server must serve `.crx` with an installable content-type and **not** `X-Content-Type-Options: nosniff`.
- Forensic/abuse signal: a non-store `update_url` + attacker-controlled `codebase` = silent off-store update channel (EXT-PERS-001). On Win/macOS this only works if installed via enterprise policy.

## XPI (Firefox `.xpi`)
- An `.xpi` is a **ZIP**; unzip directly for ExtYARA.
- Must be **Mozilla-signed**; signature lives under `META-INF/` (`mozilla.rsa`/`.sf`/manifest). `signedState` in `extensions.json` reflects validity. Unsigned XPIs load only on Dev/Nightly/unbranded builds.
- ID comes from `browser_specific_settings.gecko.id` (email-style `addon@example.com` or `{UUID}`), not a key hash.
- Self-distribution: a signed XPI + an `updates.json` (JSON, not XML) referenced by `browser_specific_settings.gecko.update_url`:
```json
{ "addons": { "addon@example.com": { "updates": [
  { "version": "2.0", "update_link": "https://host/addon-2.0.xpi" } ] } } }
```

## Safari packaging
- No CRX/XPI. The web extension is compiled into an **app extension** and signed with an **Apple Developer certificate**, distributed via the App Store (or bundled app). See `safari-web-extensions`. Identity = app bundle ID + Apple signing; no public-key-hash ID scheme.

## Practical scan recipe (ExtYARA harness)
1. Acquire CRX/XPI (or copy the already-unpacked `Extensions/<id>/<ver>/` tree).
2. CRX: detect `Cr24` magic → skip CRX3 header → unzip ZIP payload. XPI: unzip.
3. Record: signing public key (CRX), derived ID, `manifest.json` keys, `update_url`, file SHA-256 set.
4. Run ExtYARA over the tree; parse `manifest.json` structurally for permission arrays.
5. For forked-clone/ownership-transfer: compare code similarity + name/icon across IDs; compare signing key continuity across versions.
