# Enterprise Extension Policy Reference

Exact keys, value formats, and storage paths. Verified against chromeenterprise.google/policies, learn.microsoft.com/deployedge/microsoft-edge-policies, and mozilla.github.io/policy-templates.

## Chrome / Chromium

### ExtensionInstallForcelist
Format: array of `"<id>;<update_url>"`.
```
Windows GPO: HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist\1 =
  "pckdojakecnhhplcgfflhghiicjqfhfb;https://clients2.google.com/service/update2/crx"
Linux:  /etc/opt/chrome/policies/managed/policy.json
macOS:  plist domain com.google.Chrome
```
```json
{ "ExtensionInstallForcelist": ["EXTID;https://clients2.google.com/service/update2/crx"] }
```

### ExtensionSettings (per-ID management)
```json
{
  "ExtensionSettings": {
    "*": { "installation_mode": "blocked", "blocked_install_message": "Contact IT." },
    "EXTID": {
      "installation_mode": "force_installed",
      "update_url": "https://clients2.google.com/service/update2/crx",
      "runtime_blocked_hosts": ["*://*.bank.example/*"]
    }
  }
}
```
`installation_mode`: `allowed` | `blocked` | `force_installed` | `normal_installed`. `force_installed`/`normal_installed` require `update_url`.

### Other keys
`ExtensionInstallAllowlist` (IDs), `ExtensionInstallBlocklist` (IDs or `"*"`), `ExtensionInstallSources` (URL patterns), `ExtensionAllowedTypes`, `BlockExternalExtensions` (bool), `ExtensionInstallTypeBlocklist`, `ExtensionManifestV2Availability`, `ExtensionDeveloperModeSettings`, `ExtensionUnpublishedAvailability`, `ExtensionOAuthRedirectUrls`.

### Native messaging
`NativeMessagingAllowlist`, `NativeMessagingBlocklist` (host names or `"*"`), `NativeMessagingUserLevelHosts` (bool), `NativeHostsExecutablesLaunchDirectly`.

## Microsoft Edge
Identical Chromium key names under `HKLM\Software\Policies\Microsoft\Edge\…` / plist `com.microsoft.Edge` / `/etc/opt/edge/policies/managed/`.
Keys: `ExtensionInstallForcelist`, `ExtensionInstallAllowlist`, `ExtensionInstallBlocklist`, `ExtensionInstallSources`, `ExtensionSettings`, `BlockExternalExtensions`, `ExtensionManifestV2Availability`, `ControlDefaultStateOfAllowExtensionFromOtherStoresSettingEnabled`, `NativeMessagingAllowlist`, `NativeMessagingBlocklist`, `NativeMessagingUserLevelHosts`.
Edge store update URL differs from Chrome's; self-hosted CRX via `update_url` is the off-store path.

## Firefox

### ExtensionSettings (recommended)
```json
{
  "policies": {
    "ExtensionSettings": {
      "*": { "installation_mode": "blocked", "install_sources": ["https://addons.mozilla.org/*"] },
      "addon@example.com": {
        "installation_mode": "force_installed",
        "install_url": "https://addons.mozilla.org/firefox/downloads/latest/ADDON_ID/latest.xpi"
      }
    }
  }
}
```
Fields: `installation_mode` (`allowed`/`blocked`/`force_installed`/`normal_installed`), `install_url`, `install_sources`, `allowed_types`, `blocked_install_message`, `restricted_domains`, `updates_disabled`, `default_area`, `private_browsing`. `blocked` beats all; `"*"` default config.

### Legacy / adjacent keys
`Extensions` → `{ "Install": [xpiUrlsOrPaths], "Uninstall": [ids], "Locked": [ids] }`.
`InstallAddonsPermission` → `{ "Allow": [origins], "Default": bool }`.
`ExtensionUpdate` (bool), `DisableSystemAddonUpdate` (bool), `3rdparty` → `Extensions` (per-ID managed storage consumed by `browser.storage.managed`).

### policies.json locations
- Windows: `distribution\policies.json` next to `firefox.exe` (or GPO `HKLM\Software\Policies\Mozilla\Firefox`).
- macOS: `Firefox.app/Contents/Resources/distribution/policies.json`.
- Linux: `/etc/firefox/policies/policies.json` (or distro install dir).
UTF-8 required. `EnterprisePoliciesEnabled` needed to turn on policy support on macOS.

## High-signal detection selectors
- Any extension-policy value whose `update_url` / `install_url` host ∉ {`clients2.google.com`, `edge.microsoft.com`, `addons.mozilla.org`}.
- `installation_mode: force_installed` added outside change control.
- `ExtensionInstallSources` or `ExtensionDeveloperModeSettings` loosened on managed endpoints.
- `NativeMessagingUserLevelHosts` enabled + new host manifest in user-writable dir.
