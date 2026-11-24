# On-Disk Extension Artifacts (paths + state files)

Analyst reference for locating installed extensions and their metadata. Paths are the common defaults; profiles can be renamed/multiple. Always enumerate all profile dirs.

## Chromium (Chrome / Edge / Brave / Opera / Vivaldi)
Profile roots:
- **Windows**: `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\`
  - Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\`
  - Brave: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\<Profile>\`
- **macOS**: `~/Library/Application Support/Google/Chrome/<Profile>/` (Edge: `…/Microsoft Edge/…`)
- **Linux**: `~/.config/google-chrome/<Profile>/` (Chromium: `~/.config/chromium/…`)

`<Profile>` = `Default`, `Profile 1`, etc.

Key artifacts under the profile:
| Artifact | Meaning |
|----------|---------|
| `Extensions/<id>/<version>_<n>/` | Unpacked extension tree (manifest.json + code) → feed ExtYARA |
| `Preferences` (JSON) | `extensions.settings.<id>`: manifest, permissions, `from_webstore`, `install_time`, `state` |
| `Secure Preferences` (JSON) | HMAC-protected copy of sensitive settings incl. `protection.macs`; `install_source`, `was_installed_by_default`; tampering breaks the MAC |
| `Local Extension Settings/<id>/` | Per-extension `storage.local` (LevelDB) |
| `IndexedDB/chrome-extension_<id>_*/` | Extension IndexedDB (LevelDB) |
| `Managed Extension Settings/<id>/` | `storage.managed` (policy-delivered config → EXT-C2-004) |
| `Local Storage/leveldb/` | localStorage incl. extension origins |
| `Network/` , `Service Worker/` | SW scripts/cache (runtime C2 artifacts) |
| `Local State` (JSON, profile-parent) | encryption key material, profile list |

Install-source evidence: `Preferences`/`Secure Preferences` → `from_webstore` false + non-store `update_url` = off-store; `install_source` and `was_installed_by_default`/`was_installed_by_oem` indicate policy/bundled installs.

## Firefox (and Tor / LibreWolf)
Profile roots:
- **Windows**: `%APPDATA%\Mozilla\Firefox\Profiles\<rand>.default*\`
- **macOS**: `~/Library/Application Support/Firefox/Profiles/<rand>.default*/`
- **Linux**: `~/.mozilla/firefox/<rand>.default*/`

Key artifacts:
| Artifact | Meaning |
|----------|---------|
| `extensions/<id>.xpi` | Installed add-on package (ZIP) → unzip for ExtYARA |
| `extensions.json` | Add-on inventory: id, version, `location` (app-profile vs app-system vs app-global), signedState, install telemetry |
| `addonStartup.json.lz4` | Early-start add-on state (mozLz4-compressed) |
| `storage/default/moz-extension+++<uuid>/` | Extension storage (IndexedDB/localStorage) |
| `prefs.js` | `extensions.*` prefs; managed via policy |
| `browser-extension-data/<id>/` | `storage.local` data |

Managed installs: `distribution/policies.json` or `/etc/firefox/policies/policies.json` (see `browser-enterprise-policies`). `signedState` reveals Mozilla-signature status (unsigned = Dev/Nightly only).

## Safari
- Extension lives inside its **containing app** bundle (`.app`) and is registered as an app extension.
- User data / app group under `~/Library/Containers/<bundle-id>/` and `~/Library/Group Containers/<group-id>/`.
- Safari extension enable-state via `SFSafariExtensionManager` (programmatic) and Safari settings; managed deployment = MDM profile.
- No registry/policies.json equivalent; see `safari-web-extensions`.

## OS-level corroboration
- **Windows registry** extension policies: `HKLM\Software\Policies\Google\Chrome\…`, `…\Microsoft\Edge\…`, `…\Mozilla\Firefox\…`; native-host manifests referenced under `…\NativeMessagingHosts\`.
- **macOS**: managed plist `com.google.Chrome` / `com.microsoft.Edge`; native-host manifests in `/Library/Google/Chrome/NativeMessagingHosts/` or `~/Library/.../NativeMessagingHosts/`.
- **Linux**: `/etc/opt/chrome/policies/managed/*.json`; native hosts in `/etc/opt/chrome/native-messaging-hosts/` or `~/.config/...`.

## Parsing tips
- LevelDB (`Local Extension Settings`, `IndexedDB`) → use a LevelDB reader; records hold exfil staging / config.
- `Secure Preferences` MAC check: recompute HMAC with the profile seed to detect tampering.
- Always hash (SHA-256) the CRX/XPI and each extracted file for the evidence trail.
