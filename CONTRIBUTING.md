# Contributing to Extension ATT&CK

Thanks for helping build a shared vocabulary for browser-extension tradecraft. This
project is a taxonomy of browser-extension techniques. Active entries include public
examples; proposed entries need further validation. Signatures and runtime detections
are separate companion work and are not part of this repository yet.

## Ground rules

- **Defensive framing only.** Describe capabilities and detections, not weaponized
  build steps or working payloads.
- **No fabricated sources.** `real_world_examples` must be *public* and *verified* —
  fetch the URL and confirm it actually demonstrates the technique. If you can't
  verify one, leave a `references: ["TODO: ..."]` note and set `status: proposed`.
  See the `extension-threat-intel` skill for sourcing and vetting.
  The build **fails** if a `status: active` technique has no `real_world_examples`.
- **Attribution is a claim, not a fact.** Record who assessed it and their confidence.

## Add or edit a technique

1. Pick the **primary tactic** (exactly one). Use `related` for cross-tactic links.
2. Assign the next free ID: `EXT-<PREFIX>-NNN` (prefixes in `matrix/tactics.yaml`).
   IDs are sequential, zero-padded, and **never reused** — deprecate, don't recycle.
3. Add the entry to the matching `matrix/techniques/<tactic>.yaml`. Required fields:
   `id, name, tactic, status, description, platforms, detection_ideas`. Recommended:
   `apis, permissions, manifest_fingerprint, install_vectors, store_policy_violations,
   real_world_examples, mitre_attack_xref`.
4. **Ground it** using the skills in `.github/skills/`:
   - `mv3-extension-apis` → `apis`, `permissions`, `manifest_fingerprint`
   - `browser-ecosystem-landscape` / `safari-web-extensions` → `platforms`, `scope_note`
   - `extension-store-policies` → `store_policy_violations`
   - `browser-enterprise-policies` → `install_vectors` (force-install/sideload)
5. Run the build (it validates). Open a PR.

See the full field spec in `.github/skills/ext-attack-matrix/references/schema.md` and
the schema at `schema/technique.schema.json`.

## Validate locally

```bash
python -m pip install -r tools/requirements.txt
python tools/build.py --check     # validate only
python tools/build.py             # validate + regenerate build/ artifacts
```

The build **fails** on: schema violations, duplicate IDs, a prefix that doesn't match
its tactic, or a dangling `related` reference.

## Review checklist (PRs)

- [ ] ID unique, correct prefix, sequential, not reused.
- [ ] Exactly one primary tactic; valid enums; schema-valid.
- [ ] API/permission/fingerprint grounded in the skills.
- [ ] `store_policy_violations` cited where applicable.
- [ ] `real_world_examples` public + verified, or `status: proposed` with a TODO.
- [ ] `python tools/build.py` passes.
- [ ] Defensive framing; no weaponization aid.
