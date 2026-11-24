---
name: extension-threat-intel
description: 'Methodology for sourcing, vetting, and citing PUBLIC real-world examples, CVEs, and campaign references that ground Extension ATT&CK technique entries (the matrix requires public real_world_examples). Use when finding or validating a public reference for a technique, categorizing a known malicious-extension campaign pattern, mapping to MITRE ATT&CK (T1176 Browser Extensions), or avoiding fabricated/low-quality citations. Emphasizes verification, provenance, and defensive framing. Keywords: threat intelligence, real-world example, CVE, public report, MITRE ATT&CK T1176, campaign attribution, source vetting, citation, browser extension malware writeup.'
argument-hint: '<find-example | vet-source | map-attack> [technique id or behavior]'
---

# Extension Threat Intelligence & Sourcing

The matrix schema **requires** at least one *public* real-world example per technique. This skill is the sourcing + vetting discipline that keeps those citations real, attributable, and safe. It feeds the `ext-attack-matrix` `real_world_examples`, `references`, and `mitre_attack_xref` fields.

## When to Use
- Find or validate a **public** reference for a matrix technique.
- Categorize a known malicious-extension campaign pattern.
- Map a technique to **MITRE ATT&CK** (`T1176` Browser Extensions and current sub-techniques).
- Avoid fabricated, paywalled, or operationally harmful citations.

See [sourcing-and-attribution](./references/sourcing-and-attribution.md) for source channels, a vetting rubric, and attribution cautions.

## Hard Rules (non-negotiable)
1. **Never fabricate** a citation, CVE id, vendor, URL, or victim. If you cannot verify a source, mark the technique's example as `TODO: needs verified public source` rather than invent one.
2. **Public + verifiable only.** Prefer primary sources (vendor research blog, CERT/CISA advisory, store transparency notice, academic paper, CVE record, court/DOJ filing). No private intel, no leaks, no non-public victim data.
3. **Verify the URL resolves** and the content actually describes the technique before adding it. Fetch and confirm.
4. **Defensive framing.** Cite to explain *detection/attribution*, not to provide a build recipe. Strip operational payload detail.
5. **Attribution is a claim, not a fact.** Record who made the attribution and their confidence; don't assert actor identity as settled.

## Campaign Pattern Taxonomy (map examples to these)
Use these recurring *patterns* to classify a source and link it to matrix techniques (confirm specifics against the actual report):
- **Store-published trojan** — clean listing, malicious intent (EXT-INITACC-001).
- **Ownership transfer / update trojan** — popular extension sold or auto-updated to add payload; same ID, new code (EXT-INITACC-002 / EXT-PERS-001).
- **Forked-clone / typosquat** — copy of a popular extension + payload; new ID (EXT-INITACC-003).
- **Developer-account compromise** — OAuth/phishing of a publisher pushes a malicious update (supply chain; links to store-policies 2SV).
- **Malicious SDK / library** — monetization/analytics SDK bundled into many extensions performs the abuse (collection/exfil).
- **Affiliate / cookie-stuffing / ad-injection** monetization abuse (EXT-IMPACT-002/003).
- **Data-harvesting / "privacy tool" that exfiltrates** browsing data (EXT-COLL-001/002, EXT-EXFIL-001).
- **Residential-proxy / SDK monetization** turning the browser into a relay node (EXT-IMPACT-004).
- **Mass CWS/AMO removals** — store transparency actions are citable evidence of a campaign class.

## MITRE ATT&CK Mapping
- Primary cross-reference: **`T1176.001` Browser Extensions**, a sub-technique of **`T1176` Software Extensions** (tactic: Persistence). As of ATT&CK v19 (Oct 2025) T1176 was renamed "Software Extensions" and split into `T1176.001` (Browser Extensions) and `T1176.002` (IDE Extensions). Use `T1176.001` for browser-extension techniques; keep the parent `T1176` only when a technique isn't browser-specific. Always confirm the current id on attack.mitre.org before writing `mitre_attack_xref` (ATT&CK evolves).
- MITRE's T1176.001 page lists **verified, cited procedure examples** (e.g. Bundlore, Grandoreiro, Kimsuky, Lumma Stealer, Mispadu, OSX/Shlayer, TRANSLATEXT) with primary references — a reputable secondary source that satisfies the vetting rubric. Cite the specific vendor report plus the MITRE page.
- The Extension ATT&CK matrix is **extension-scoped and finer-grained** than ATT&CK; use `mitre_attack_xref` to point outward, not to replace the EXT ids.

## Sourcing Procedure
1. Start from the technique's behavior + APIs (from `mv3-extension-apis`).
2. Search primary channels (see reference) for a report that demonstrably shows that behavior.
3. **Fetch and read** the candidate; confirm it matches the technique (not just keyword overlap).
4. Capture `{title, url}`, the publishing org, date, and the attribution/confidence as stated.
5. Add `mitre_attack_xref` after verifying the current ATT&CK id.
6. If no solid public source exists, leave a `TODO` marker — do **not** invent one. A technique may ship `status: proposed` pending a citation.

## Vetting Rubric (accept only if)
- [ ] Source is public and primary (or a reputable secondary citing a primary).
- [ ] URL fetched and content confirms the technique.
- [ ] Publisher + date recorded; attribution framed as a claim.
- [ ] No operational/weaponization detail copied in.
- [ ] No private victim/PII data.

## Anti-patterns
- Copy-pasting a vendor headline without reading the body.
- Citing a listicle/SEO blog instead of the primary research.
- Inventing a plausible-looking CVE or campaign name.
- Stating actor attribution as fact.

## See also
- [ext-attack-matrix](../ext-attack-matrix/SKILL.md) — vetted examples populate technique `real_world_examples`.
- [extension-store-policies](../extension-store-policies/SKILL.md) — the clauses each campaign violated.
- [extension-detection-rules](../extension-detection-rules/SKILL.md) — turn campaign TTPs into detections.
- [browser-ecosystem-landscape](../browser-ecosystem-landscape/SKILL.md) — which store/engine a campaign targeted.
