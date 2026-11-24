# Sourcing Channels, Vetting & Attribution

Companion to the `extension-threat-intel` SKILL. Use these channels to find verifiable public sources; verify every link by fetching it before citing.

## Primary source channels (verify at use time)
- **Browser-vendor security/transparency**: Chrome/Google Security blog & CWS transparency actions; Mozilla Add-ons blog & AMO blocklist/blocked-add-ons notices; Microsoft Edge / MSRC.
- **Government / CERT**: CISA advisories, national CERTs — authoritative, citable.
- **Vendor threat research**: established security vendors' research blogs (read the primary post, not a syndication).
- **Academic**: peer-reviewed studies on extension security/privacy (measurement papers on CWS/AMO at scale) — strong for *class*-level evidence.
- **CVE / NVD**: for extension or extension-platform vulnerabilities — cite the CVE record itself.
- **Store policy/enforcement pages**: the developer-policy pages (see `extension-store-policies`) document *what* is prohibited and sometimes enforcement stats — citable for "why it's abuse."
- **Legal**: DOJ/FTC filings or court documents where an extension scheme was prosecuted.

## What NOT to use
- Private/commercial intel feeds, leaked data, non-public victim details.
- SEO/listicle blogs, unattributed forum posts, social media rumor.
- AI-generated summaries as a primary source.
- Anything you cannot open and confirm.

## Vetting rubric (score each candidate)
| Check | Pass condition |
|-------|----------------|
| Public | Freely reachable, no leak/paywall-of-stolen-data |
| Primary | Original research or official notice (or reputable secondary citing it) |
| Confirmed | Fetched; body demonstrates the technique (not keyword match) |
| Dated/attributed | Publisher + date captured |
| Safe | No operational payload / PII copied into the matrix |
Accept only if all pass. Otherwise `TODO: needs verified public source`.

## Attribution cautions
- Record attribution as **"<org> assessed (confidence: X)"**, never as settled fact.
- Family/actor names differ across vendors — note the naming source.
- Resemblance (code reuse, infrastructure) ≠ confirmed actor; cross-reference before asserting.
- For ownership-transfer/forked-clone cases, separate **what is observable** (same ID, new code; copied name/icon; signing-key continuity — see `extension-forensics`) from **who** did it.

## Capturing a verified example (matrix fields)
```yaml
real_world_examples:
  - title: "<primary source exact title>"
    url: "https://<verified-primary-source>"
    publisher: "<org>"
    date: "YYYY-MM-DD"
    attribution: "<org> assessed; confidence <low|med|high>"   # optional, as a claim
mitre_attack_xref: ["T1176"]   # confirm current id/sub-techniques on attack.mitre.org first
```
Keep the matrix schema's required `{title, url}`; the extra keys are optional provenance you can fold into `references` if the schema is strict.

## Seeding the first release responsibly
- For each of the 20–25 seed techniques, attempt one verified example.
- Techniques without a solid public source ship as `status: proposed` with a `TODO` — this keeps the corpus honest and reviewable rather than padded with invented citations.
- Prefer store-transparency + CERT + academic sources for breadth; they are durable and defensible.
