<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->
# Release policy (frozen at F0; SPEC 25.4, F0-G28..G34)

This document fixes how an sv0cov public release is identified, built,
approved, published, verified, retained, and withdrawn. It is the procedure
the release pipeline implements: CV-243 built it as a dry run
(`tools/release.py`, section 8), CV-411 adds the supply-chain closure and
CV-413 attestation, approval and publication. Nothing here has been
exercised by a real publication yet. Machine-checkable parts live in
`sv0cov.formats.release` and `schemas/sv0cov.release-manifest-1.0.schema.json`,
with fixtures in `tests/fixtures/release/`.

## 1. Product version and identity (F0-G28)

- One static `[project].version` in `pyproject.toml`: `MAJOR.MINOR.PATCH`,
  5..128 ASCII bytes, each component `0` or `[1-9][0-9]*`. No `v`, epoch,
  pre-release, post, dev, or local label; no normalization.
  (`inventory.parse_product_version`, `release.version_key`.)
- Wrappers are exact: signed annotated tag `v<version>`; sdist
  `sv0cov-<version>.tar.gz`; wheel `sv0cov-<version>-py3-none-any.whl`;
  release manifest `sv0cov-<version>.release.json`; SBOM
  `sv0cov-<version>.spdx.json`; GitHub Release title `sv0cov <version>`.
- Every other identity (core metadata, `.dist-info`, `version --json`,
  the root policy's `expected_tool.version`, evidence) equals the source
  declaration byte for byte. A release preflight checks this before
  building; independent inspection repeats it after installation. A
  mismatch stops the release; nothing is rewritten to agree.
- A published version is never reused, retagged, or re-uploaded. A
  correction is a new version. CI snapshots and candidates are not releases.

## 2. Version progression (F0-G29)

- Major zero until every R1 gate passes; the first stable release is exactly
  `1.0.0`. Precedence is numeric (`1.10.0` > `1.9.0`).
- Each release strictly increases precedence, resets lower components on a
  MAJOR or MINOR increment, and increments at least the component its
  highest-impact change requires (`release.check_successor`):
  - PATCH: compatible corrections, fixes, docs/evidence, refactors.
  - MINOR: compatible additions; deprecations.
  - MAJOR: any incompatible change to the public contract (SPEC 25.4.2),
    or any change not proven compatible.
  - Before `1.0.0` a MAJOR-impact change may ship as a MINOR increment.
- The release record inventories every public-contract change with its
  impact. A skipped version is recorded, never reused.
- Product SemVer grants no range acceptance: the toolchain still pins one
  exact version and commit, and protocols version independently.

## 3. Attestations (F0-G30)

- Every release attachment, including `SHA256SUMS`, gets a GitHub artifact
  attestation (OIDC, Sigstore public-good) whose subject name and SHA-256
  equal the published bytes.
- Only workflow `.github/workflows/release.yml` in `sv0-toolchain/sv0cov`,
  at the release commit, on the signed-tag event, with issuer
  `https://token.actions.githubusercontent.com`, may produce them. These
  values are frozen in the manifest's `attestation_policy`. Every action is
  pinned by full commit digest.
- The build job has no publication authority. The attestation step has only
  `id-token: write`, `attestations: write`, and read access, and fails if a
  subject changes between digest and attestation.
- Evidence keeps, per subject, the Sigstore bundle and digest, verifier
  version and digest, policy and result, transparency-log inclusion, and a
  trusted-root snapshot. Online and offline verification must both pass
  before promotion. Offline results are never presented as current
  revocation checks.
- Attestations prove provenance and post-build integrity only. No SLSA
  level beyond GitHub's documented capability is claimed.

## 4. Checksums, release manifest, and SBOM (F0-G31)

- `SHA256SUMS`: one line per other attachment,
  `<64 lowercase hex><two spaces><basename>` then LF, strictly ordered by
  UTF-8 filename bytes. Basenames match `[A-Za-z0-9][A-Za-z0-9._-]{0,254}`.
  No header, comment, blank line, binary marker, path, CR, BOM, or
  self-entry (`release.parse_sums`, `release.encode_sums`).
- `sv0cov-<version>.release.json` is `sv0cov.release-manifest` 1.0:
  exactly fourteen properties, canonical JSON, self-digest over the other
  thirteen. `artifacts` lists every attachment except `SHA256SUMS` and the
  manifest itself, filename-sorted, each with `filename`, `media_type`,
  `role`, `sha256`, and `size`. The sdist, wheel (role `package`), and SBOM
  (role `sbom`, digest equal to `sbom_sha256`) are required.
  `release.reconcile` requires `SHA256SUMS` to list exactly those
  artifacts plus the manifest.
- The product version is the one in `release_tag`; every `sv0cov-*`
  filename must carry it.
- SPDX profile: SPDX 2.3 JSON, canonical JSON bytes; document namespace
  `<canonical release URL>/spdx`; creation time is the UTC rendering of
  `SOURCE_DATE_EPOCH`; a locked creator tool; bytewise-stable arrays and
  relationships; no host path, username, runner identifier, secret, or
  wall-clock time. It covers every shipped payload and component: product,
  embedded packages, Python build/test/release distributions, the qualified
  CPython and native runtime closure, external tools, vendored corpora,
  generated and copied assets. Each carries digest, supplier or origin,
  version, download location (`NOASSERTION` only where none lawfully
  exists), declared and concluded licenses, notices, modification state, and
  scope. `SHA256SUMS`, the release manifest, the SBOM itself, and
  attestation material stay outside the SPDX graph. Validation requires the
  SPDX schema, project semantic checks, license reconciliation, and two
  independent reader imports. CycloneDX may exist only as an audit export.

## 5. Independent approval (F0-G32)

- Two distinct accountable people: a release owner who proposes the
  signed-tag candidate and an approver who did not start the publication
  deployment. The GitHub `release` environment requires the approver,
  prevents self-review, accepts only the canonical signed tag, and holds the
  only publication authority. No administrative bypass, workflow-dispatch
  substitute, local publication, personal token, long-lived signing secret,
  or emergency self-approval. Urgency may shorten waiting, never skip
  approval or a gate.
- The candidate input set (source, tag, lock, workflows, action digests,
  build image, caches, generators, schemas, corpora, configuration,
  metadata) is frozen; any change voids earlier build, reproduction,
  attestation, and approval evidence. Two clean builds on independently
  provisioned cells must reproduce the candidate digests.
- The approver reviews the gate manifest, SemVer classification,
  dependency and vulnerability diff, licenses, SBOM, release and checksum
  manifests, attestation results, platform results, open findings, rollback
  target, withdrawal procedure, and publication plan. Approval identity,
  candidate digests, decision, and time are retained without secrets.
- Permissions are default-deny and job-scoped; only the protected
  publication job gets short-lived `contents: write`, and it consumes only
  verified frozen artifacts.
- **Single maintainer (D-3, resolved as DEC-087, SPEC 25.4.5).** While the
  project has one accountable maintainer, the release owner may approve,
  with compensating controls: the protected `release` environment still
  requires an explicit approval, recorded at least 24 hours after the
  candidate input set is frozen; the approval record states that no second
  person was available and lists the whole review set above; every
  automated gate, both reproducible builds, every attestation and every
  verification pass with no manual override; the prohibitions above still
  hold; and the release is labelled `single-maintainer-approved`. The same
  applies to a withdrawal. The two-person rule returns with the first
  release after a second accountable person is available.

## 6. Immutable publication and verification (F0-G33)

- GitHub immutable releases are enabled on the repository or organization
  before the first R1 publication; if enforcement cannot be confirmed, the
  release is blocked.
- The workflow creates a draft for the exact signed tag, uploads the
  complete predeclared attachment set, verifies names, bytes, checksums,
  manifests, attestations, permissions, and the absence of extras, then
  publishes the draft once.
- After publication, GitHub release verification and local verification of
  every downloaded attachment must pass. Evidence keeps the immutable
  status, release attestation, tag and commit, inventory, commands, verifier
  identity, and results. GitHub's generated source archives are not release
  assets.
- No release-identifying field or normative note is edited afterwards;
  corrections are separate dated advisories. A platform change that weakens
  tag, asset, or attestation immutability stops publication pending review.

## 7. Retention, withdrawal, and trust compromise (F0-G34)

- Every non-withdrawn release, its tag, attachments, attestations,
  manifests, SBOM, licenses, evidence, and verification instructions stay
  available indefinitely, plus a complete recovery set in two
  administratively independent, integrity-checked archives.
- At least yearly, and before any toolchain rollback or rewrite cutover, a
  drill restores one current and one prior release and verifies Git objects,
  signatures, checksums, attestations (retained and current trust), install,
  capability identity, and the toolchain policy. The final Python oracle is
  retained until a post-rewrite amendment replaces it.
- Withdrawal only for a demonstrated security threat, compromised trust
  identity, legal prohibition, or material privacy defect, under the same
  owner/approver separation, with an incident record (affected versions and
  digests, reason, impact, detection and decision times, replacement,
  toolchain-pin disposition, credential response, rollback, advisory).
  Ordinary defects get a new release instead.
- A withdrawn version and tag stay reserved forever. Deleting the GitHub
  Release is allowed only when continued access itself causes the harm;
  access-controlled archives keep the bytes where lawful, and public records
  keep digests, status, advisory, and replacement. Withdrawal is contained
  only after every supported toolchain pin has moved through its normal
  policy/gitlink change.

## 8. The dry run (CV-243, R0-G8)

`python tools/release.py dry-run OUT [--commit REV]` runs the pipeline up to,
and never including, tagging, attestation and publication; the tool has no
such step. `python tools/release.py verify OUT [--commit REV]` re-checks a
result from its bytes. CI runs both on all eight host/interpreter cells and
requires the eight `SHA256SUMS` to be identical.

1. **Preflight.** The commit's static `[project].version` is a valid product
   version; a `v<version>` tag, if present, peels to the commit (a dry run
   does not need one).
2. **Input.** The commit's tree from `git archive`, never the working tree.
   Only regular files, except relative symlinks inside the vendored suite
   (`tests/vendor/`), which the sdist excludes. The release build-info
   `src/sv0cov/_build_info.json` (SPEC 25.2.7.1) is written into the export,
   naming the commit; it is ignored by Git and never tracked.
3. **Build once, twice.** The locked `build` group in a fresh environment,
   `SOURCE_DATE_EPOCH` = the commit time, the sdist from the export and the
   wheel from that sdist, without build isolation (as
   `tools/check_packaging.py build`); the two results are byte-identical.
4. **Inspection.** Sdist and wheel allowlists, metadata, records; every
   sdist member is the commit's file, except `PKG-INFO` and the build-info,
   which both archives carry unchanged; the wheel, unpacked and run as
   installed, reports the version and the commit in `version --json`
   (COV-PKG-028) and passes the standalone doctor.
5. **Attachments** (role): `sv0cov-<v>.tar.gz` and
   `sv0cov-<v>-py3-none-any.whl` (package); `sv0cov-<v>-source.tar.gz`, the
   complete tree (source); `sv0cov-<v>-protocol.tar.gz`, schemas, registry
   and the doctor fixture (protocol); `CHANGELOG.md` and
   `sv0cov-<v>.compatibility-matrix.json`, what the release supports and
   advertises (documentation); `sv0cov-<v>.compatibility-policy.json`, the
   root policy that would select it (support); `sv0cov-<v>.licenses.json`
   (license); `sv0cov-<v>.spdx.json` (sbom); `sv0cov-<v>.evidence.json`, the
   build record: backend and Hatchling lock identity, argv and environment
   rule, commit and epoch, sdist-to-wheel edge, member inventories,
   reproduction and installed results (evidence). Then
   `sv0cov-<v>.release.json` and `SHA256SUMS`. The archives are reproducible
   (sorted members, fixed time, owner and modes, gzip without name or time),
   so every attachment is a pure function of the commit.

The dry-run SBOM describes the product, the sdist and wheel and the
generated build-info; the closure of build distributions, the CPython
runtime and every component license comes with CV-411. The dry run makes no
public-channel claim (COV-PKG-001): its output is a local directory, and a
CI snapshot is never a release.

