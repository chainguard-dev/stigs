# CertificateAudit

Rule `xccdf_mil.disa.stig_rule_SV-263659r982563_rule` (CCI-004909, severity
medium), implemented by OVAL definition `oval:org.CABundleHash:def:1` in
`gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml`.

This document records what each criterion checks, why it is written the way it
is, and the traps that are easy to fall into when changing it. The rule is
small but its shape is load-bearing: several criteria exist only to close a
loophole, and removing one silently turns a failure into a vacuous pass.

## What the rule asserts

Two things:

1. Every trust store in the image still matches the SHA-256 digest recorded
   beside it when the image was built.
2. `SSL_CERT_FILE` names a CA bundle that was verified in (1).

### Where "approved" is established

CCI-004909 requires that the image trust only approved certificate authorities.
The approval boundary is the **apko build definition**: a declarative,
version-controlled statement of the image's package set and trust anchors, from
which the image is built and then signed. A trust anchor present because the
build definition asked for it is approved by construction; the review of that
definition *is* the approval step.

The sidecar files record what that approved build produced. This rule then
verifies that the trust stores in the image under assessment still match — so
any anchor introduced outside the approved build path fails the rule. That is
how the rule implements "only approved trust anchors": approved means declared
in the build definition, and the sidecar is the evidence of what was declared.

This is why package checksums are the wrong reference and the sidecar is the
right one. `apk`'s recorded checksums describe the packages as shipped, and so
cannot express an approved addition at all — an image with legitimately added
DoD roots diverges from them. The sidecar is written after the additions are
merged, so it describes the approved image rather than the packages it was
assembled from.

## Where the expected digests come from

The expected digests are **not pinned in this repo**. Each is read at scan time
out of a sidecar file that apko writes next to the file it describes:

| Trust store | Sidecar |
| --- | --- |
| `/etc/ssl/certs/ca-certificates.crt` | `/etc/ssl/certs/.ca-certificates.crt.sha256` |
| `/etc/ssl/certs/java/cacerts` (Java images) | `/etc/ssl/certs/java/.cacerts.sha256` |
| `/kaniko/ssl/certs/ca-certificates.crt` (where present) | `/kaniko/ssl/certs/.ca-certificates.crt.sha256` (where present) |

Sidecars were added to apko in commit `7912130077`; the implementation is
`pkg/build/certificates.go`. Facts that matter when reading the OVAL:

- **Format** is one `sha256sum`-compatible line, `"<hex>  <basename>\n"` — two
  spaces, and the *basename* rather than a path, so it verifies with
  `sha256sum -c` from the file's own directory. The OVAL regexes are written
  against exactly this format.
- **Mode** is `0444`.
- **Ordering:** in `pkg/build/build_implementation.go` the sequence is package
  installation (`FixateWorld`, which runs apk triggers) → `installCertificates`
  (merges any additional trust anchors) → `writeCABundleChecksums`. The sidecar
  therefore describes the *final* assembled rootfs, including approved
  additions — not the packages' contents.
- **No package owns a sidecar.** `apk info -W` on one reports "Could not find
  owner package". Nothing inside the image regenerates them:
  `update-ca-certificates` has no `sha256` reference and the only apk commit
  hook is `ldconfig-commit.sh`.

apko's own comment on `writeCABundleChecksums` states the purpose: "so
downstream tooling (e.g. OpenSCAP) can verify they were not modified
post-build." This rule is that downstream tooling.

## Why not a pinned digest

The rule previously pinned the CA bundle's SHA-256 in the datastream. That had
two failure modes:

- **Churn and false failures.** Every upstream `ca-certificates` roll turned a
  correctly-updated image into a STIG failure until a bot re-pinned the value
  and its PR merged. The re-pin bot merged 14 PRs before the pin was removed.
- **Approved customisation was unrepresentable.** A digest pinned in a shared
  datastream can only match one reference image's bundle. An image built with
  approved customer trust anchors — DoD roots, say — could never satisfy it, so
  the rule could not be applied to exactly the images that most need it.

Reading the digest from the image removes both.

## The criteria

Top level is an `AND`.

| Test | Kind | Checks |
| --- | --- | --- |
| `tst:1` | `unix:file_test`, `only_one_exists` | `/etc/ssl/certs/ca-certificates.crt` exists |
| `tst:4` | `textfilecontent54`, `only_one_exists` | the system sidecar exists and yields exactly one digest |
| `tst:2` | `filehash58` vs `ste:1` (`var:1`) | the bundle's SHA-256 equals the digest from `tst:4`'s object |

Then an `OR` over how `SSL_CERT_FILE` may be satisfied:

- `tst:3` — `SSL_CERT_FILE` is `/etc/ssl/certs/ca-certificates.crt`; or
- the `/kaniko` branch, an `AND` of:
  - `tst:8` — `/kaniko/ssl/certs/ca-certificates.crt` exists,
  - an inner `OR`: either (`tst:11` + `tst:12`) the copy has its own sidecar and
    matches it, or (`tst:13` + `tst:9`) there is *no* sidecar beside the copy and
    it matches the system one,
  - `tst:10` — `SSL_CERT_FILE` is the `/kaniko` path.

Then an `OR` for the Java truststore:

- `tst:5` — `unix:file_test` with `check_existence="none_exist"`: no truststore
  at all, i.e. a non-Java image; or
- `tst:6` + `tst:7` — the truststore's sidecar exists and parses, and the
  truststore matches it.

### Why each guard exists

- **`tst:4` / `tst:6` / `tst:11` (sidecar exists and parses).** Without these the
  rule could pass vacuously. If a sidecar is missing or malformed, the variable
  behind the comparison collects no values and the `filehash58` test evaluates to
  **error**, not false. OVAL's `AND` truth table gives `false AND error = false`,
  so pairing the comparison with an explicit existence test is what converts
  "could not evaluate" into a definite failure. Verified: on a malformed sidecar,
  `tst:4 => false` and `tst:2 => error`, definition `false`.
- **`tst:6` paired with `tst:7`.** This is what stops the Java `OR` from being a
  loophole. A truststore shipped *without* a sidecar must fail, not fall through
  to the absent-truststore branch.
- **`tst:13` before falling back to `tst:9`.** A sidecar beside the `/kaniko`
  copy takes precedence, so a divergent copy cannot sidestep its own sidecar by
  appealing to the system one.
- **`tst:5` uses `none_exist`** rather than testing for Java some other way,
  because a non-Java image must not fail for lacking a truststore.

## How additional trust anchors reach the sidecars

An image may legitimately trust anchors beyond the Mozilla set — a DoD root, for
example. This section describes the mechanism by which such an image ends up
self-consistent, so that a passing result on one is understood rather than
mistaken for a gap. It is not a procedure to follow: the build definition is an
input to the image build, not something edited in the image under assessment.

Additional anchors enter the image through apko's `certificates:` stanza, either
as inline PEM (`additional:`) or from an installed package advertising a
capability named in `providers:`:

```yaml
certificates:
  additional:
    - name: dod-root-ca-3
      content: |
        -----BEGIN CERTIFICATE-----
        ...
  providers:
    - custom-ca-certificates
```

For each such certificate apko writes
`usr/local/share/ca-certificates/<name>-<fingerprint>.crt`, appends it to every
bundle in `caBundlePaths`, and inserts it into every Java truststore in
`javaTruststorePaths` under the alias `<name>-<fingerprint>`. Only then does it
write the sidecars. `installCertificates` explicitly "replac[es] the role of
update-ca-certificates post-install scripts", which is why no apk trigger has to
run for the merged result to be recorded.

Two consequences follow, and they are the ones that matter when reading a
result:

- An image built with additional anchors is **self-consistent**: its sidecars
  cover the merged trust stores, so it passes. This is why the rule can be
  applied to customised images at all, which a digest pinned in a shared
  datastream could not be.
- A trust store modified **after** the build — for instance by
  `update-ca-certificates` in a derived build layer — leaves the sidecars
  describing the pre-modification state, so the rule fails. Nothing in the image
  regenerates them.

Which of those two a given failure represents is worth establishing before
treating it as tampering; see the Java re-encoding note below for a case that
looks alarming and is not.

## Gotchas

### `apk audit` is deliberately absent from the rule's verification guidance

It looks like a natural corroboration and it is a trap. All of the following are
measured, not inferred:

- **It answers a different question.** `apk audit` compares each file to *the
  package that shipped it*; the sidecar compares it to the approved build. On an
  image with approved added anchors these disagree: `sha256sum -c` reports `OK`
  while `apk audit` reports `U etc/ssl/certs/ca-certificates.crt`. Pointing an
  assessor at `apk audit` produces spurious findings on precisely the
  configuration the rule was changed to support.
- **`A` on a sidecar is universal and benign.** Sidecars are unowned, so
  `apk audit` always lists `A etc/ssl/certs/.ca-certificates.crt.sha256` on every
  apko-built image, pristine or not. It is not a signal.
- **The exit code is always 0**, even when differences are reported. Any
  `apk audit && echo compliant` construction is a false pass.
- **The mode matters, and the intuitive flags are the wrong ones.** Coverage is
  split across invocations:

  | Code | Meaning | Reported in |
  | --- | --- | --- |
  | `A` | present but unowned by any package | default mode |
  | `U` | owned, content differs from the package's checksum | default mode |
  | `X` | owned but missing | `--system` **only** |
  | `m` | mode/ownership mismatch | `--check-permissions` |

  Modification of the bundle shows only in default mode; deletion shows only
  under `--system`. Neither `--system` nor `--full` reports a modified bundle.
- **`protected_paths.d` is a red herring.** `protected_paths.d/ca-certificates.list`
  excludes `etc/ssl/certs/ca-certificates.crt` with a `-` prefix, and is shipped
  by `ca-certificates` — so it is absent from bundle-only images such as
  `wolfi-base`, which install only `ca-certificates-bundle`. It does not affect
  audit reporting either way: both an image with the exclusion (`jdk:latest-dev`)
  and one without (`wolfi-base`) report `U` on a modified bundle. Do not
  conclude anything about detection from this file's presence.

### The Java truststore is not reproducible; the CA bundle is

A post-build `update-ca-certificates` leaves `ca-certificates.crt`
byte-identical, so its sidecar still verifies — but it fires the `java-cacerts`
hook (`trust extract --overwrite --format=java-cacerts`), which rewrites
`/etc/ssl/certs/java/cacerts` to a different digest **even when no trust anchor
was added**. Measured on `jre:latest-dev` and `jdk:latest-dev`: shipped
`7966225f…` versus regenerated `b1b254d4…` / `5808906d…`, with an identical
145-alias set per `keytool -list`. It is pure JKS re-encoding.

Consequence: a no-op trust refresh fails `tst:7` and only `tst:7`. The finding
is legitimate — the truststore no longer matches the approved build — but it is
not evidence that the anchor set changed, so do not read it as tampering without
comparing alias sets.

### Verification cannot always be run inside the image

Distroless images ship no shell, and most ship no `apk` binary either —
`jre:latest` and `static:latest` carry the apk *database* at
`usr/lib/apk/db/installed` but no `apk`. The manual verification commands are
meant to be run against an extracted root filesystem (or a `-dev` variant),
which is what the rule's `Script Verification` text now says.

### `$JAVA_HOME` is not a second truststore

`$JAVA_HOME/lib/security/cacerts` is a symlink to `/etc/ssl/certs/java/cacerts`,
so `tst:7` covers the truststore the JVM actually loads. No separate check is
needed.

## Trust model

The rule assumes what the platform already guarantees: the image was produced by
apko from a reviewed build definition, signed, and is run without an in-place
writable root filesystem. Under those assumptions the sidecar is a sound record
of the approved trust set, and this rule binds the assessed image back to it.

The sidecar is not a secret, so an adversary who can write to the assessed
filesystem could rewrite a trust store and its sidecar together. That is not a
gap this rule can close, and no in-image reference can — including apk's, whose
checksums an attacker with the same access could not alter but which, as above,
do not describe the approved image in the first place. Integrity against that
adversary comes from the image signature covering the whole rootfs and from
immutability at runtime; this rule is the piece that detects trust stores which
no longer match the build that was signed.

## Testing

Offline fixtures (`tests/oscap-offline/internal/scan/fixtures_test.go`,
`certificate_audit/*`) cover: the clean pass; a tampered bundle; a wrong,
malformed, and missing system sidecar; the Java pass, wrong sidecar, and missing
sidecar; and the `/kaniko` pass, own-sidecar pass, wrong own-sidecar digest,
malformed own sidecar, tampered copy, and env-without-bundle cases. E2E fixtures
`baseline-clean` and `cabundle-tampered` cover the rule under `oscap-docker`.

Two cautions when editing that matrix:

- The Java fixtures **synthesize** a truststore and a matching sidecar with
  `AddFile`, so they exercise the comparison but never a real `trust extract`.
  The re-encoding behaviour described above is not covered by any fixture.
- A dropped `matrixCase` row is silent — Go does not report unused package-level
  variables, so a fixture blob can exist with no row referencing it and the
  suite still passes. Check the subtest count, not just the diff.

## Known gaps

- apko also stamps `var/lib/ecs/deps/execute-command/certs/tls-ca-bundle.pem`
  (still in `caBundlePaths` as of apko v1.2.35). This rule neither checks that
  bundle nor its sidecar.
- `CertificateAuditTest.xml` is the only OVAL component referenced by the
  datastream with no standalone file under
  `gpos/xml/scap/ssg/content/ssg-chainguard-xccdf/OvalDefinitions/`, so
  `make validate_checks` does not validate this definition.
- `<ind:instance>1</ind:instance>` with `only_one_exists` means a sidecar
  containing two matching lines silently uses the first.
- Deleting `/etc/ssl/certs/java/cacerts` outright satisfies the Java `OR` via
  `tst:5`.
