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

### Which images this rule can assess

Because the expected digest comes from the sidecar, an image that has no sidecar
has nothing to compare against — and the rule **fails** rather than skipping.
That is deliberate: `tst:4`/`tst:6`/`tst:11` exist so a missing sidecar cannot
pass vacuously, and `certificate_audit/fail_missing_stamp` pins it.

The consequence is a floor on which images the rule can meaningfully assess:

| image | outcome |
| --- | --- |
| built by apko **v1.2.30 or later** | assessable |
| built by apko **v1.2.29 or earlier** | fails — no sidecars exist |
| not built by apko at all | fails — no sidecars exist |

v1.2.30 is the first release carrying `writeCABundleChecksums`; v1.2.29 does not
have it. Every current Chainguard image is well past that, so this is not a
concern for scanning what the registry serves today. It matters when scanning
something older: an archived release, a customer's pinned image from before the
change, or an image built by other tooling.

**A failure caused by the floor is not distinguishable from a real one by the
rule verdict alone** — both are `fail`. It *is* distinguishable from the scan
artifact, in the per-test OVAL results, so no access to the image is needed and
an archived results file can be read after the fact. Scan with `--oval-results`
(or keep the ARF) and compare two tests:

| | no usable sidecar | trust store actually drifted |
| --- | --- | --- |
| `tst:4` — sidecar exists and parses | `false` | `true` |
| `tst:2` — bundle matches the sidecar digest | `error` | `false` |

The `error` on `tst:2` is itself the tell: the variable behind the comparison
collected no values, because there was no sidecar to read one from. A `false`
there means a sidecar was read and disagreed.

So `tst:4 false` says the rule *could not assess* this image — it predates the
mechanism, or the sidecar is malformed — which is a different statement from
"this image's trust stores were modified". `tst:4 true` with `tst:2 false` is
the real finding. The same reading applies to `tst:6`/`tst:7` for the Java
truststore and `tst:11`/`tst:12` for a `/kaniko` copy.

Measured, not inferred: scanning an image with its sidecar removed and its
bundle intact gives `tst:4 false`, `tst:2 error`; scanning one with the sidecar
intact and the bundle appended to gives `tst:4 true`, `tst:2 false`. Both report
the rule as `fail`.

In-image, `ls -l /etc/ssl/certs/.ca-certificates.crt.sha256` answers the same
question more directly, where you have a shell and the image to hand.

Note this is a change in which images are assessable, not only in how. Under the
previous design the expected digest was pinned in the datastream, so an old image
could pass if its bundle happened to match that pin — no sidecar required.

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
  appealing to the system one. Which branch a real image takes has
  changed. `kaniko/ssl/certs/ca-certificates.crt` was **not** in apko's
  `caBundlePaths` at v1.2.35 but **is** at v1.2.43, and the published kaniko
  image now ships `/kaniko/ssl/certs/.ca-certificates.crt.sha256` where in
  August 2026 it did not. So real kaniko images have moved off the fallback and
  onto `tst:11`/`tst:12`. Confirmed by running the guard against the image: the
  copy matches its own sidecar, and that sidecar matches `obj:10`'s pattern —
  the first time that pattern has been checked against anything other than a
  synthetic fixture. Both branches remain fixture-covered, so nothing needs
  changing; the fallback is now the path an *older* kaniko image would take.
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

### Guarding the premise

Those fixtures test the rule against images this repository builds. They cannot
tell you that a *real* image still ships sidecars in the shape the rule expects
— which is the assumption the whole rule now rests on, and which upstream can
change without warning. `tests/stamps/run.sh` covers that: for each trust store
in an image it checks the sidecar exists, agrees with the file it names, and
matches the regex the OVAL will apply. The pattern is read out of the datastream
rather than copied, so the guard cannot drift from the definition it guards.

    make test-stamps                     # default: cgr.dev/chainguard/jre:latest
    make test-stamps-selftest            # failure paths, hermetic, no registry

`jre` is the default because it is a public image carrying both the system and
Java sidecars. The daily `update-ca-cert` workflow runs the same script, so a
sidecar that disappears or changes format upstream fails there rather than
surfacing later as a mysterious `CertificateAudit` failure on clean images.

`run_test.sh` is where the failure paths live, with `crane` stubbed so the cases
need no registry or network. It matters because a green daily run only ever sees
a healthy image, so nothing else exercises the diagnostics.

#### Covering the /kaniko criteria

The `/kaniko` bundle copy exists only on `cgr.dev/chainguard-private/kaniko`, so
the default run does not reach it and says so. Anyone with access to that image
can cover it locally by naming it.

`crane` reads the same credentials as `docker`, and `cgr.dev` is served by the
`cgr` credential helper, which needs a token issued for the `cgr.dev` audience
specifically:

    chainctl auth login --audience=cgr.dev

A plain `chainctl auth login` is not enough — that token is scoped to the
console API, so `chainctl auth status` reports `Valid: True` while the pull
still fails with `No matching credentials were found for "cgr.dev"`. The
credential helper itself is usually already wired up (`chainctl auth
configure-docker` will say so); the audience is the part that goes missing.

    tests/stamps/run.sh cgr.dev/chainguard/jre:latest \
                        cgr.dev/chainguard-private/kaniko:latest

    # or, equivalently
    make test-stamps STAMP_IMAGES="cgr.dev/chainguard/jre:latest cgr.dev/chainguard-private/kaniko:latest"

A run reports what it did not reach, so passing that ref drops the `/kaniko`
caveat from the closing note instead of printing it.

This is deliberately not automated. Doing so would need two additions to the
workflow's trust surface, not one: a credential for the private registry, and a
second accepted signer identity, because that image is signed by
`chainguard-dev/stereo/.github/workflows/release-containers.yaml` rather than
the `chainguard-images/images/*` identity the workflow requires. The copy is
currently byte-identical to its system bundle, so the drift being guarded
against is remote; the trade was judged not worth it for now. Revisit if the
`/kaniko` copy ever starts diverging, or gains a sidecar of its own.

## Known gaps

- apko also stamps `var/lib/ecs/deps/execute-command/certs/tls-ca-bundle.pem`
  (still in `caBundlePaths` as of apko v1.2.43). This rule neither checks that
  bundle nor its sidecar.
- `<ind:instance>1</ind:instance>` with `only_one_exists` means a sidecar
  containing two matching lines silently uses the first.
- Deleting `/etc/ssl/certs/java/cacerts` outright satisfies the Java `OR` via
  `tst:5`.
- No automated run guards the `/kaniko` criteria against a real image; the
  daily workflow inspects only public images. It is coverable on demand — see
  [Covering the /kaniko criteria](#covering-the-kaniko-criteria) — and deferred
  rather than declined.
