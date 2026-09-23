#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Chainguard
#
# Tests tests/stamps/run.sh against synthetic images.
#
# The guard's whole value is in its failure paths, and those are the paths a
# green CI run never exercises: the daily run only ever sees a healthy image.
# Two of them were previously unreachable or absent altogether —
#
#   - a missing sidecar aborted on `tar`'s "Not found in archive" before the
#     diagnostic naming which trust store could run, and
#   - a sidecar whose digest is right but whose filename spelling the OVAL's
#     regex rejects passed a `sha256sum -c`-only guard while failing the rule.
#
# so each is pinned by a case below.
#
# `crane` is stubbed with a script that streams a tar of a prepared directory,
# which keeps the test hermetic: no registry, no network, and mutations that
# would be awkward to publish as real images are just files on disk.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Overridable so the suite can be pointed at a deliberately-broken copy of the
# guard to confirm these cases actually fail when the behaviour regresses.
GUARD="${STAMP_GUARD:-${HERE}/run.sh}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

VARIANTS="${WORK}/variants"
mkdir -p "${WORK}/bin" "${VARIANTS}"

cat > "${WORK}/bin/crane" <<'EOS'
#!/usr/bin/env bash
# Stub. `crane export <variant> -` streams a tar of the prepared directory,
# shaped like real crane output (no leading "./").
[ "$1" = "export" ] || { echo "stub crane: unexpected args: $*" >&2; exit 64; }
d="${STAMP_TEST_VARIANTS}/$2"
[ -d "${d}" ] || { echo "stub crane: no such variant: $2" >&2; exit 1; }
cd "${d}" && exec tar -cf - $(ls -A)
EOS
chmod +x "${WORK}/bin/crane"
export PATH="${WORK}/bin:${PATH}"
export STAMP_TEST_VARIANTS="${VARIANTS}"

# A pristine image: two trust stores, each with a sidecar that describes it.
base="${WORK}/base"
mkdir -p "${base}/etc/ssl/certs/java" "${base}/kaniko/ssl/certs"
echo "bundle content" > "${base}/etc/ssl/certs/ca-certificates.crt"
echo "truststore content" > "${base}/etc/ssl/certs/java/cacerts"
sidecar_for() {
  printf '%s  %s\n' "$(sha256sum "$1" | cut -d' ' -f1)" "$(basename "$1")"
}
sidecar_for "${base}/etc/ssl/certs/ca-certificates.crt" \
  > "${base}/etc/ssl/certs/.ca-certificates.crt.sha256"
sidecar_for "${base}/etc/ssl/certs/java/cacerts" \
  > "${base}/etc/ssl/certs/java/.cacerts.sha256"

variant() { rm -rf "${VARIANTS:?}/$1"; cp -r "${base}" "${VARIANTS}/$1"; echo "${VARIANTS}/$1"; }

v="$(variant clean)"

v="$(variant no_java)";              rm -rf "${v}/etc/ssl/certs/java"

v="$(variant kaniko_without_sidecar)"
cp "${base}/etc/ssl/certs/ca-certificates.crt" "${v}/kaniko/ssl/certs/ca-certificates.crt"

v="$(variant missing_system_sidecar)"; rm "${v}/etc/ssl/certs/.ca-certificates.crt.sha256"

v="$(variant missing_java_sidecar)";   rm "${v}/etc/ssl/certs/java/.cacerts.sha256"

v="$(variant wrong_digest)"
printf '%064d  ca-certificates.crt\n' 0 > "${v}/etc/ssl/certs/.ca-certificates.crt.sha256"

# Digest is correct; only the filename field's spelling differs. `sha256sum -c`
# accepts this, the OVAL's regex does not.
v="$(variant absolute_path_sidecar)"
( cd "${v}/etc/ssl/certs" \
  && printf '%s  /etc/ssl/certs/ca-certificates.crt\n' \
       "$(sha256sum ca-certificates.crt | cut -d' ' -f1)" \
       > .ca-certificates.crt.sha256 )

v="$(variant kaniko_sidecar_disagrees)"
cp "${base}/etc/ssl/certs/ca-certificates.crt" "${v}/kaniko/ssl/certs/ca-certificates.crt"
printf '%064d  ca-certificates.crt\n' 0 > "${v}/kaniko/ssl/certs/.ca-certificates.crt.sha256"

# A copy with no sidecar of its own is held to the system sidecar instead
# (tst:13 + tst:9), so "no sidecar" is permitted only while the copy still
# matches. A diverged copy has to fail: permitting the branch without checking
# its premise would pass an image the rule rejects.
v="$(variant kaniko_copy_diverges)"
echo "a different bundle" > "${v}/kaniko/ssl/certs/ca-certificates.crt"

# name | variant | want_exit | substring the output must contain
CASES=(
  "pristine image passes|clean|0|matches .ca-certificates.crt.sha256"
  "image without Java skips the truststore|no_java|0|etc/ssl/certs/java/cacerts: absent"
  "kaniko copy without a sidecar passes while it matches the system one|kaniko_without_sidecar|0|matches the system sidecar it falls back to"
  "kaniko copy without a sidecar that diverges from the system one fails|kaniko_copy_diverges|1|does not match the system sidecar it falls back to"
  "missing system sidecar is named, not a tar error|missing_system_sidecar|1|etc/ssl/certs/.ca-certificates.crt.sha256 missing"
  "missing Java sidecar is named, not a tar error|missing_java_sidecar|1|etc/ssl/certs/java/.cacerts.sha256 missing"
  "sidecar digest that disagrees fails|wrong_digest|1|does not match the digest"
  "sidecar the OVAL regex rejects fails despite sha256sum -c passing|absolute_path_sidecar|1|does not match the pattern"
  "kaniko sidecar that disagrees fails|kaniko_sidecar_disagrees|1|does not match the digest"
)

failed=0
for case in "${CASES[@]}"; do
  IFS='|' read -r name ref want_exit want_substr <<<"${case}"

  set +e
  out="$("${GUARD}" "${ref}" 2>&1)"
  got_exit=$?
  set -e

  if [ "${got_exit}" -ne "${want_exit}" ]; then
    printf 'FAIL %s\n     variant=%s want exit %s, got %s\n     output:\n%s\n' \
      "${name}" "${ref}" "${want_exit}" "${got_exit}" "${out}"
    failed=1
    continue
  fi
  if ! printf '%s' "${out}" | grep -qF -- "${want_substr}"; then
    printf 'FAIL %s\n     variant=%s exit %s as expected, but output lacked %q\n     output:\n%s\n' \
      "${name}" "${ref}" "${got_exit}" "${want_substr}" "${out}"
    failed=1
    continue
  fi
  printf 'ok   %s\n' "${name}"
done

# The guard must refuse to report success when it verified nothing at all,
# rather than treating an image with no trust stores as compliant.
v="$(variant empty)"; rm -rf "${v:?}/etc" "${v:?}/kaniko"; mkdir -p "${v}/usr"
set +e
out="$("${GUARD}" empty 2>&1)"; got_exit=$?
set -e
if [ "${got_exit}" -eq 0 ] || ! printf '%s' "${out}" | grep -qF "pass vacuously"; then
  printf 'FAIL guard rejects an image where nothing was verified\n     want non-zero and a vacuous-pass error, got exit %s:\n%s\n' \
    "${got_exit}" "${out}"
  failed=1
else
  printf 'ok   guard rejects an image where nothing was verified\n'
fi

# An object id the datastream does not define must abort the run, not fall
# through with an empty pattern.
#
# This is the one failure path where a silent pass is a single edit away.
# `oval_pattern` exits non-zero for an unresolvable id, but its caller consumes
# it as `pattern="$(oval_pattern "${obj_id}")"` and then runs
# `grep -Pq -- "${pattern}"` — and an empty pattern matches anything. So the
# only thing converting "could not read the regex" into a failure is `set -e`
# aborting on the failed command substitution. Wrapping that call in a
# conditional, or appending `|| true`, would turn the format check into a
# no-op that still reports every sidecar as matching. Nothing else in this
# suite would notice, because every other case supplies a datastream where all
# three ids resolve.
#
# The mutation is a realistic one rather than a corrupt file: the datastream
# renames an object and SIDECARS is not updated to follow.
renamed_ds="${WORK}/datastream-obj4-renamed.xml"
sed 's/oval:org\.CABundleHash:obj:4/oval:org.CABundleHash:obj:404/g' \
  "${HERE}/../../gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml" > "${renamed_ds}"
if grep -qF 'oval:org.CABundleHash:obj:4"' "${renamed_ds}"; then
  printf 'FAIL oval_pattern fixture is not what it claims\n     obj:4 still present in %s after the rename\n' "${renamed_ds}"
  failed=1
else
  set +e
  out="$(DATASTREAM="${renamed_ds}" "${GUARD}" clean 2>&1)"; got_exit=$?
  set -e
  if [ "${got_exit}" -eq 0 ]; then
    printf 'FAIL unresolvable OVAL object id aborts the run\n     want non-zero, got exit 0 — an empty pattern matched and the format check silently passed:\n%s\n' \
      "${out}"
    failed=1
  elif ! printf '%s' "${out}" | grep -qF "no pattern for oval:org.CABundleHash:obj:4"; then
    printf 'FAIL unresolvable OVAL object id aborts the run\n     exit %s as expected, but output did not name the unresolvable id:\n%s\n' \
      "${got_exit}" "${out}"
    failed=1
  elif printf '%s' "${out}" | grep -qF "matches oval:org.CABundleHash:obj:4's pattern"; then
    printf 'FAIL unresolvable OVAL object id aborts the run\n     exit %s, but a sidecar was still reported as matching a pattern that could not be read:\n%s\n' \
      "${got_exit}" "${out}"
    failed=1
  else
    printf 'ok   unresolvable OVAL object id aborts the run\n'
  fi
fi

if [ "${failed}" -ne 0 ]; then
  echo "FAILED" >&2
  exit 1
fi
echo "all stamp-guard cases passed"
