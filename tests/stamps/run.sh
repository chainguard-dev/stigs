#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Chainguard
#
# Guards the premise CertificateAudit rests on.
#
# The rule pins no digest. For each trust store it reads the expected SHA-256
# out of a sidecar file the image build writes beside it, then compares. That
# only works while the sidecars keep three properties, none of which this
# repository controls:
#
#   1. they exist,
#   2. their contents match the file they name, and
#   3. they are formatted so the OVAL's own regex matches them.
#
# (3) is the one a plain `sha256sum -c` cannot check: `sha256sum -c` accepts
# filename spellings the regex rejects (an absolute path, say), so a format
# change would sail past a checksum-only guard and start failing the rule on
# clean images. So the patterns are read out of the datastream and applied
# here — the guard cannot drift from the OVAL it is guarding.
#
# Usage:
#   tests/stamps/run.sh [image-ref ...]
#
# Environment:
#   DATASTREAM  path to the datastream (default: the in-repo one)
#   STAMP_IMAGES  space-separated default image list when no args are given
#   STAMP_DIGEST_FILE  if set, each verified trust store is appended to this
#                      file as "<path> <sha256>", for a caller that wants to
#                      report the digests without exporting the image again
#
# Exits non-zero, naming the trust store, on the first violation.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATASTREAM="${DATASTREAM:-${REPO_ROOT}/gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml}"

# jre carries both of the sidecars the rule reads on a public image — the
# system CA bundle's and the Java truststore's — so one export covers both.
# wolfi-base has no Java and would leave the truststore criterion unguarded.
DEFAULT_IMAGES="${STAMP_IMAGES:-cgr.dev/chainguard/jre:latest}"

# Sidecars the OVAL reads, and whether the rule tolerates one being absent.
#
#   <oval object id>|<dir>|<sidecar>|<trust store>|<required>
#
# required=yes  the criteria demand the sidecar (tst:4, tst:6), so a trust
#               store present without one is a failure.
# required=no   the criteria accept its absence and fall back to the system
#               sidecar (tst:13 + tst:9), so only a present-but-wrong sidecar
#               is a failure.
#
# /kaniko is listed for completeness but is not reachable on a public image;
# see the coverage note printed at the end of a run.
SIDECARS=(
  "oval:org.CABundleHash:obj:4|etc/ssl/certs|.ca-certificates.crt.sha256|ca-certificates.crt|yes"
  "oval:org.CABundleHash:obj:6|etc/ssl/certs/java|.cacerts.sha256|cacerts|yes"
  "oval:org.CABundleHash:obj:10|kaniko/ssl/certs|.ca-certificates.crt.sha256|ca-certificates.crt|no"
)

die() {
  # ::error:: is picked up as an annotation under Actions and is harmless
  # otherwise, so the same script serves CI and a local run.
  echo "::error::$*" >&2
  exit 1
}

note() { echo "  $*"; }

# Print the <pattern> the datastream gives an OVAL object, so this guard
# asserts the regex the scanner will actually apply rather than a copy of it.
oval_pattern() {
  local obj_id="$1"
  # The parsed input is this repository's own datastream, not untrusted data,
  # so the stdlib parser is used rather than taking on a defusedxml dependency.
  python3 - "$DATASTREAM" "$obj_id" <<'PY'
import sys, xml.etree.ElementTree as ET
ds, obj_id = sys.argv[1], sys.argv[2]
local = lambda e: e.tag.split('}')[-1]
for e in ET.parse(ds).iter():
    if local(e) == 'textfilecontent54_object' and e.get('id') == obj_id:
        for c in e:
            if local(c) == 'pattern':
                print((c.text or '').strip())
                sys.exit(0)
sys.exit(f"no pattern for {obj_id} in {ds}")
PY
}

check_image() {
  local ref="$1" workdir checked=0
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand workdir now, not at trap time
  trap "rm -rf '${workdir}'" RETURN

  echo "== ${ref}"

  # Extract the containing directories rather than naming each file. `tar -x
  # <member>` exits 2 when a member is absent from the archive, which under
  # `set -e` would kill this function before the per-file checks below could
  # say *which* sidecar was missing — the exact diagnosis this guard exists to
  # produce. Directories that the image does not have are simply not extracted.
  local dirs=() seen=""
  local entry dir
  for entry in "${SIDECARS[@]}"; do
    dir="$(echo "${entry}" | cut -d'|' -f2)"
    case " ${seen} " in *" ${dir} "*) continue ;; esac
    seen="${seen} ${dir}"
    dirs+=("${dir}")
  done

  # A missing directory is not an error here (no Java, no /kaniko), so ask tar
  # for each separately and let absence be silent. `|| true` is safe because
  # every file is then explicitly accounted for below.
  local tarball="${workdir}/image.tar"
  crane export "${ref}" - > "${tarball}" \
    || die "could not export ${ref}"
  for dir in "${dirs[@]}"; do
    tar -C "${workdir}" -xf "${tarball}" "${dir}" 2>/dev/null || true
  done
  rm -f "${tarball}"

  for entry in "${SIDECARS[@]}"; do
    local obj_id sidecar store required pattern
    obj_id="$(echo "${entry}" | cut -d'|' -f1)"
    dir="$(echo "${entry}" | cut -d'|' -f2)"
    sidecar="$(echo "${entry}" | cut -d'|' -f3)"
    store="$(echo "${entry}" | cut -d'|' -f4)"
    required="$(echo "${entry}" | cut -d'|' -f5)"

    # No trust store at this path means the rule has nothing to verify here.
    if [ ! -f "${workdir}/${dir}/${store}" ]; then
      note "${dir}/${store}: absent, nothing to verify"
      continue
    fi

    if [ ! -f "${workdir}/${dir}/${sidecar}" ]; then
      if [ "${required}" = "yes" ]; then
        die "${dir}/${sidecar} missing from ${ref}, but ${dir}/${store} is present; CertificateAudit will fail on clean images"
      fi
      note "${dir}/${sidecar}: absent, permitted (rule falls back to the system sidecar)"
      continue
    fi

    # (3) format: the regex the OVAL will apply must match this sidecar.
    pattern="$(oval_pattern "${obj_id}")"
    if ! grep -Pq -- "${pattern}" "${workdir}/${dir}/${sidecar}"; then
      die "${dir}/${sidecar} in ${ref} does not match the pattern ${obj_id} applies (${pattern}); CertificateAudit will fail on clean images"
    fi

    # (2) contents: the digest must describe the file it names.
    if ! (cd "${workdir}/${dir}" && sha256sum -c "${sidecar}" >/dev/null); then
      die "${dir}/${store} in ${ref} does not match the digest in ${sidecar}; CertificateAudit will fail on clean images"
    fi

    note "${dir}/${store}: matches ${sidecar}, and ${sidecar} matches ${obj_id}'s pattern"
    if [ -n "${STAMP_DIGEST_FILE:-}" ]; then
      printf '%s %s\n' "${dir}/${store}" \
        "$(sha256sum "${workdir}/${dir}/${store}" | cut -d' ' -f1)" \
        >> "${STAMP_DIGEST_FILE}"
    fi
    checked=$((checked + 1))
  done

  [ "${checked}" -gt 0 ] \
    || die "no trust store was verified in ${ref}; the guard checked nothing and would pass vacuously"
}

main() {
  local images=("$@")
  [ "${#images[@]}" -gt 0 ] || read -r -a images <<<"${DEFAULT_IMAGES}"

  for ref in "${images[@]}"; do
    check_image "${ref}"
  done

  # Say what was not covered, so a green run is not read as "the whole rule's
  # premise is guarded".
  cat <<'EOF'

Not covered by this guard:
  - /kaniko/ssl/certs — only present on cgr.dev/chainguard-private/kaniko,
    which needs registry credentials this workflow does not have.
  - var/lib/ecs/deps/execute-command/certs/tls-ca-bundle.pem — the image build
    writes a sidecar for it, but CertificateAudit does not read it, so there is
    no premise to guard yet.
EOF
}

main "$@"
