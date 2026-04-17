#!/usr/bin/env bash
# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end test harness for the Chainguard GPOS SRG datastream.
#
# For each fixture under tests/e2e/fixtures/<name>/ the harness:
#   1. Builds the fixture's Dockerfile into a tagged image.
#   2. Runs `oscap-docker image <tag> xccdf eval` with the in-repo
#      datastream, writing results.xml to tests/e2e/out/<name>/.
#   3. Parses results.xml and checks that every rule listed in
#      tests/e2e/fixtures/<name>/expected.txt produced the expected
#      XCCDF result (pass / fail / notapplicable).
#
# Exit code is non-zero if any fixture fails to build, scan, or match
# its expected results. Output is newline-delimited and safe to stream
# in CI logs.
#
# Usage:
#   tests/e2e/run.sh              # run every fixture
#   tests/e2e/run.sh <fixture>    # run a single fixture
#
# Environment variables:
#   SCAP_IMAGE    oscap-docker scan image (default: cgr.dev/chainguard/openscap:latest-dev)
#   DATASTREAM    path to datastream (default: gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml)
#   PROFILE       XCCDF profile ID (default: xccdf_basic_profile_.check)
#   FIXTURES_DIR  fixtures root (default: tests/e2e/fixtures)
#   OUT_DIR       results root (default: tests/e2e/out)
#   KEEP_IMAGES   if set, skip `docker image rm` of fixture images
set -euo pipefail

# Resolve repo root (assumes this script lives at tests/e2e/run.sh).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

SCAP_IMAGE="${SCAP_IMAGE:-cgr.dev/chainguard/openscap:latest-dev}"
DATASTREAM="${DATASTREAM:-gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml}"
PROFILE="${PROFILE:-xccdf_basic_profile_.check}"
FIXTURES_DIR="${FIXTURES_DIR:-tests/e2e/fixtures}"
OUT_DIR="${OUT_DIR:-tests/e2e/out}"

if [[ ! -f "${DATASTREAM}" ]]; then
  echo "::error::datastream not found: ${DATASTREAM}" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "::error::docker is required but not found on PATH" >&2
  exit 2
fi

# Pre-pull the scan image so individual fixture runs are faster.
echo "== pulling scan image: ${SCAP_IMAGE} =="
docker pull --quiet "${SCAP_IMAGE}" >/dev/null

# Determine fixture list.
if [[ $# -gt 0 ]]; then
  FIXTURES=("$@")
else
  mapfile -t FIXTURES < <(find "${FIXTURES_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
fi

if [[ ${#FIXTURES[@]} -eq 0 ]]; then
  echo "::error::no fixtures found under ${FIXTURES_DIR}" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

# Parse an XCCDF results.xml and extract the XCCDF result string for a
# given rule id. Prints one of: pass / fail / error / unknown / notapplicable
# / notchecked / notselected / informational / fixed, or "missing" if the
# rule wasn't present in the results.
#
# Uses xmlstarlet if available, falls back to Python.
extract_rule_result() {
  local results_xml="$1"
  local rule_id="$2"
  if command -v xmlstarlet >/dev/null 2>&1; then
    xmlstarlet sel -N x="http://checklists.nist.gov/xccdf/1.2" \
      -t -v "(//x:rule-result[@idref='${rule_id}']/x:result)[1]" \
      -n "${results_xml}" 2>/dev/null | head -n1 | tr -d '[:space:]' || true
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "${results_xml}" "${rule_id}" <<'PY'
import sys
import xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
root = tree.getroot()
ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
rid = sys.argv[2]
for rr in root.iter("{http://checklists.nist.gov/xccdf/1.2}rule-result"):
    if rr.attrib.get("idref") == rid:
        res = rr.find("x:result", ns)
        if res is not None and res.text is not None:
            print(res.text.strip())
            sys.exit(0)
print("missing")
PY
  else
    echo "::error::need xmlstarlet or python3 to parse results" >&2
    exit 2
  fi
}

overall_rc=0
summary=()

for fixture in "${FIXTURES[@]}"; do
  dir="${FIXTURES_DIR}/${fixture}"
  dockerfile="${dir}/Dockerfile"
  expected="${dir}/expected.txt"

  if [[ ! -f "${dockerfile}" ]]; then
    echo "::error::${fixture}: missing Dockerfile" >&2
    overall_rc=1
    summary+=("FAIL ${fixture} (no Dockerfile)")
    continue
  fi
  if [[ ! -f "${expected}" ]]; then
    echo "::error::${fixture}: missing expected.txt" >&2
    overall_rc=1
    summary+=("FAIL ${fixture} (no expected.txt)")
    continue
  fi

  tag="stigs-e2e/${fixture}:test"
  out_sub="${OUT_DIR}/${fixture}"
  mkdir -p "${out_sub}"

  echo
  echo "== ${fixture}: build =="
  docker build --quiet -t "${tag}" -f "${dockerfile}" "${dir}" >/dev/null

  echo "== ${fixture}: scan =="
  # Mount the repo at /src so oscap can read the in-repo datastream
  # without needing the datastream to be baked into the scan image.
  # The `dev.orbstack.add-ca-certificates=false` label prevents OrbStack
  # from injecting its root CA into the scanner container on macOS hosts;
  # without it, the scanner's own CA bundle would diverge from expected
  # and could skew CertificateAudit assertions.
  set +e
  docker run --rm -u 0:0 --pid=host \
    -l dev.orbstack.add-ca-certificates=false \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${REPO_ROOT}:/src:ro" \
    -v "${REPO_ROOT}/${out_sub}:/out" \
    --entrypoint sh \
    "${SCAP_IMAGE}" -c "
      oscap-docker image '${tag}' xccdf eval \
        --profile '${PROFILE}' \
        --results /out/results.xml \
        --report /out/report.html \
        '/src/${DATASTREAM}'
    "
  scan_rc=$?
  set -e
  # oscap xccdf eval returns 2 when at least one rule fails — that is a
  # valid outcome for violation fixtures, so we only bail on 1 (error) or
  # >=3 (unexpected).
  if [[ ${scan_rc} -ne 0 && ${scan_rc} -ne 2 ]]; then
    echo "::error::${fixture}: oscap-docker exited ${scan_rc}" >&2
    overall_rc=1
    summary+=("FAIL ${fixture} (oscap rc=${scan_rc})")
    continue
  fi

  if [[ ! -f "${out_sub}/results.xml" ]]; then
    echo "::error::${fixture}: results.xml not produced" >&2
    overall_rc=1
    summary+=("FAIL ${fixture} (no results)")
    continue
  fi

  fixture_rc=0
  while IFS= read -r raw_line; do
    # Strip comments and surrounding whitespace.
    line="${raw_line%%#*}"
    line="$(echo "${line}" | xargs || true)"
    [[ -z "${line}" ]] && continue

    rule_id="${line%%=*}"
    want="${line#*=}"
    got="$(extract_rule_result "${out_sub}/results.xml" "${rule_id}")"
    got="${got:-missing}"

    if [[ "${got}" == "${want}" ]]; then
      echo "  [ok]  ${rule_id}: ${got}"
    else
      echo "  [XX]  ${rule_id}: want=${want} got=${got}"
      fixture_rc=1
    fi
  done < "${expected}"

  if [[ -z "${KEEP_IMAGES:-}" ]]; then
    docker image rm "${tag}" >/dev/null 2>&1 || true
  fi

  if [[ ${fixture_rc} -eq 0 ]]; then
    summary+=("PASS ${fixture}")
  else
    overall_rc=1
    summary+=("FAIL ${fixture}")
  fi
done

echo
echo "== summary =="
for line in "${summary[@]}"; do
  echo "  ${line}"
done

exit "${overall_rc}"
