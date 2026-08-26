#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Chainguard
#


# validate the individual Oval check definitions
validate_checks:
	@$(foreach check, $(wildcard gpos/xml/scap/ssg/content/ssg-chainguard-xccdf/OvalDefinitions/*.xml), $(call validate,$(check)) ; )

# validate the combined gpos srg xml file
# This unfortunately fails with the current xml
validate_xml:
	@$(call validate,gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml)

validate: validate_checks validate_xml

# Compare each standalone OVAL check against its copy inside the datastream.
# The standalone files are the source the datastream is generated from
# (chainguard-dev/oscap-playground embeds each one verbatim), but between SRG
# bumps the datastream is edited by hand and nothing runs the generator, so the
# two drift and it is the generated artifact that ships. validate_checks and
# validate_xml only ever check each copy against its schema in isolation, so
# neither notices. Differences that would change a scan verdict fail; purely
# descriptive ones are logged.
#
# Runs as part of `make test-offline` too, since that runs the whole module.
validate_mirrors:
	cd tests/oscap-offline && go test -count=1 ./internal/mirrors/

.PHONY: validate validate_xml validate_checks validate_mirrors

# End-to-end scan harness. Each fixture under tests/e2e/fixtures/<name>/
# builds a container image, runs oscap-docker against the in-repo datastream,
# and asserts the XCCDF rule outcomes in tests/e2e/fixtures/<name>/expected.txt.
test-e2e:
	@tests/e2e/run.sh

# Run a single fixture, e.g. `make test-e2e-non-https-repo`.
test-e2e-%:
	@tests/e2e/run.sh $*

.PHONY: test-e2e

# Fast offline scan tier. Runs the tests/oscap-offline Go harness, which
# scans an extracted rootfs with oscap pointed at it via OSCAP_PROBE_ROOT
# (no privileged oscap-docker, no docker socket mount). Drives a per-OVAL-
# definition pass+fail matrix and asserts the XCCDF rule verdicts.
test-offline:
	cd tests/oscap-offline && go test -race -count=1 ./...

# Clear the Go test cache so the next `test-offline` re-runs every scan from
# scratch. The harness caches base tar(s) under a per-run temp dir (t.TempDir),
# so there is no persistent on-disk cache to remove; clearing the test cache is
# what forces a full re-scan.
test-offline-clean:
	cd tests/oscap-offline && go clean -testcache

.PHONY: test-offline test-offline-clean

# Formatting and static analysis for the Go test tooling. Neither was gated
# anywhere until now: CI ran `go test` only, so an unformatted file reached main
# unnoticed.
#
# gofmt -l is checked by its output rather than its exit status on purpose — it
# exits 0 whether or not it lists anything, so `gofmt -l . && ...` silently
# succeeds on unformatted input. `go test` runs only a subset of vet, so vet is
# run in full here to cover the rest.
lint-go:
	@cd tests/oscap-offline && \
	  unformatted=$$(gofmt -l .); \
	  if [ -n "$$unformatted" ]; then \
	    echo "::error::gofmt: these files are not formatted; run 'gofmt -w' on them:"; \
	    echo "$$unformatted" | sed 's/^/  /'; \
	    exit 1; \
	  fi; \
	  echo "gofmt: clean"; \
	  go vet ./... && echo "go vet: clean"

.PHONY: lint-go

# Trust-store sidecar guard. CertificateAudit pins no digest; it reads each
# expected value from a sidecar file the image build writes beside the trust
# store. This target checks that premise against a real image: the sidecars
# exist, agree with the files they name, and are formatted so the OVAL's own
# regex (read from the datastream, not copied) matches them. The daily
# update-ca-cert workflow runs the same script.
#
# Override the images with STAMP_IMAGES="ref [ref ...]".
test-stamps:
	@tests/stamps/run.sh

# Exercise the guard's failure paths against synthetic images, with `crane`
# stubbed so no registry or network is needed. These are the paths a green
# daily run never reaches.
test-stamps-selftest:
	@tests/stamps/run_test.sh

.PHONY: test-stamps test-stamps-selftest

# Extract the XCCDF Benchmark block from the datastream and diff it
# against BASE_REF (default: origin/main). STIGViewer v3 loads the full
# datastream directly, so this target's job is to surface content drift
# in the Benchmark (titles, descriptions, fix text) that a reviewer
# should eyeball in STIGViewer before tagging a release.
#
# Outputs land under tests/e2e/out/stigviewer/ (already gitignored).
BASE_REF ?= origin/main
DATASTREAM := gpos/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml
STIGVIEWER_OUT := tests/e2e/out/stigviewer

stigviewer-check:
	@rm -rf "$(STIGVIEWER_OUT)"
	@mkdir -p "$(STIGVIEWER_OUT)"
	@echo "=== extracting current-branch Benchmark ==="
	@awk '/<ns0:Benchmark/,/<\/ns0:Benchmark>/' "$(DATASTREAM)" \
	  > "$(STIGVIEWER_OUT)/current.xccdf.xml"
	@echo "=== extracting $(BASE_REF) Benchmark ==="
	@git show "$(BASE_REF):$(DATASTREAM)" \
	  | awk '/<ns0:Benchmark/,/<\/ns0:Benchmark>/' \
	  > "$(STIGVIEWER_OUT)/base.xccdf.xml"
	@echo "=== benchmark diff (base -> current) ==="
	@diff -u "$(STIGVIEWER_OUT)/base.xccdf.xml" "$(STIGVIEWER_OUT)/current.xccdf.xml" || true
	@echo
	@echo "STIGViewer: load the full datastream directly ($(DATASTREAM))."

.PHONY: stigviewer-check

# function to run oscap, fall back to running in docker if not available locally
# (busybox 'which' does not support -s, hence the /dev/null redirection
validate = echo "=== checking $(1) ===" && if which oscap 2>&1 >/dev/null ; then \
             oscap xccdf validate $(1) ; \
	   else \
             docker run -i --rm -v $$(pwd)/:/in cgr.dev/chainguard/openscap:latest-dev xccdf validate /in/$(1) ; \
	   fi
