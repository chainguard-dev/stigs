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

.PHONY: validate validate_xml validate_checks

# End-to-end scan harness. Each fixture under tests/e2e/fixtures/<name>/
# builds a container image, runs oscap-docker against the in-repo datastream,
# and asserts the XCCDF rule outcomes in tests/e2e/fixtures/<name>/expected.txt.
test-e2e:
	@tests/e2e/run.sh

# Run a single fixture, e.g. `make test-e2e-non-https-repo`.
test-e2e-%:
	@tests/e2e/run.sh $*

.PHONY: test-e2e

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
