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

# function to run oscap, fall back to running in docker if not available locally
# (busybox 'which' does not support -s, hence the /dev/null redirection
validate = echo "=== checking $(1) ===" && if which oscap 2>&1 >/dev/null ; then \
             oscap xccdf validate $(1) ; \
	   else \
             docker run -i --rm -v $$(pwd)/:/in cgr.dev/chainguard/openscap:latest-dev xccdf validate /in/$(1) ; \
	   fi
