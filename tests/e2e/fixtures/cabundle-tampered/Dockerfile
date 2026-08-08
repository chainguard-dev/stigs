# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CertificateAudit violation fixture.
#
# Appends a bogus trust anchor to /etc/ssl/certs/ca-certificates.crt so
# the SHA-256 of the baked bundle diverges from the pinned value the
# CertificateAudit OVAL check expects. The rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:c0534ee75e0a6bc74bdfef07155049ec435b9e03a706d3545be3130d1a7cd00f

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '\n# tampered\n-----BEGIN CERTIFICATE-----\nTAMPERED\n-----END CERTIFICATE-----\n' \
      >> /etc/ssl/certs/ca-certificates.crt
