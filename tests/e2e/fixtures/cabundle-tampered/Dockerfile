# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CertificateAudit violation fixture.
#
# Appends a bogus trust anchor to /etc/ssl/certs/ca-certificates.crt so
# the SHA-256 of the baked bundle diverges from the pinned value the
# CertificateAudit OVAL check expects. The rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:0cff4df29a6597173dc8b813787318150141eb96ac783dc3ff4f5ff52c49a1e2

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '\n# tampered\n-----BEGIN CERTIFICATE-----\nTAMPERED\n-----END CERTIFICATE-----\n' \
      >> /etc/ssl/certs/ca-certificates.crt
