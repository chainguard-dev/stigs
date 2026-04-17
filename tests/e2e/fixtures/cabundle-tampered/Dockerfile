# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CertificateAudit violation fixture.
#
# Appends a bogus trust anchor to /etc/ssl/certs/ca-certificates.crt so
# the SHA-256 of the baked bundle diverges from the pinned value the
# CertificateAudit OVAL check expects. The rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1af610c4a70668dad46159ee178b20378c79a49b554f76405670fc442d30183a

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '\n# tampered\n-----BEGIN CERTIFICATE-----\nTAMPERED\n-----END CERTIFICATE-----\n' \
      >> /etc/ssl/certs/ca-certificates.crt
