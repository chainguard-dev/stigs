# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CertificateAudit violation fixture.
#
# Appends a bogus trust anchor to /etc/ssl/certs/ca-certificates.crt without
# touching the ca-certificates stamp file, so the SHA-256 of the baked bundle
# diverges from the digest recorded in /etc/ssl/certs/.ca-certificates.crt.sha256
# that the CertificateAudit OVAL check compares it against. The rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:b6bfe8564bb0630778b04df06b42e78acf221e9540703cfc03d040ab7f91e357

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '\n# tampered\n-----BEGIN CERTIFICATE-----\nTAMPERED\n-----END CERTIFICATE-----\n' \
      >> /etc/ssl/certs/ca-certificates.crt
