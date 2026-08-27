# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# CertificateAudit kaniko-layout fixture.
#
# Mirrors the trust store layout cgr.dev/chainguard/kaniko ships: the CA bundle
# is copied to /kaniko/ssl/certs/ca-certificates.crt and SSL_CERT_FILE names
# that copy instead of /etc/ssl/certs/ca-certificates.crt. No stamp file is
# copied alongside it, because the kaniko image ships none there either.
#
# CertificateAudit accepts the alternative location only when the copy carries
# the digest the ca-certificates stamp file at /etc/ssl/certs records, which an
# untouched copy does. The rule must therefore PASS.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:19f7a7b40a11c435311e3784bd134c6b6f19677462440da48f96d5c84eefd669

# Suppress OrbStack's automatic root-CA injection so the bundle (and the copy
# taken from it) is identical to the upstream wolfi-base bundle the stamp file
# describes. Without this, the CertificateAudit SHA-256 check would fail on
# macOS/OrbStack hosts.
# See https://docs.orbstack.dev/features/https.
LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN mkdir -p /kaniko/ssl/certs \
      && cp /etc/ssl/certs/ca-certificates.crt /kaniko/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/kaniko/ssl/certs/ca-certificates.crt
