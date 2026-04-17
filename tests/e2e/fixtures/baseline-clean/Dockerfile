# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Baseline fixture: a vanilla Chainguard wolfi-base image.
#
# Exercises the "happy path" through the SCAP profile:
#   - RemoteAccessServices: no banned remote-access packages installed
#   - PackageSignature: /etc/apk/repositories contains only https:// entries
#   - LibraryPermissions: /usr/lib owned by root:root
#   - VarLogPermissions: /var/log owned by root:root
#   - NoUsers: no interactive user accounts beyond the image default
#   - CertificateAudit: /etc/ssl/certs/ca-certificates.crt matches the pinned SHA-256
#
# Expected result: a clean scan with no failures attributable to these rules.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:70750dfde91b4c5804b4df269121253fbdff73a9122925c7acc067aa33f9f55e

# Suppress OrbStack's automatic root-CA injection so the baked CA bundle in
# the image is identical to the upstream wolfi-base bundle. Without this, the
# CertificateAudit SHA-256 check would fail on macOS/OrbStack hosts.
# See https://docs.orbstack.dev/features/https.
LABEL dev.orbstack.add-ca-certificates=false
