# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# PackageSignature violation fixture.
#
# Injects a non-https repository URL into /etc/apk/repositories so the
# textfilecontent54 pattern ^(?!\s*#)(?!.*https://).+$ must match at
# least one line and the rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:4cf5932a0f95a88af352f77e4efa67480cab0e1f7a48f0eddca3cce003a7c0fb

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '# vendor-mirror\nhttp://insecure.example.com/alpine\n' >> /etc/apk/repositories
