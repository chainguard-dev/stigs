# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# PackageSignature violation fixture.
#
# Injects a non-https repository URL into /etc/apk/repositories so the
# textfilecontent54 pattern ^(?!\s*#)(?!.*https://).+$ must match at
# least one line and the rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:88a20e2d017bd20cdc0cb3910de603e7bea9512a6c351a8dd3c9df212ab03d73

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '# vendor-mirror\nhttp://insecure.example.com/alpine\n' >> /etc/apk/repositories
