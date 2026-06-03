# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# PackageSignature violation fixture.
#
# Injects a non-https repository URL into /etc/apk/repositories so the
# textfilecontent54 pattern ^(?!\s*#)(?!.*https://).+$ must match at
# least one line and the rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:cb2fc9d795bf874e660dbc25958cfa699b55e789235896ec7c354c57d3e3a704

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '# vendor-mirror\nhttp://insecure.example.com/alpine\n' >> /etc/apk/repositories
