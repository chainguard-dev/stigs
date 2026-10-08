# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# PackageSignature violation fixture.
#
# Injects a non-https repository URL into /etc/apk/repositories so the
# textfilecontent54 pattern ^(?!\s*#)(?!.*https://).+$ must match at
# least one line and the rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:238642d42c5613936474d00b900c4e65fb6f637d8991c913403ff09a09cf43a3

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf '# vendor-mirror\nhttp://insecure.example.com/alpine\n' >> /etc/apk/repositories
