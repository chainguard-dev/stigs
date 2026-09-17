# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs dropbear (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1d95114038f76513a9ace6fca107d5582b08c65981f81f61cb56bf7fd2ef216d

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache dropbear
