# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs openssh-server (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:cb2fc9d795bf874e660dbc25958cfa699b55e789235896ec7c354c57d3e3a704

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache openssh-server
