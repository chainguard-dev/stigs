# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs dropbear (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:b6bfe8564bb0630778b04df06b42e78acf221e9540703cfc03d040ab7f91e357

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache dropbear
