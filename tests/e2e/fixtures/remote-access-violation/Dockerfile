# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs dropbear (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:3754b6da0e1ccdab0fe46abfdd7bbbba994b593c28149f6659fa6597f2261aeb

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache dropbear
