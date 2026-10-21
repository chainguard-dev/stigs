# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs dropbear (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache dropbear
