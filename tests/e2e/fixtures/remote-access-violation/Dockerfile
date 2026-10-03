# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs dropbear (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:9c2092b053779e14c82fb50f77b37bcc38b7d2c83972352d5813280f9d035b03

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache dropbear
