# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs dropbear (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:d69a74aa929a006d05880a9287fbbf89aa278d55d7239955331f239122824ba6

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache dropbear
