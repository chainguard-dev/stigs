# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs openssh-server (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:70750dfde91b4c5804b4df269121253fbdff73a9122925c7acc067aa33f9f55e

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache openssh-server
