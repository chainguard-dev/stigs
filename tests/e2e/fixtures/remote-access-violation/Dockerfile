# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Remote-access violation fixture.
#
# Installs openssh-server (a banned remote-access package) so the
# RemoteAccessServices OVAL check must detect the package record under
# /usr/lib/apk/db/installed and every RemoteAccessServices-backed rule
# must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:c0534ee75e0a6bc74bdfef07155049ec435b9e03a706d3545be3130d1a7cd00f

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN apk add --no-cache openssh-server
