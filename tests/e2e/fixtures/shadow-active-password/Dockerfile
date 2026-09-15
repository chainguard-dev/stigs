# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# UserPasswordConfigured violation fixture.
#
# Appends a /etc/shadow entry whose password field is a traditional
# DES-style crypt hash ("ZZx/p0vU8jVbA") — an active password that does
# NOT begin with "$". The old ^[^:]+:\$[^\n]*: pattern only matched
# "$"-prefixed hashes and would have let this slip through; the corrected
# ^[^:]+:(?![!*])[^:\n]*: pattern matches any unlocked field, so the
# UserPasswordConfigured rule must FAIL.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:9a8d954d8f03a21bcf2be73d4628f0ad26d35c3275469925de63a34eebd58f13

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf 'compliance-test:ZZx/p0vU8jVbA:19000:0:99999:7:::\n' >> /etc/shadow
