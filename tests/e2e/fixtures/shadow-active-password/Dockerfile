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
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:fac38d12efdb4bf43ac9e599a31db10a27ad5dd71e5f1618790962eda8d66180

LABEL dev.orbstack.add-ca-certificates=false

USER root

RUN printf 'compliance-test:ZZx/p0vU8jVbA:19000:0:99999:7:::\n' >> /etc/shadow
