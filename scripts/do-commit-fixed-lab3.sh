#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(A01-Lab3): validate the callback URL before fetching it

The statement-email feature used the attacker-supplied callback URL verbatim
as the target of a server-side HTTP request. There was no scheme check, no
host allowlist and no protection against private, loopback or link-local
address ranges, so the server could be made to reach services that are
unreachable from the internet: cloud metadata endpoints (169.254.169.254), the
report service on the Docker network, and anything else on the internal
address space.

The URL is now validated in three layers before any request is made:

  - Layer 1, scheme allowlist: only http and https are accepted, so file://,
    gopher:// and jar: cannot be used to read local files or speak other
    protocols.
  - Layer 2, host allowlist: only hosts the application actually needs are
    fetchable.
  - Layer 3, resolved address check: the host is resolved and every address it
    resolves to is checked, not just the first. Checking the hostname string
    is not enough - 'localhost', '127.0.0.1' and a public domain resolving to
    127.0.0.1 all slip past it. The check covers loopback, link-local (which
    includes the cloud metadata range), site-local, 0.0.0.0 and IPv6
    unique-local.

Redirects are also no longer followed. An allowed host could otherwise answer
with a 302 pointing at an internal address and bypass all three layers, since
the checks only run on the original URL.

Every rejection returns the same generic message, so the response does not
reveal whether the guess hit something real.

On this branch the lab marker flips from VULN: to FIXED:, and the Lab 3
expectations in verify-labs.sh and verify-walkthrough.sh are inverted: they now
assert that the exploit FAILS."

git add backend/core/src/main/java/com/securebank/lab/a01/Lab3SsrfController.java
git add labs/labs.meta.yaml
git add scripts/verify-labs.sh
git add scripts/verify-walkthrough.sh
git add scripts/apply-fixed-lab3.py
git add scripts/do-commit-fixed-lab2-script.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
