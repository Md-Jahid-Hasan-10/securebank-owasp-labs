#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(A01-Lab1): enforce object-level authorization on account lookup

The account was fetched by primary key only and the owning user_id was never
compared against the authenticated caller, so any logged-in customer could read
any account in the system.

The fix loads the account, then rejects the request unless account.user_id
equals the caller's id. A mismatch returns 404 with the same 'Account not
found' body as a genuinely missing account, so a caller cannot distinguish
'exists but not yours' from 'does not exist' - that difference is itself an
enumeration oracle (see Lab 16).

On this branch the lab marker flips from VULN: to FIXED:, and the Lab 1
expectations in verify-labs.sh and verify-walkthrough.sh are inverted: they now
assert that the exploit FAILS."

git add backend/core/src/main/java/com/securebank/lab/a01/Lab1IdorController.java
git add labs/labs.meta.yaml
git add scripts/apply-fixed-lab1.py
git add scripts/check-labs-json.py
git add scripts/verify-labs.sh
git add scripts/verify-walkthrough.sh
git add scripts/do-branch-fixed.sh
git add scripts/do-commit.sh
git add scripts/do-commit-fixed.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
