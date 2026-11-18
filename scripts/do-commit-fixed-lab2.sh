#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(A01-Lab2): require the admin role on the admin endpoints

Both /api/a01/admin/users and /api/a01/admin/accounts accepted any
authenticated principal. The filter confirmed that a token existed but never
checked the role it carried, so a regular customer could list every user in
the system - including their MD5 password hashes - and every account with its
balance.

The fix checks the caller's role before the query runs, so a non-admin gets
403 and no user row is ever serialised into the response. The check lives in a
single requireAdmin() helper that both endpoints call, because a per-endpoint
check is exactly the kind of thing that gets forgotten when the next admin
endpoint is added.

The Labs 8 and 21 checks used /api/a01/admin/users as their probe, which now
correctly refuses a customer. They move to /api/a10/transfers/history, which
echoes back the principal the filter resolved, so those labs stay independent
of this fix.

On this branch the lab marker flips from VULN: to FIXED:, and the Lab 2
expectations in verify-labs.sh and verify-walkthrough.sh are inverted: they now
assert that the exploit FAILS."

git add backend/core/src/main/java/com/securebank/lab/a01/Lab2PrivilegeEscalationController.java
git add labs/labs.meta.yaml
git add scripts/verify-labs.sh
git add scripts/verify-walkthrough.sh
git add scripts/apply-fixed-lab2.py
git add scripts/do-commit-readme.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
