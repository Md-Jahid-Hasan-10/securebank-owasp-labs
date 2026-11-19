#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="Merge branch 'main' into fixed

Brings the current main branch into the fixed branch before the Lab 6
remediation is applied, so that the solutions branch stays in step with the
training branch.

The only conflict is in the admin console page: main has no password-change
flow, while fixed carries the Lab 5 one. The fixed version is kept, because it
is a strict superset - main simply never touched that part of the file."

git add frontend/src/features/admin/AdminConsolePage.jsx
git add scripts/do-push-fixed-lab4.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
