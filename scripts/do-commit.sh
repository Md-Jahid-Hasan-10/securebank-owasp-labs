#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="infra: track the Lab 6 fixture under lab-fixtures/ and support FIXED: markers

Git refuses to track any path containing a '.git' component - not even with
'git add -f' or 'git update-index --cacheinfo' - so the Lab 6 fixture could
never be committed at static/.git/config and Lab 6 was broken for anyone
cloning the repo. It now lives at
backend/core/src/main/resources/lab-fixtures/git-config and the Dockerfile
renames it to /app/static/.git/config inside the image, so the served path is
still /.git/config.

sync-labs.py and check-labs-json.py now anchor on 'VULN:' or 'FIXED:' so the
in-app Affected Code tab works on both the training branch and the solution
branch."

git commit -m "$MSG"
git log --oneline -3
