#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

git add scripts/do-commit-merge-main-into-fixed.sh
git commit -m "chore: track the Lab 6 merge helper on the fixed branch"

git push origin fixed
git log --oneline -3
git status --short
