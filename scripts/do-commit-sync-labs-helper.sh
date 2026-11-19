#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

git add scripts/do-commit-sync-labs-fix.sh

git commit -m "chore: track the lab panel regex commit helper on main"

git push origin main
git log --oneline -2
git status --short
