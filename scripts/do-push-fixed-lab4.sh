#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

git add scripts/do-commit-fixed-lab4.sh
git commit -m "chore: track the Lab 4 commit helper on the fixed branch"
git push origin fixed
git log --oneline -4
