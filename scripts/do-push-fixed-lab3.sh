#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

git add scripts/do-commit-fixed-lab3.sh
git commit -m "chore: track the Lab 3 commit helper on the fixed branch"
git push origin fixed
git log --oneline -3
