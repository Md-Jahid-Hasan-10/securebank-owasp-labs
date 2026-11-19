#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

git add scripts/do-push-fixed-lab6.sh
git commit -m "chore: track the Lab 6 push helper on the fixed branch"

git push origin fixed
git log --oneline -2
