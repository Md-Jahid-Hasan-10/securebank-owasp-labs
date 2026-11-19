#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(lab-panel): match the marker tags on the training branch too

The marker pattern in scripts/sync-labs.py only allowed uppercase letters, so
the tag A01-Lab1 never matched and every lab reported an empty tag list in the
generated panel. The 'Affected Code' tab was unaffected, because that path
escapes the tag instead of matching it against a character class.

The pattern now accepts the lowercase letters in 'Lab', so the panel lists the
marker tags for all 25 labs on the vulnerable branch as well as on the fixed
one."

git add scripts/sync-labs.py
git add scripts/do-push-fixed-lab6-helper.sh

git commit -m "$MSG"
git push origin main
git log --oneline -3
git status --short
