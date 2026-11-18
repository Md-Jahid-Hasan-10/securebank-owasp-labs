#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

echo "=== switching to fixed ==="
git switch fixed

echo "=== merging main into fixed ==="
if git merge main --no-edit; then
    echo "merge: clean"
else
    echo "merge: CONFLICT - aborting"
    git merge --abort
    exit 1
fi

echo "=== applying the Lab 1 solution ==="
python3 scripts/apply-fixed-lab1.py

echo "=== regenerating the lab panel payload ==="
python3 scripts/sync-labs.py

echo
echo "=== fixed branch state ==="
git log --oneline -3
git status --short
