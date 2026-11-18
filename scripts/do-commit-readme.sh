#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="docs: describe the main/fixed branch model in the README

main keeps all 25 vulnerabilities live so the labs can be practised; fixed
carries the remediation, with each marker flipped from VULN: to FIXED: so the
lab panel shows the patched code instead of the vulnerable code."

git add README.md
git commit -m "$MSG"
git log --oneline -3
