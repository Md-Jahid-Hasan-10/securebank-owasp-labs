#!/usr/bin/env python3
"""Sanity-check the generated labs.json that the frontend panel consumes."""
import json
import sys
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost/api/labs"

with urllib.request.urlopen(URL, timeout=10) as resp:
    payload = json.load(resp)

# /api/labs returns the whole labs.json map: {"categories": [...], "labs": [...]}
labs = payload["labs"] if isinstance(payload, dict) else payload

print("labs:", len(labs))

problems = []
for lab in labs:
    for key in ("id", "category", "title", "severity", "objective",
                "exploit", "hint", "fix", "code", "source"):
        if key not in lab:
            problems.append(f"lab {lab.get('id')}: missing '{key}'")
    if not lab.get("code"):
        problems.append(f"lab {lab.get('id')}: empty affected-code block")
    tag = f"[A{str(lab.get('category', ''))[1:]}-Lab{lab.get('id')}]"
    if tag not in (lab.get("code") or ""):
        problems.append(f"lab {lab.get('id')}: code block has no {tag} marker")

first = labs[0]
print("keys:", sorted(first.keys()))
print("sample:", first["id"], "|", first["title"], "|", first["severity"])
print("code length (lab 1):", len(first["code"]))

cats = {}
for lab in labs:
    cats.setdefault(lab["category"], []).append(lab["id"])
print("categories:", {k: v for k, v in sorted(cats.items())})

if problems:
    print("\nPROBLEMS:")
    for p in problems:
        print("  -", p)
    sys.exit(1)

print("\nOK - every lab has all fields and a populated affected-code block.")
