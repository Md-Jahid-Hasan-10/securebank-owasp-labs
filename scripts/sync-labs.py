#!/usr/bin/env python3
"""Generate the lab panel payload from labs.meta.yaml plus the real Java sources.

The "Affected Code" tab in the UI shows the *current* source of the vulnerable
code, extracted from the Java file at build time. That means the panel can never
drift out of sync with the code, and the future remediation pass gets a reliable
before/after diff for free.

Usage:
    python3 scripts/sync-labs.py

Writes:
    backend/core/src/main/resources/labs/labs.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print(
        "PyYAML is required: pip install pyyaml",
        file=sys.stderr,
    )
    raise SystemExit(1)


ROOT = Path(__file__).resolve().parent.parent
META_PATH = ROOT / "labs" / "labs.meta.yaml"
BACKEND_DIR = ROOT / "backend"
OUT_PATH = BACKEND_DIR / "core" / "src" / "main" / "resources" / "labs" / "labs.json"

# How many lines of context to include around the anchor.
CONTEXT_LINES = 14

VULN_MARKER = re.compile(r"(?:VULN|FIXED):\s*\[(?P<tag>[A-Z0-9\-]+)\]")


def extract_block(source: str, anchor: str, context: int = CONTEXT_LINES) -> str:
    """Return the anchor line plus `context` lines around it, or the file head."""
    lines = source.splitlines()
    for index, line in enumerate(lines):
        if anchor in line:
            start = max(0, index - context)
            end = min(len(lines), index + context + 1)
            return "\n".join(lines[start:end])
    # Anchor not found - fall back to the top of the file rather than failing the build.
    return "\n".join(lines[: context * 2])


def extract_vuln_block(source: str, tag: str, context: int = CONTEXT_LINES) -> str | None:
    """Extract the block around this lab's own marker.

    The marker is `// VULN: [tag]` on the training branch and `// FIXED: [tag]` on
    the solution branch. Anchoring on the marker rather than on a hand-written line
    from the metadata means the "Affected Code" tab always shows the vulnerable
    statement together with the comment that names it, even when the surrounding
    code moves.
    """
    lines = source.splitlines()
    pattern = re.compile(rf"(?:VULN|FIXED):\s*\[{re.escape(tag)}\]")
    for index, line in enumerate(lines):
        if pattern.search(line):
            start = max(0, index - context)
            end = min(len(lines), index + context + 1)
            return "\n".join(lines[start:end])
    return None


def find_vuln_tags(source: str) -> list[str]:
    """Return every VULN tag found in the file, in order, de-duplicated."""
    tags: list[str] = []
    for match in VULN_MARKER.finditer(source):
        tag = match.group("tag")
        if tag not in tags:
            tags.append(tag)
    return tags


def main() -> int:
    if not META_PATH.exists():
        print(f"missing metadata: {META_PATH}", file=sys.stderr)
        return 1

    meta = yaml.safe_load(META_PATH.read_text(encoding="utf-8"))
    labs = meta.get("labs", [])

    categories: list[dict] = []
    seen_categories: dict[str, dict] = {}
    output_labs: list[dict] = []

    for lab in labs:
        lab_id = lab["id"]
        source_rel = lab["source"]
        source_path = BACKEND_DIR / source_rel

        if not source_path.exists():
            print(f"  ! lab {lab_id}: source not found: {source_rel}", file=sys.stderr)
            code = ""
            tags = []
        else:
            source = source_path.read_text(encoding="utf-8")
            tags = find_vuln_tags(source)
            # The lab's own tag is the reliable anchor; the metadata anchor is only
            # a fallback for labs whose source carries no marker.
            code = extract_vuln_block(source, f"A{lab['category'][1:]}-Lab{lab_id}")
            if code is None:
                code = extract_block(source, lab["anchors"][0])

        entry = {
            "id": lab_id,
            "category": lab["category"],
            "categoryName": lab["categoryName"],
            "title": lab["title"],
            "severity": lab["severity"],
            "objective": lab["objective"].strip(),
            "exploit": lab["exploit"].strip(),
            "hint": lab["hint"].strip(),
            "fix": lab["fix"].strip(),
            "source": source_rel,
            "code": code,
            "vulnTags": tags,
        }
        output_labs.append(entry)

        category = lab["category"]
        if category not in seen_categories:
            category_entry = {
                "code": category,
                "name": lab["categoryName"],
                "labs": [],
            }
            seen_categories[category] = category_entry
            categories.append(category_entry)
        seen_categories[category]["labs"].append(lab_id)

    payload = {"categories": categories, "labs": output_labs}

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"wrote {OUT_PATH.relative_to(ROOT)}")
    print(f"  {len(output_labs)} labs across {len(categories)} categories")

    missing = [lab["id"] for lab in labs if not (BACKEND_DIR / lab["source"]).exists()]
    if missing:
        print(f"  ! missing sources for labs: {missing}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
