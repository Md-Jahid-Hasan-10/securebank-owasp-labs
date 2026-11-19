#!/usr/bin/env python3
"""Apply the Lab 13 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab13.py

The Java fix was written in:
  - lab/a05/Lab13XssController.java   (the note is sanitised on write)
  - frontend/src/features/banking/TransfersPage.jsx   (the note is rendered as text)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 13 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 13 fix text)

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"


def replace_once(path: Path, old: str, new: str, label: str, sentinel: str = "") -> None:
    """Replace `old` with `new`, at most once."""
    text = path.read_text()
    if sentinel and sentinel in text:
        print(f"  already applied: {label}")
        return
    if old not in text:
        print(f"  already applied: {label}")
        return
    path.write_text(text.replace(old, new, 1))
    print(f"  applied: {label}")


# --- 1. verify-labs.sh: invert the Lab 13 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 13: stored XSS -----------------------------------------------------
if should_run 13; then
  lab 13 "Stored XSS"
  OUT="$(post "$API/api/a05/transfers/send" \\
    -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}')"
  check "note with a script payload is stored verbatim" "$OUT" 'onerror=alert'
  OUT="$(get "$API/api/a05/transfers")"
  check "payload is returned to every client" "$OUT" 'onerror=alert'
fi""",
    """# --- Lab 13: stored XSS (FIXED on this branch) -------------------------------
if should_run 13; then
  lab 13 "Stored XSS"
  OUT="$(post "$API/api/a05/transfers/send" \\
    -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}')"
  refute "the note with a script payload is no longer stored verbatim" "$OUT" 'onerror=alert'
  OUT="$(get "$API/api/a05/transfers")"
  refute "the payload is no longer returned to every client" "$OUT" 'onerror=alert'
  refute "the stored note does not contain a raw img tag" "$OUT" '<img'
  # The frontend must render the note as text, not as markup. The source is
  # checked for the JSX attribute itself; the FIXED comment that explains the
  # change mentions it by name, so the attribute is matched only when it is
  # actually used.
  FRONTEND_SRC="$(cat frontend/src/features/banking/TransfersPage.jsx 2>/dev/null || true)"
  refute "the frontend does not use dangerouslySetInnerHTML for the note" \\
    "$FRONTEND_SRC" 'dangerouslySetInnerHTML={'
fi""",
    "verify-labs.sh: Lab 13 expectations inverted",
    sentinel='refute "the note with a script payload is no longer stored verbatim"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 13 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 13: stored XSS =="
check "the note is stored verbatim" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}' \\
     "$API/api/a05/transfers/send")" 'onerror=alert'
check "the note is returned to every client" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a05/transfers")" 'onerror=alert'""",
    """echo "== Lab 13: stored XSS =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}' \\
     "$API/api/a05/transfers/send")" == *'onerror=alert'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the note is still stored verbatim\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the note is no longer stored verbatim\\n'
  PASS=$((PASS + 1))
fi
if [[ "$(curl -s "${AUTH[@]}" "$API/api/a05/transfers")" == *'<img'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the note is still returned with a raw img tag\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the note is no longer returned with a raw img tag\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 13 expectations inverted",
    sentinel="the note is no longer returned with a raw img tag",
)

# --- 3. labs.meta.yaml: the Lab 13 fix text -----------------------------------

replace_once(
    META,
    """      Better still, render the value as plain text and never use
      `dangerouslySetInnerHTML` for user data:

      ```jsx
      <div>{txn.note}</div>
      ```
    source: core/src/main/java/com/securebank/lab/a05/Lab13XssController.java""",
    """      Better still, render the value as plain text and never use
      `dangerouslySetInnerHTML` for user data:

      ```jsx
      <div>{txn.note}</div>
      ```

      **What was changed:** the frontend now renders the note as a plain text
      child, which React escapes, so it can never be interpreted as markup. The
      server sanitises the note on write as well - tags are stripped and the
      remaining angle brackets are escaped - so a note stored before the frontend
      fix was applied is harmless too.
    source: core/src/main/java/com/securebank/lab/a05/Lab13XssController.java""",
    "labs.meta.yaml: Lab 13 fix text",
    sentinel="**What was changed:** the frontend now renders the note as a plain text",
)

print("Lab 13 fix applied.")
