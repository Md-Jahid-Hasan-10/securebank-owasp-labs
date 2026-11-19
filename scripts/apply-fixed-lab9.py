#!/usr/bin/env python3
"""Apply the Lab 9 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab9.py

The Java fix was written in:
  - lab/a04/Lab9PiiController.java   (masked response fields, PII-free logging)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 9 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 9 fix text)

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"


def replace_once(path: Path, old: str, new: str, label: str, sentinel: str = "") -> None:
    """Replace `old` with `new`, at most once.

    The patched form carries a sentinel (a comment that only exists in the
    new text). If the sentinel is already in the file the patch has been
    applied, which keeps the script idempotent even when the new block
    contains the old block as a prefix.
    """
    text = path.read_text()
    if sentinel and sentinel in text:
        print(f"  already applied: {label}")
        return
    if old not in text:
        print(f"  already applied: {label}")
        return
    path.write_text(text.replace(old, new, 1))
    print(f"  applied: {label}")


# --- 1. verify-labs.sh: invert the Lab 9 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 9: PII in cleartext ------------------------------------------------
if should_run 9; then
  lab 9 "PII in cleartext responses"
  OUT="$(get "$API/api/a04/profile")"
  check "full account number is returned" "$OUT" '"account_number":"ACC-1001"'
  check "sort code is returned" "$OUT" '"sort_code"'
fi""",
    """# --- Lab 9: PII in cleartext (FIXED on this branch) --------------------------
if should_run 9; then
  lab 9 "PII in cleartext responses"
  OUT="$(get "$API/api/a04/profile")"
  refute "the full account number is not returned" "$OUT" '"account_number":"ACC-1001"'
  check "the account number is masked" "$OUT" '"account_number":"ACC-****1001"'
  refute "the full sort code is not returned" "$OUT" '"sort_code":"20-00-00"'
  check "the sort code is masked" "$OUT" '"sort_code":"20-**-**"'
  refute "the full name is not returned" "$OUT" '"full_name":"Alice Morgan"'
  refute "the full email address is not returned" "$OUT" '"email":"alice@bank.com"'
  refute "the balance is not returned" "$OUT" '"balance"'
  # The PII must not be written to the application log either.
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'account_number=' || true)"
  refute "the log does not contain the account number" "$OUT" "1"
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'profile lookup.*balance=' || true)"
  refute "the log does not contain the balance" "$OUT" "1"
  # The lookup must still be logged, so the request can be audited. The count grows
  # with every run, so test for presence rather than for an exact number.
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'profile lookup' || true)"
  if [[ "${OUT:-0}" -gt 0 ]]; then
    green "the profile lookup is still logged"
    PASS=$((PASS + 1))
  else
    red "the profile lookup is no longer logged"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
fi""",
    "verify-labs.sh: Lab 9 expectations inverted",
    sentinel='check "the account number is masked"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 9 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 9: PII =="
check "GET /api/a04/profile leaks the account number" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a04/profile")" '"account_number":"ACC-1001"'""",
    """echo "== Lab 9: PII =="
if [[ "$(curl -s "${AUTH[@]}" "$API/api/a04/profile")" == *'"account_number":"ACC-1001"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m GET /api/a04/profile leaks the account number\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m GET /api/a04/profile does not leak the account number\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 9 expectation inverted",
    sentinel="GET /api/a04/profile does not leak the account number",
)

# --- 3. labs.meta.yaml: the Lab 9 fix text -----------------------------------

replace_once(
    META,
    """    fix: >-
      Mask sensitive fields in responses (`ACC-****1001`, `20-**-**`). Never log PII.
      Use TLS in transit and apply field-level encryption at rest.""",
    """    fix: >-
      Mask sensitive fields in responses (`ACC-****1001`, `20-**-**`). Never log PII.
      Use TLS in transit and apply field-level encryption at rest.

      **What was changed:** the profile endpoint now masks every sensitive field.
      The account number keeps only its last four digits, the sort code only its
      first segment, the name and the email address keep their first character,
      and the balance is dropped entirely - the dashboard reads it from the
      authenticated account endpoint instead. The log line now records the
      username and the user id and nothing else, so no personal data reaches the
      log file.""",
    "labs.meta.yaml: Lab 9 fix text",
    sentinel="**What was changed:** the profile endpoint now masks every sensitive field",
)

print("Lab 9 fix applied.")
