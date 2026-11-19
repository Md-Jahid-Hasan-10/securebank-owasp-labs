#!/usr/bin/env python3
"""Apply the Lab 14 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab14.py

The Java fix was written in:
  - lab/a06/Lab14BusinessLogicController.java   (the amount must be positive)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 14 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 14 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 14 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 14: negative transfer ----------------------------------------------
if should_run 14; then
  lab 14 "Negative transfer amount"
  BEFORE="$(get "$API/api/a01/accounts/1")"
  OUT="$(post "$API/api/a06/transfers/" \\
    -d '{"from_account_id": 2, "to_account_id": 1, "amount": -1000}')"
  check "negative transfer is accepted" "$OUT" '"transfer_id"'
  AFTER="$(get "$API/api/a01/accounts/1")"
  if [[ "$BEFORE" != "$AFTER" ]]; then
    green "negative transfer changed alice's balance"
    PASS=$((PASS + 1))
  else
    red "negative transfer did not change alice's balance"
    FAIL=$((FAIL + 1))
  fi
fi""",
    """# --- Lab 14: negative transfer (FIXED on this branch) -------------------------
if should_run 14; then
  lab 14 "Negative transfer amount"
  BEFORE="$(get "$API/api/a01/accounts/1")"
  OUT="$(post "$API/api/a06/transfers/" \\
    -d '{"from_account_id": 2, "to_account_id": 1, "amount": -1000}')"
  refute "the negative transfer is no longer accepted" "$OUT" '"transfer_id"'
  AFTER="$(get "$API/api/a01/accounts/1")"
  if [[ "$BEFORE" == "$AFTER" ]]; then
    green "the negative transfer did not change alice's balance"
    PASS=$((PASS + 1))
  else
    red "the negative transfer still changed alice's balance"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # A positive transfer must still work, so the fix did not simply break the endpoint.
  OUT="$(post "$API/api/a06/transfers/" \\
    -d '{"from_account_id": 2, "to_account_id": 1, "amount": 1}')"
  check "a positive transfer is still accepted" "$OUT" '"transfer_id"'
fi""",
    "verify-labs.sh: Lab 14 expectations inverted",
    sentinel='refute "the negative transfer is no longer accepted"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 14 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 14: negative transfer =="
check "a negative transfer is accepted" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"from_account_id":2,"to_account_id":1,"amount":-1000}' \\
     "$API/api/a06/transfers/")" '"transfer_id"'""",
    """echo "== Lab 14: negative transfer =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"from_account_id":2,"to_account_id":1,"amount":-1000}' \\
     "$API/api/a06/transfers/")" == *'"transfer_id"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m a negative transfer is still accepted\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m a negative transfer is no longer accepted\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 14 expectation inverted",
    sentinel="a negative transfer is no longer accepted",
)

# --- 3. labs.meta.yaml: the Lab 14 fix text -----------------------------------

replace_once(
    META,
    """      This is an **insecure design** flaw: the rule was simply never considered
      during design, so no single line of code was ever wrong.
    source: core/src/main/java/com/securebank/lab/a06/Lab14BusinessLogicController.java""",
    """      This is an **insecure design** flaw: the rule was simply never considered
      during design, so no single line of code was ever wrong.

      **What was changed:** the sign rule is now enforced at the input boundary.
      An amount of zero or less is rejected with a 400, the two accounts must
      differ, and the sender must have enough money. A positive transfer still
      works, so the endpoint was not simply broken.
    source: core/src/main/java/com/securebank/lab/a06/Lab14BusinessLogicController.java""",
    "labs.meta.yaml: Lab 14 fix text",
    sentinel="**What was changed:** the sign rule is now enforced at the input boundary",
)

print("Lab 14 fix applied.")
