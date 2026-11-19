#!/usr/bin/env python3
"""Apply the Lab 24 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab24.py

The Java fix was written in:
  - lab/a10/Lab24TypeCoercionController.java   (the amount is bound as a BigDecimal)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 24 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 24 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 24 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 24: type coercion --------------------------------------------------
if should_run 24; then
  lab 24 "Error-based info disclosure"
  OUT="$(post "$API/api/a10/transfers/send" \\
    -d '{"from_account_id": 1, "to_account_id": 2, "amount": "notanumber"}')"
  check "a type error is returned" "$OUT" 'NumberFormatException'
  check "the error names the amount parameter" "$OUT" 'amount'
fi""",
    """# --- Lab 24: type coercion (FIXED on this branch) ----------------------------
if should_run 24; then
  lab 24 "Error-based info disclosure"
  OUT="$(post "$API/api/a10/transfers/send" \\
    -d '{"from_account_id": 1, "to_account_id": 2, "amount": "notanumber"}')"
  refute "the type error is no longer described to the client" "$OUT" 'NumberFormatException'
  refute "the exception type name is no longer returned" "$OUT" 'java.lang.'
  refute "the stack trace is no longer returned" "$OUT" 'stacktrace'
  refute "the exception message is no longer returned" "$OUT" '"detail"'
  # The request must be rejected with a generic error.
  check "the response names only the invalid amount" "$OUT" '"error"'
  # A valid transfer must still work.
  OUT="$(post "$API/api/a10/transfers/send" \\
    -d '{"from_account_id": 1, "to_account_id": 2, "amount": 1}')"
  check "a valid transfer is still accepted" "$OUT" '"transfer_id"'
fi""",
    "verify-labs.sh: Lab 24 expectations inverted",
    sentinel='refute "the type error is no longer described to the client"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 24 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 24: type coercion =="
check "the amount parameter is named" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"from_account_id":1,"to_account_id":2,"amount":"notanumber"}' \\
     "$API/api/a10/transfers/send")" 'amount'""",
    """echo "== Lab 24: type coercion =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"from_account_id":1,"to_account_id":2,"amount":"notanumber"}' \\
     "$API/api/a10/transfers/send")" == *'stacktrace'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the stack trace is still returned\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the stack trace is no longer returned\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 24 expectation inverted",
    sentinel="the stack trace is no longer returned",
)

# --- 3. labs.meta.yaml: the Lab 24 fix text -----------------------------------

replace_once(
    META,
    """      ```java
      BigDecimal amount;
      try {
          amount = new BigDecimal(request.get("amount").toString());
      } catch (NumberFormatException e) {
          return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
      }
      ```
    source: core/src/main/java/com/securebank/lab/a10/Lab24TypeCoercionController.java""",
    """      ```java
      BigDecimal amount;
      try {
          amount = new BigDecimal(request.get("amount").toString());
      } catch (NumberFormatException e) {
          return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
      }
      ```

      **What was changed:** the request record now binds the amount as a
      `BigDecimal`, so a value that is not a number is rejected by the JSON binder
      with a generic 400 and no exception is ever caught and re-described. The
      `StringWriter` block that echoed the message, the parameter name, the Java
      type and the whole stack trace has been deleted. The amount is also checked
      against the business rules - it must be positive and the two accounts must
      differ.
    source: core/src/main/java/com/securebank/lab/a10/Lab24TypeCoercionController.java""",
    "labs.meta.yaml: Lab 24 fix text",
    sentinel="**What was changed:** the request record now binds the amount as a",
)

print("Lab 24 fix applied.")
