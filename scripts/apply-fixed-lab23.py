#!/usr/bin/env python3
"""Apply the Lab 23 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab23.py

The Java fix was written in:
  - lab/a10/Lab23VerboseErrorController.java   (the id is validated, the datasource URL is redacted)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 23 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 23 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 23 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 23: verbose error (the global handler no longer leaks) -------------
if should_run 23; then
  lab 23 "Verbose error with stack trace"
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  refute "no stack trace is returned to the client" "$OUT" 'NumberFormatException'
  refute "the internal call chain is not exposed" "$OUT" '"trace"'
  refute "the configuration is not leaked with the error" "$OUT" '"jwt.secret"'
fi""",
    """# --- Lab 23: verbose error (FIXED on this branch) ----------------------------
if should_run 23; then
  lab 23 "Verbose error with stack trace"
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  refute "no stack trace is returned to the client" "$OUT" 'NumberFormatException'
  refute "the internal call chain is not exposed" "$OUT" '"trace"'
  refute "the configuration is not leaked with the error" "$OUT" '"jwt.secret"'
  # The conversion is now handled explicitly, so the request is rejected with a
  # generic 400 rather than raising an unhandled exception.
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a10/transfers/account-summary?id=abc")"
  check "a malformed id is rejected with a 400" "$CODE" '400'
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  check "the rejection is a generic error" "$OUT" '"error":"Invalid id"'
  # The leak preview must not disclose the datasource URL either.
  OUT="$(curl -s "$API/api/a10/transfers/leak-preview")"
  refute "the datasource url is not disclosed" "$OUT" 'jdbc:postgresql'
  refute "the datasource url is redacted" "$OUT" '"spring.datasource.url":"[redacted]"'
  # A valid id must still work, so the fix did not simply break the endpoint.
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=1")"
  refute "a valid id is still accepted" "$OUT" '"error"'
fi""",
    "verify-labs.sh: Lab 23 expectations inverted",
    sentinel='check "a malformed id is rejected with a 400"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 23 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 23: verbose error (no stack trace on this branch) =="
check "the error response is a generic message" \\
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" '"error"'""",
    """echo "== Lab 23: verbose error (no stack trace on this branch) =="
check "the error response is a generic message" \\
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" '"error"'
if [[ "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" == *'jdbc:postgresql'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the datasource url is still disclosed\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the datasource url is no longer disclosed\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 23 expectation inverted",
    sentinel="the datasource url is no longer disclosed",
)

# --- 3. labs.meta.yaml: the Lab 23 fix text -----------------------------------

replace_once(
    META,
    """      Add a global error handler that logs the detail and returns a generic message.
    source: core/src/main/java/com/securebank/lab/a10/Lab23VerboseErrorController.java""",
    """      Add a global error handler that logs the detail and returns a generic message.

      **What was changed:** the id is now parsed inside a `try` block and a
      malformed value is rejected with a generic 400, so no exception escapes the
      controller and there is no stack trace to leak. The leak-preview endpoint
      also redacts the datasource URL, which names the database host, port and
      database name.
    source: core/src/main/java/com/securebank/lab/a10/Lab23VerboseErrorController.java""",
    "labs.meta.yaml: Lab 23 fix text",
    sentinel="**What was changed:** the id is now parsed inside a `try` block",
)

print("Lab 23 fix applied.")
