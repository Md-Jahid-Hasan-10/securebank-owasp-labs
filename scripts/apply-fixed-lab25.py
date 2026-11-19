#!/usr/bin/env python3
"""Apply the Lab 25 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab25.py

The Java fix was written in:
  - core/security/AuthFilter.java   (no admin fallback, authentication fails closed)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 25 expectations are inverted)
  - labs/labs.meta.yaml               (the Lab 25 fix text)

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERIFY = ROOT / "scripts/verify-labs.sh"
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


# --- 1. verify-labs.sh: invert the Lab 25 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 25: auth bypass on exception ---------------------------------------
if should_run 25; then
  lab 25 "Authentication bypass on exception"
  NO_TOKEN="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a10/transfers/history")"
  check "no token is rejected with 401" "$NO_TOKEN" '401'
  GARBAGE="$(curl -s -o /dev/null -w '%{http_code}' \\
    -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  check "a garbage token is ACCEPTED (fail-open)" "$GARBAGE" '200'
  OUT="$(curl -s -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  check "the garbage token was treated as admin" "$OUT" '"transfers"'
fi""",
    """# --- Lab 25: auth bypass on exception (FIXED on this branch) ------------------
if should_run 25; then
  lab 25 "Authentication bypass on exception"
  NO_TOKEN="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a10/transfers/history")"
  check "no token is rejected with 401" "$NO_TOKEN" '401'
  GARBAGE="$(curl -s -o /dev/null -w '%{http_code}' \\
    -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  check "a garbage token is REJECTED with 401 (fail-closed)" "$GARBAGE" '401'
  OUT="$(curl -s -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  refute "the garbage token is no longer treated as admin" "$OUT" '"transfers"'
  refute "the garbage token does not receive an admin role" "$OUT" '"requested_role":"admin"'
  # A tampered token must be rejected too.
  TAMPERED="${TOKEN%?}x"
  CODE="$(curl -s -o /dev/null -w '%{http_code}' \\
    -H "Authorization: Bearer $TAMPERED" "$API/api/a10/transfers/history")"
  check "a tampered token is rejected with 401" "$CODE" '401'
  # A valid token must still work.
  CODE="$(curl -s -o /dev/null -w '%{http_code}' \\
    -H "Authorization: Bearer $TOKEN" "$API/api/a10/transfers/history")"
  check "a valid token is still accepted" "$CODE" '200'
fi""",
    "verify-labs.sh: Lab 25 expectations inverted",
    sentinel='check "a garbage token is REJECTED with 401 (fail-closed)"',
)

# --- 2. labs.meta.yaml: the Lab 25 fix text -----------------------------------

replace_once(
    META,
    """      Never fail open. Exceptions in authentication logic must always fail closed.
    source: core/src/main/java/com/securebank/core/security/AuthFilter.java""",
    """      Never fail open. Exceptions in authentication logic must always fail closed.

      **What was changed:** the fallback principal is gone. The `CurrentUser` is
      built only from a token that has been successfully verified, and a token
      that cannot be verified - malformed, unsigned, tampered with or expired -
      is rejected with a 401 and a generic `Invalid token` body. A token with no
      subject is rejected as well, so no principal can be produced without a
      verified identity behind it.
    source: core/src/main/java/com/securebank/core/security/AuthFilter.java""",
    "labs.meta.yaml: Lab 25 fix text",
    sentinel="**What was changed:** the fallback principal is gone",
)

print("Lab 25 fix applied.")
