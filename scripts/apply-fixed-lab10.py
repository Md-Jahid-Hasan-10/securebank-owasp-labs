#!/usr/bin/env python3
"""Apply the Lab 10 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab10.py

The Java fix was written in:
  - lab/a05/Lab10SqlInjectionController.java   (PreparedStatement, no bypass)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 10 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 10 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 10 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 10: SQL injection ---------------------------------------------------
if should_run 10; then
  lab 10 "SQL injection"
  OUT="$(curl -s -X POST "$API/api/a05/auth/login" -H "Content-Type: application/json" \\
    -d '{"username":"admin'\\'' --","password":"anything"}')"
  check "login bypass with admin' --" "$OUT" '"token"'
  check "bypass returned the admin account" "$OUT" '"role":"admin"'
  OUT="$(get "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
  # The row count grows with every account in the database, so assert on the
  # seeded accounts rather than on a fixed number.
  check "UNION SELECT dumps the seeded users" "$OUT" '"username":"alice"'
  check "UNION SELECT dumps the administrator too" "$OUT" '"username":"admin"'
  check "UNION SELECT exposes the password hashes" "$OUT" '"password_hash"'
fi""",
    """# --- Lab 10: SQL injection (FIXED on this branch) -----------------------------
if should_run 10; then
  lab 10 "SQL injection"
  OUT="$(curl -s -X POST "$API/api/a05/auth/login" -H "Content-Type: application/json" \\
    -d '{"username":"admin'\\'' --","password":"anything"}')"
  refute "the login bypass with admin' -- no longer returns a token" "$OUT" '"token"'
  refute "the login bypass no longer returns the admin account" "$OUT" '"role":"admin"'
  OUT="$(get "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
  refute "the UNION SELECT no longer dumps the seeded users" "$OUT" '"username":"alice"'
  refute "the UNION SELECT no longer dumps the administrator" "$OUT" '"username":"admin"'
  refute "the UNION SELECT no longer exposes the password hashes" "$OUT" '"password_hash"'
  # A legitimate login must still work, so the fix did not simply break the query.
  OUT="$(curl -s -X POST "$API/api/a05/auth/login" -H "Content-Type: application/json" \\
    -d '{"username":"alice","password":"password123"}')"
  check "a legitimate login still works" "$OUT" '"token"'
  # The search must still work for a plain term.
  OUT="$(get "$API/api/a05/transfers/search?q=alice")"
  check "a normal search still finds the user" "$OUT" '"username":"alice"'
fi""",
    "verify-labs.sh: Lab 10 expectations inverted",
    sentinel='refute "the login bypass with admin',
)

# --- 2. verify-walkthrough.sh: invert the Lab 10 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 10: SQL injection =="
check "login bypass with admin' --" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"admin'\\'' --","password":"anything"}' \\
     "$API/api/a05/auth/login")" '"token"'""",
    """echo "== Lab 10: SQL injection =="
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"admin'\\'' --","password":"anything"}' \\
     "$API/api/a05/auth/login")" == *'"token"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m login bypass with admin'\\'' -- still returns a token\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m login bypass with admin'\\'' -- no longer returns a token\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 10 expectation inverted",
    sentinel="login bypass with admin'\\'' -- no longer returns a token",
)

replace_once(
    WALKTHROUGH,
    """WALK_SQLI_OUT="$(curl -s "${AUTH[@]}" "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
check "UNION SELECT dumps the seeded users" "$WALK_SQLI_OUT" '"username":"alice"'
check "UNION SELECT dumps the administrator too" "$WALK_SQLI_OUT" '"username":"admin"'
check "UNION SELECT exposes the password hashes" "$WALK_SQLI_OUT" '"password_hash"'""",
    """WALK_SQLI_OUT="$(curl -s "${AUTH[@]}" "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
if [[ "$WALK_SQLI_OUT" == *'"username":"alice"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m UNION SELECT still dumps the seeded users\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m UNION SELECT no longer dumps the seeded users\\n'
  PASS=$((PASS + 1))
fi
if [[ "$WALK_SQLI_OUT" == *'"password_hash"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m UNION SELECT still exposes the password hashes\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m UNION SELECT no longer exposes the password hashes\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 10 UNION expectation inverted",
    sentinel="UNION SELECT no longer exposes the password hashes",
)

# --- 3. labs.meta.yaml: the Lab 10 fix text -----------------------------------

replace_once(
    META,
    """      Never interpolate user input into SQL text.
    source: core/src/main/java/com/securebank/lab/a05/Lab10SqlInjectionController.java""",
    """      Never interpolate user input into SQL text.

      **What was changed:** both queries now use a `PreparedStatement` with a `?`
      placeholder, so the username and the search term are sent to the driver as
      values and can never change the shape of the statement. The `isInjected()`
      helper - which skipped the password check precisely when an injection had
      manipulated the WHERE clause - has been deleted, so the bcrypt check now
      applies to every login.
    source: core/src/main/java/com/securebank/lab/a05/Lab10SqlInjectionController.java""",
    "labs.meta.yaml: Lab 10 fix text",
    sentinel="**What was changed:** both queries now use a `PreparedStatement`",
)

print("Lab 10 fix applied.")
