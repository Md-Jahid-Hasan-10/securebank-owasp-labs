#!/usr/bin/env python3
"""Apply the Lab 16 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab16.py

The Java fix was written in:
  - lab/a06/Lab16EnumerationController.java   (one message, constant-time)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 16 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 16 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 16 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 16: account enumeration --------------------------------------------
if should_run 16; then
  lab 16 "Account enumeration"
  MISSING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \\
    -d '{"username": "notauser", "password": "anything"}')"
  EXISTING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \\
    -d '{"username": "alice", "password": "wrongpassword"}')"
  check "missing user is reported as 'User not found'" "$MISSING" 'User not found'
  check "existing user is reported as 'Incorrect password'" "$EXISTING" 'Incorrect password'
  if [[ "$MISSING" != "$EXISTING" ]]; then
    green "the two error responses differ"
    PASS=$((PASS + 1))
  else
    red "the two error responses are identical"
    FAIL=$((FAIL + 1))
  fi
fi""",
    """# --- Lab 16: account enumeration (FIXED on this branch) ----------------------
if should_run 16; then
  lab 16 "Account enumeration"
  MISSING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \\
    -d '{"username": "notauser", "password": "anything"}')"
  EXISTING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \\
    -d '{"username": "alice", "password": "wrongpassword"}')"
  refute "a missing user is no longer reported as 'User not found'" "$MISSING" 'User not found'
  refute "an existing user is no longer reported as 'Incorrect password'" "$EXISTING" 'Incorrect password'
  if [[ "$MISSING" == "$EXISTING" ]]; then
    green "the two error responses are identical"
    PASS=$((PASS + 1))
  else
    red "the two error responses differ"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  check "the shared message is 'Invalid credentials'" "$MISSING" 'Invalid credentials'
fi""",
    "verify-labs.sh: Lab 16 expectations inverted",
    sentinel="refute \"a missing user is no longer reported as 'User not found'\"",
)

# --- 2. verify-walkthrough.sh: invert the Lab 16 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 16: enumeration =="
check "missing user" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"notauser","password":"x"}' "$API/api/a06/auth/login/")" 'User not found'
check "existing user" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"alice","password":"wrongpassword"}' "$API/api/a06/auth/login/")" 'Incorrect password'""",
    """echo "== Lab 16: enumeration =="
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"notauser","password":"x"}' "$API/api/a06/auth/login/")" == *'User not found'* ]]; then
  printf '\\033[31m  FAIL\\033[0m a missing user is still reported separately\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m a missing user is no longer reported separately\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 16 expectation inverted",
    sentinel="a missing user is no longer reported separately",
)

# --- 3. labs.meta.yaml: the Lab 16 fix text -----------------------------------

replace_once(
    META,
    """      Equalise the timing too, so that a missing user and a wrong password take the
      same time to answer.
    source: core/src/main/java/com/securebank/lab/a06/Lab16EnumerationController.java""",
    """      Equalise the timing too, so that a missing user and a wrong password take the
      same time to answer.

      **What was changed:** both failure paths now return the same
      `Invalid credentials` body with the same status. The "user not found" path
      still performs a bcrypt comparison - against a fixed dummy hash - so the two
      responses take the same time and the difference cannot be measured even
      though the messages match.
    source: core/src/main/java/com/securebank/lab/a06/Lab16EnumerationController.java""",
    "labs.meta.yaml: Lab 16 fix text",
    sentinel="**What was changed:** both failure paths now return the same",
)

print("Lab 16 fix applied.")
