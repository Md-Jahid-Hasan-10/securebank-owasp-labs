#!/usr/bin/env python3
"""Apply the Lab 19 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab19.py

The Java fix was written in:
  - lab/a07/Lab19ResetController.java   (SecureRandom token, single use)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 19 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 19 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 19 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 19: predictable reset token ----------------------------------------
if should_run 19; then
  lab 19 "Predictable password reset token"
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \\
    -d '{"username": "alice"}')"
  check "a reset token is issued" "$OUT" '"token"'
  COMPUTED="$(python3 - <<'PY'
import hashlib, time
username = "alice"
now = int(time.time())
for offset in range(-30, 31):
    ts = now + offset
    print(hashlib.md5(f"{username}{ts}".encode()).hexdigest())
PY
)"
  MATCHED=0
  while read -r candidate; do
    OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \\
      -d "{\\"token\\": \\"$candidate\\", \\"new_password\\": \\"hacked123\\"}")"
    if [[ "$OUT" == *'"password_reset":true'* ]]; then
      MATCHED=1
      break
    fi
  done <<< "$COMPUTED"
  if [[ "$MATCHED" -eq 1 ]]; then
    green "an offline-computed token was accepted"
    PASS=$((PASS + 1))
  else
    red "no computed token was accepted"
    FAIL=$((FAIL + 1))
  fi
  # restore alice's password so the next run can log in
  reset_alice_password >/dev/null 2>&1
  login alice password123 >/dev/null 2>&1
fi""",
    """# --- Lab 19: predictable reset token (FIXED on this branch) ------------------
if should_run 19; then
  lab 19 "Predictable password reset token"
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \\
    -d '{"username": "alice"}')"
  check "a reset token is issued" "$OUT" '"token"'
  COMPUTED="$(python3 - <<'PY'
import hashlib, time
username = "alice"
now = int(time.time())
for offset in range(-30, 31):
    ts = now + offset
    print(hashlib.md5(f"{username}{ts}".encode()).hexdigest())
PY
)"
  MATCHED=0
  while read -r candidate; do
    OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \\
      -d "{\\"token\\": \\"$candidate\\", \\"new_password\\": \\"hacked123\\"}")"
    if [[ "$OUT" == *'"password_reset":true'* ]]; then
      MATCHED=1
      break
    fi
  done <<< "$COMPUTED"
  if [[ "$MATCHED" -eq 0 ]]; then
    green "no offline-computed token was accepted"
    PASS=$((PASS + 1))
  else
    red "an offline-computed token was accepted"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # A token that was actually issued must work, and must work only once.
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \\
    -d '{"username": "alice"}')"
  GOOD_TOKEN="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)"
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \\
    -d "{\\"token\\": \\"$GOOD_TOKEN\\", \\"new_password\\": \\"password123\\"}")"
  check "an issued token can still be redeemed" "$OUT" '"password_reset":true'
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \\
    -d "{\\"token\\": \\"$GOOD_TOKEN\\", \\"new_password\\": \\"password123\\"}")"
  refute "the token cannot be redeemed twice" "$OUT" '"password_reset":true'
  # The response must not reveal whether an account exists.
  MISSING="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \\
    -d '{"username": "notauser"}')"
  EXISTING="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \\
    -d '{"username": "alice"}')"
  refute "a missing account is not reported as an error" "$MISSING" 'User not found'
  # The token field is present but empty for an unknown account - it must not hold
  # a usable value.
  MISSING_TOKEN="$(echo "$MISSING" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)"
  if [[ -z "$MISSING_TOKEN" ]]; then
    green "a missing account is not given a token"
    PASS=$((PASS + 1))
  else
    red "a missing account was given a token"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # The response shape must be identical for both accounts.
  if [[ "$(echo "$MISSING" | python3 -c "import sys,json; print(sorted(json.load(sys.stdin).keys()))" 2>/dev/null)" \\
        == "$(echo "$EXISTING" | python3 -c "import sys,json; print(sorted(json.load(sys.stdin).keys()))" 2>/dev/null)" ]]; then
    green "the response shape is the same for a missing and an existing account"
    PASS=$((PASS + 1))
  else
    red "the response shape differs between a missing and an existing account"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # restore alice's password so the next run can log in
  reset_alice_password >/dev/null 2>&1
  login alice password123 >/dev/null 2>&1
fi""",
    "verify-labs.sh: Lab 19 expectations inverted",
    sentinel='green "no offline-computed token was accepted"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 19 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 19: predictable reset token =="
check "a reset token is issued" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"alice"}' "$API/api/a07/auth/reset-request")" '"token"'""",
    """echo "== Lab 19: predictable reset token =="
check "a reset token is issued" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"username":"alice"}' "$API/api/a07/auth/reset-request")" '"token"'
WALK_RT_OUT=""
for offset in $(seq -30 30); do
  WALK_RT_TOKEN="$(python3 -c "import hashlib,time; print(hashlib.md5(f'alice{int(time.time())+$offset}'.encode()).hexdigest())")"
  WALK_RT_OUT="$(curl -s -X POST -H "Content-Type: application/json" \\
     -d "{\\"token\\":\\"$WALK_RT_TOKEN\\",\\"new_password\\":\\"hacked123\\"}" \\
     "$API/api/a07/auth/reset-confirm")"
  if [[ "$WALK_RT_OUT" == *'"password_reset":true'* ]]; then
    break
  fi
done
if [[ "$WALK_RT_OUT" == *'"password_reset":true'* ]]; then
  printf '\\033[31m  FAIL\\033[0m an offline-computed token was accepted\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m an offline-computed token was not accepted\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 19 expectation inverted",
    sentinel="an offline-computed token was not accepted",
)

# --- 3. labs.meta.yaml: the Lab 19 fix text -----------------------------------

replace_once(
    META,
    """      Store it with a one-hour expiry, delete it after a single use, and do not
      return it in the response body.
    source: core/src/main/java/com/securebank/lab/a07/Lab19ResetController.java""",
    """      Store it with a one-hour expiry, delete it after a single use, and do not
      return it in the response body.

      **What was changed:** the token is 32 bytes of `SecureRandom` output, stored
      against its own expiry and keyed by the token itself - so it can only be
      redeemed by presenting exactly the value that was issued, and there is
      nothing left to derive offline. A valid token is removed from the store the
      moment it is redeemed, so it cannot be used twice. The reset-request endpoint
      now returns the same neutral response whether or not the account exists.
    source: core/src/main/java/com/securebank/lab/a07/Lab19ResetController.java""",
    "labs.meta.yaml: Lab 19 fix text",
    sentinel="**What was changed:** the token is 32 bytes of `SecureRandom` output",
)

print("Lab 19 fix applied.")
