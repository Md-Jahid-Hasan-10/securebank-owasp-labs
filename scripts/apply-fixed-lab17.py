#!/usr/bin/env python3
"""Apply the Lab 17 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab17.py

The Java fix was written in:
  - lab/a07/Lab17BruteForceController.java   (the counter now blocks)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 17 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 17 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 17 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 17: brute force ----------------------------------------------------
if should_run 17; then
  lab 17 "No rate limiting"
  FOUND=0
  for pw in password123 letmein welcome qwerty123 monkey dragon; do
    OUT="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \\
      -d "{\\"username\\":\\"alice\\",\\"password\\":\\"$pw\\"}")"
    if [[ "$OUT" == *'"token"'* ]]; then
      FOUND=$((FOUND + 1))
    fi
  done
  if [[ "$FOUND" -gt 0 ]]; then
    green "multiple guesses were accepted without throttling"
    PASS=$((PASS + 1))
  else
    red "no guess succeeded"
    FAIL=$((FAIL + 1))
  fi
  OUT="$(get "$API/api/a07/auth/attempts")"
  check "attempts are counted but never blocked" "$OUT" 'attempts'
fi""",
    """# --- Lab 17: brute force (FIXED on this branch) ------------------------------
if should_run 17; then
  lab 17 "No rate limiting"
  # Use a username that is not a real account, so the throttle bucket is not
  # shared with the seeded users and the run does not lock anybody out.
  FOUND=0
  for pw in one two three four five six seven eight; do
    OUT="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \\
      -d "{\\"username\\":\\"ratelimitprobe\\",\\"password\\":\\"$pw\\"}")"
    if [[ "$OUT" == *'"token"'* ]]; then
      FOUND=$((FOUND + 1))
    fi
  done
  if [[ "$FOUND" -eq 0 ]]; then
    green "no guess was ever accepted"
    PASS=$((PASS + 1))
  else
    red "a guess was accepted"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # After enough failures the account must be locked out.
  LAST=""
  for pw in nine ten eleven twelve thirteen; do
    LAST="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \\
      -d "{\\"username\\":\\"ratelimitprobe\\",\\"password\\":\\"$pw\\"}")"
  done
  check "the account is locked out after too many failures" "$LAST" 'Too many failed attempts'
  # A correct password must not be accepted while the account is locked out.
  OUT="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \\
    -d '{"username":"ratelimitprobe","password":"password123"}')"
  refute "the locked-out account cannot be used to log in" "$OUT" '"token"'
  # The attempt counter must no longer leak the number of attempts made.
  OUT="$(get "$API/api/a07/auth/attempts")"
  refute "the attempt counter no longer leaks the number of attempts" "$OUT" 'attempts_so_far'
fi""",
    "verify-labs.sh: Lab 17 expectations inverted",
    sentinel='check "the account is locked out after too many failures"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 17 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 17: brute force =="
check "attempts are counted" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a07/auth/attempts")" 'attempts'""",
    """echo "== Lab 17: brute force =="
WALK_BF_LAST=""
for pw in one two three four five six seven eight nine ten; do
  WALK_BF_LAST="$(curl -s -X POST -H "Content-Type: application/json" \\
     -d "{\\"username\\":\\"ratelimitprobe\\",\\"password\\":\\"$pw\\"}" \\
     "$API/api/a07/auth/login")"
done
if [[ "$WALK_BF_LAST" == *'Too many failed attempts'* ]]; then
  printf '\\033[32m  PASS\\033[0m the account is locked out after too many failures\\n'
  PASS=$((PASS + 1))
else
  printf '\\033[31m  FAIL\\033[0m the account is not locked out\\n'
  FAIL=$((FAIL + 1))
fi""",
    "verify-walkthrough.sh: Lab 17 expectation inverted",
    sentinel="the account is locked out after too many failures",
)

# --- 3. labs.meta.yaml: the Lab 17 fix text -----------------------------------

replace_once(
    META,
    """      Combine it with per-account lockout after N failures and a CAPTCHA on
      web-facing login forms.
    source: core/src/main/java/com/securebank/lab/a07/Lab17BruteForceController.java""",
    """      Combine it with per-account lockout after N failures and a CAPTCHA on
      web-facing login forms.

      **What was changed:** the attempt counter is now consulted before the
      password is even checked. After five failures the bucket is locked out for
      sixty seconds and every further attempt is refused with a 429. The lockout
      is keyed by username *and* client address, so one attacker cannot lock
      every customer out, and cannot dodge the limit by rotating usernames. The
      `attempts_so_far` field is no longer returned.
    source: core/src/main/java/com/securebank/lab/a07/Lab17BruteForceController.java""",
    "labs.meta.yaml: Lab 17 fix text",
    sentinel="**What was changed:** the attempt counter is now consulted before the",
)

print("Lab 17 fix applied.")
