#!/usr/bin/env python3
"""Apply the Lab 15 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab15.py

The Java fix was written in:
  - lab/a06/Lab15MassAssignmentController.java   (the role is not bindable)
  - frontend/src/features/banking/ProfilePage.jsx   (the form does not send the role)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 15 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 15 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 15 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 15: mass assignment ------------------------------------------------
if should_run 15; then
  lab 15 "Mass assignment"
  OUT="$(curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $TOKEN" \\
    -d '{"username": "alice", "email": "alice@bank.com", "role": "admin"}')"
  check "role was changed to admin via the profile endpoint" "$OUT" '"role":"admin"'
  # restore
  curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $TOKEN" \\
    -d '{"username": "alice", "email": "alice@bank.com", "role": "customer"}' >/dev/null
fi""",
    """# --- Lab 15: mass assignment (FIXED on this branch) --------------------------
if should_run 15; then
  lab 15 "Mass assignment"
  OUT="$(curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $TOKEN" \\
    -d '{"username": "alice", "email": "alice@bank.com", "role": "admin"}')"
  refute "the role was no longer changed to admin via the profile endpoint" "$OUT" '"role":"admin"'
  # The stored role must still be the customer's.
  OUT="$(get "$API/api/a06/profile")"
  refute "the stored role is not admin" "$OUT" '"role":"admin"'
  # A legitimate email update must still work.
  OUT="$(curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $TOKEN" \\
    -d '{"email": "alice@bank.com"}')"
  check "a legitimate email update still works" "$OUT" '"email":"alice@bank.com"'
  refute "the role is still not changed by a legitimate update" "$OUT" '"role":"admin"'
fi""",
    "verify-labs.sh: Lab 15 expectations inverted",
    sentinel='refute "the role was no longer changed to admin via the profile endpoint"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 15 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 15: mass assignment =="
check "the role is bound from the request body" \\
  "$(curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"username":"alice","email":"alice@bank.com","role":"admin"}' \\
     "$API/api/a06/profile")" '"role":"admin"'
curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \\
  -d '{"username":"alice","email":"alice@bank.com","role":"customer"}' \\
  "$API/api/a06/profile" >/dev/null""",
    """echo "== Lab 15: mass assignment =="
if [[ "$(curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"username":"alice","email":"alice@bank.com","role":"admin"}' \\
     "$API/api/a06/profile")" == *'"role":"admin"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the role is still bound from the request body\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the role is no longer bound from the request body\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 15 expectation inverted",
    sentinel="the role is no longer bound from the request body",
)

# --- 3. labs.meta.yaml: the Lab 15 fix text -----------------------------------

replace_once(
    META,
    """      Role changes should be a privileged admin operation, exposed on a separate
      endpoint that requires admin authorisation.
    source: core/src/main/java/com/securebank/lab/a06/Lab15MassAssignmentController.java""",
    """      Role changes should be a privileged admin operation, exposed on a separate
      endpoint that requires admin authorisation.

      **What was changed:** the request record now declares only the email
      address, so there is no field for the client to bind a role into - the
      server, not the client, decides which fields may be written. The account to
      update is now taken from the authenticated principal rather than from the
      request body, which also closes the second bug where a caller could update
      somebody else's profile. The role is read back from the stored user, and the
      frontend no longer sends a role field at all.
    source: core/src/main/java/com/securebank/lab/a06/Lab15MassAssignmentController.java""",
    "labs.meta.yaml: Lab 15 fix text",
    sentinel="**What was changed:** the request record now declares only the email",
)

print("Lab 15 fix applied.")
