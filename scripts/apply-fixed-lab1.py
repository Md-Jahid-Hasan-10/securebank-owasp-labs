#!/usr/bin/env python3
"""Apply the Lab 1 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab1.py

It makes three changes:
  1. Lab1IdorController.java - the authorization check, and the marker flips
     from "VULN:" to "FIXED:" so the branch is self-documenting.
  2. scripts/verify-labs.sh - the Lab 1 expectations are inverted: they now
     assert that the exploit FAILS, not that it succeeds.
  3. labs/labs.meta.yaml - the Fix tab text for Lab 1 is replaced with the
     remediation as implemented, so the panel on this branch teaches the fix
     rather than describing a hypothetical one.

The script is idempotent: running it twice changes nothing the second time.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CONTROLLER = ROOT / "backend/core/src/main/java/com/securebank/lab/a01/Lab1IdorController.java"
VERIFY = ROOT / "scripts/verify-labs.sh"
META = ROOT / "labs/labs.meta.yaml"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"

# The marker and the code that follows it are replaced in one atomic
# operation, so the authorization check cannot end up separated from the
# account load it depends on.
OLD_BLOCK = """        // VULN: [A01-Lab1] IDOR / Broken Object Level Authorization - the account is fetched
        // by primary key only. The owning user_id is never compared with the authenticated
        // caller's id, so any logged-in customer can read any account in the system.
        // FIX:  load the account and reject the request unless account.user_id equals the
        //       authenticated caller's id, e.g.
        //       if (!Objects.equals(account.getUserId(), caller.getId())) {
        //           return ResponseEntity.status(HttpStatus.FORBIDDEN)
        //                   .body(Map.of("error", "Not your account"));
        //       }
        Account account = accounts.findById(id).orElse(null);

        if (account == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }
"""

NEW_BLOCK = """        // FIXED: [A01-Lab1] IDOR / Broken Object Level Authorization.
        // WAS: the account was fetched by primary key only, and the owning user_id
        // was never compared with the authenticated caller's id, so any logged-in
        // customer could read any account in the system.
        // NOW: the caller's id is compared against account.user_id. A mismatch is
        // rejected with 404 and the same "Account not found" body as a genuinely
        // missing account, so a caller cannot tell "exists but not yours" from
        // "does not exist" - see Lab 16 for why that distinction matters.
        Account account = accounts.findById(id).orElse(null);

        if (account == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Account not found"));
        }

        if (caller == null || !Objects.equals(account.getUserId(), caller.getId())) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Account not found"));
        }
"""

OLD_VERIFY = """# --- Lab 1: IDOR ------------------------------------------------------------
if should_run 1; then
  lab 1 "IDOR"
  OUT="$(get "$API/api/a01/accounts/2")"
  check "alice can read bob's account via /accounts/2" "$OUT" '"account_number":"ACC-1002"'
  check "bob's balance is disclosed" "$OUT" '"balance"'
fi
"""

NEW_VERIFY = """# --- Lab 1: IDOR (FIXED on this branch) -------------------------------------
if should_run 1; then
  lab 1 "IDOR"
  OUT="$(get "$API/api/a01/accounts/2")"
  check "alice CANNOT read bob's account via /accounts/2" "$OUT" '"error"'
  refute "no balance is disclosed" "$OUT" '"balance"'
  refute "bob's account number is not leaked" "$OUT" '"ACC-1002"'
  check "a non-owner gets 404, not 403 (no enumeration oracle)" "$OUT" '"error":"Account not found"'
  OWN="$(get "$API/api/a01/accounts/1")"
  check "alice can still read her OWN account" "$OWN" '"account_number":"ACC-1001"'
fi
"""

OLD_META_HINT = """    hint: >-
      The endpoint accepts an account id in the path. Ask what it does with the
      authenticated user's id before it returns the record.
    fix: >-
      Compare the account's owner with the caller before returning it:

      ```java
      if (!Objects.equals(account.getUserId(), caller.getId())) {
          return ResponseEntity.status(HttpStatus.FORBIDDEN)
                  .body(Map.of("error", "Not your account"));
      }
      ```

      Authorisation must be enforced server-side on every single request.
"""

NEW_META_HINT = """    hint: >-
      This lab is FIXED on the `fixed` branch. Compare it with `main` to see the
      original flaw:
      `git diff main fixed -- backend/core/src/main/java/com/securebank/lab/a01/`
    fix: >-
      Compare the account's owner with the caller before returning it. Reject with
      404 rather than 403, so a caller cannot distinguish "exists but not yours"
      from "does not exist":

      ```java
      if (caller == null || !Objects.equals(account.getUserId(), caller.getId())) {
          return ResponseEntity.status(HttpStatus.NOT_FOUND)
                  .body(Map.of("error", "Account not found"));
      }
      ```

      Authorisation must be enforced server-side on every single request.
"""

changes = 0

# The walkthrough script asserts the exploit still works, so its Lab 1 check has
# to be inverted on the solution branch too.
OLD_WALKTHROUGH = """echo "== Lab 1: IDOR =="
check "GET /api/a01/accounts/2 returns bob's account" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a01/accounts/2")" '"account_number":"ACC-1002"'
"""

NEW_WALKTHROUGH = """echo "== Lab 1: IDOR (fixed on this branch) =="
check "GET /api/a01/accounts/2 is refused for a non-owner" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a01/accounts/2")" '"error":"Account not found"'
check "GET /api/a01/accounts/1 still returns alice's own account" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a01/accounts/1")" '"account_number":"ACC-1001"'
"""


def replace(path: Path, old: str, new: str, label: str) -> None:
    global changes
    text = path.read_text(encoding="utf-8")
    if new in text and old not in text:
        print(f"  = {label}: already applied")
        return
    if old not in text:
        print(f"  ! {label}: pattern not found - skipped")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  + {label}: updated")
    changes += 1


print("applying the Lab 1 solution to the fixed branch")
replace(CONTROLLER, OLD_BLOCK, NEW_BLOCK, "Lab1IdorController.java (marker + authorization check)")
replace(VERIFY, OLD_VERIFY, NEW_VERIFY, "verify-labs.sh (Lab 1 expectations)")
replace(META, OLD_META_HINT, NEW_META_HINT, "labs.meta.yaml (Lab 1 hint/fix)")
replace(WALKTHROUGH, OLD_WALKTHROUGH, NEW_WALKTHROUGH, "verify-walkthrough.sh (Lab 1 expectations)")

# The controller needs two imports for the fix to compile.
text = CONTROLLER.read_text(encoding="utf-8")
for needed, anchor in (
    ("import java.util.Objects;", "import java.util.Map;"),
    ("import org.springframework.http.HttpStatus;", "import org.springframework.http.ResponseEntity;"),
):
    if needed not in text:
        text = text.replace(anchor, f"{anchor}\n{needed}", 1)
        CONTROLLER.write_text(text, encoding="utf-8")
        print(f"  + Lab1IdorController.java: added '{needed}'")
        changes += 1
    else:
        print(f"  = Lab1IdorController.java: '{needed}' already present")

print()
if changes:
    print(f"{changes} change(s) applied.")
    print("Now run:")
    print("  python3 scripts/sync-labs.py")
    print("  docker compose up -d --build backend")
    print("  ./scripts/verify-labs.sh")
else:
    print("nothing to do - the solution is already applied.")
