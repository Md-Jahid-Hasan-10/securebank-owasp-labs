#!/usr/bin/env python3
"""Apply the Lab 2 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab2.py

It makes four changes:
  1. Lab2PrivilegeEscalationController.java - both admin endpoints get a role
     check, and the marker flips from "VULN:" to "FIXED:".
  2. scripts/verify-labs.sh - the Lab 2 expectations are inverted: they now
     assert that the exploit FAILS, not that it succeeds.
  3. scripts/verify-walkthrough.sh - the same inversion for the walkthrough.
  4. labs/labs.meta.yaml - the Fix tab text for Lab 2 is replaced with the
     remediation as implemented.

It also repoints the Labs 8, 21 and 25 checks. Those labs prove that a forged
or garbage token is accepted as admin, and they used /api/a01/admin/users as
their probe. Now that Lab 2 is fixed, a customer gets 403 there, so those
checks move to /api/a10/transfers/history, which echoes back the principal the
filter resolved ("requested_by" / "requested_role").

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CONTROLLER = ROOT / "backend/core/src/main/java/com/securebank/lab/a01/Lab2PrivilegeEscalationController.java"
VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"

# --- 1. the controller ------------------------------------------------------

OLD_USERS = """        // VULN: [A01-Lab2] Privilege Escalation / Missing Function Level Access Control -
        // the endpoint is reachable by any authenticated principal. It confirms that a
        // token exists but never checks that the token carries the admin role, so a
        // regular customer can enumerate every account, discover which users are
        // admins, and read their password hashes.
        // FIX:  require the admin role, e.g. in an @RequireRole("admin") annotation:
        //       if (!"admin".equals(caller.getRole())) {
        //           return ResponseEntity.status(HttpStatus.FORBIDDEN)
        //                   .body(Map.of("error", "Admin role required"));
        //       }
        List<User> all = users.findAll();
"""

NEW_USERS = """        // FIXED: [A01-Lab2] Privilege Escalation / Missing Function Level Access Control.
        // WAS: the endpoint was reachable by any authenticated principal. It confirmed
        // that a token exists but never checked that the token carried the admin role,
        // so a regular customer could enumerate every account, discover which users
        // were admins, and read their password hashes.
        // NOW: the caller's role is checked before anything is read. A non-admin gets
        // 403 and the query never runs, so no user row - and in particular no
        // password_hash - is ever serialised into the response.
        //
        // The check is centralised in requireAdmin() below rather than repeated
        // inline, because a per-endpoint check is exactly the kind of thing that
        // gets forgotten when the next admin endpoint is added.
        ResponseEntity<?> denied = requireAdmin(caller);
        if (denied != null) {
            return denied;
        }

        List<User> all = users.findAll();
"""

OLD_ACCOUNTS = """        // VULN: [A01-Lab2] the same missing role check as /users - every customer can
        // list every account and its balance.
        // FIX:  require the admin role before returning the list.
        List<Account> all = accounts.findAll();
"""

NEW_ACCOUNTS = """        // FIXED: [A01-Lab2] the same missing role check as /users - every customer can
        // list every account and its balance.
        ResponseEntity<?> denied = requireAdmin(caller);
        if (denied != null) {
            return denied;
        }

        List<Account> all = accounts.findAll();
"""

OLD_TAIL = """                "accounts", all.stream().map(account -> LabResponses.map(
                        "id", account.getId(),
                        "owner_user_id", account.getUserId(),
                        "account_number", account.getAccountNumber(),
                        "balance", account.getBalance(),
                        "currency", account.getCurrency())).toList()));
    }
}
"""

NEW_TAIL = """                "accounts", all.stream().map(account -> LabResponses.map(
                        "id", account.getId(),
                        "owner_user_id", account.getUserId(),
                        "account_number", account.getAccountNumber(),
                        "balance", account.getBalance(),
                        "currency", account.getCurrency())).toList()));
    }

    /**
     * Rejects the request unless the caller holds the admin role.
     *
     * <p>Returns the 403 response to send, or {@code null} when the caller is
     * allowed through. The role is read from the verified principal, never from
     * anything the client supplied in the request body or query string.</p>
     */
    private ResponseEntity<?> requireAdmin(CurrentUser caller) {
        if (caller == null || !caller.isAdmin()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Admin role required"));
        }
        return null;
    }
}
"""

# --- 2. verify-labs.sh ------------------------------------------------------

OLD_VERIFY = """# --- Lab 2: privilege escalation --------------------------------------------
if should_run 2; then
  lab 2 "Privilege escalation"
  OUT="$(get "$API/api/a01/admin/users")"
  check "customer can list all users via /admin/users" "$OUT" '"username":"admin"'
  check "password hashes are disclosed" "$OUT" '"password_hash"'
fi
"""

NEW_VERIFY = """# --- Lab 2: privilege escalation (FIXED on this branch) ----------------------
if should_run 2; then
  lab 2 "Privilege escalation"
  OUT="$(get "$API/api/a01/admin/users")"
  check "a customer is refused by /admin/users" "$OUT" '"error":"Admin role required"'
  refute "the user list is not disclosed" "$OUT" '"username"'
  refute "password hashes are not disclosed" "$OUT" '"password_hash"'
  OUT="$(get "$API/api/a01/admin/accounts")"
  check "a customer is refused by /admin/accounts too" "$OUT" '"error":"Admin role required"'
  refute "no account balances are disclosed" "$OUT" '"balance"'
  ADMIN_TOKEN="$(login admin admin)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API/api/a01/admin/users")"
  check "an admin token still works" "$OUT" '"username":"admin"'
fi
"""

# --- 3. verify-walkthrough.sh -----------------------------------------------

OLD_WALKTHROUGH = """echo "== Lab 2: privilege escalation =="
check "GET /api/a01/admin/users as a customer" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a01/admin/users")" '"username":"admin"'
"""

NEW_WALKTHROUGH = """echo "== Lab 2: privilege escalation (fixed on this branch) =="
check "GET /api/a01/admin/users is refused for a customer" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a01/admin/users")" '"error":"Admin role required"'
"""

# --- 4. the Labs 8, 21 and 25 probes ----------------------------------------
#
# These labs prove that a forged or garbage token is accepted AS ADMIN. They
# used /api/a01/admin/users as the probe, but that endpoint now correctly
# refuses a customer and refuses a non-admin role. The forged tokens all carry
# role=admin, so they still pass the new check - but to keep the labs
# independent of Lab 2's fix, the probe moves to an endpoint that just echoes
# the principal the filter resolved.

OLD_LAB8 = """  OUT="$(get "$API/api/a01/admin/users" -H "Authorization: Bearer $FORGED")"
  check "token signed with 'secret' is accepted" "$OUT" '"username":"admin"'"""

NEW_LAB8 = """  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
  check "token signed with 'secret' is accepted as admin" "$OUT" '"requested_role":"admin"'"""

OLD_LAB21 = """  OUT="$(get "$API/api/a01/admin/users" -H "Authorization: Bearer $FORGED")"
  check "unsigned alg:none token is accepted as admin" "$OUT" '"username":"admin"'"""

NEW_LAB21 = """  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
  check "unsigned alg:none token is accepted as admin" "$OUT" '"requested_role":"admin"'"""

# --- 5. labs.meta.yaml ------------------------------------------------------

OLD_META = """    hint: >-
      The filter that guards these endpoints checks whether a token was presented,
      but not what role the token carries.
    fix: >-
      Add a role check so that only admin tokens are accepted:

      ```java
      if (!"admin".equals(caller.getRole())) {
          return ResponseEntity.status(HttpStatus.FORBIDDEN)
                  .body(Map.of("error", "Admin role required"));
      }
      ```

      Better: express this as a `@RequireRole("admin")` annotation applied at the
      method level, so the check cannot be forgotten on a new endpoint.
"""

NEW_META = """    hint: >-
      This lab is FIXED on the `fixed` branch. Compare it with `main` to see the
      original flaw:
      `git diff main fixed -- backend/core/src/main/java/com/securebank/lab/a01/`
    fix: >-
      Check the caller's role before the query runs, so a non-admin is refused
      with 403 and no user row is ever serialised into the response:

      ```java
      ResponseEntity<?> denied = requireAdmin(caller);
      if (denied != null) {
          return denied;
      }
      ```

      with a single helper that every admin endpoint calls:

      ```java
      private ResponseEntity<?> requireAdmin(CurrentUser caller) {
          if (caller == null || !caller.isAdmin()) {
              return ResponseEntity.status(HttpStatus.FORBIDDEN)
                      .body(Map.of("error", "Admin role required"));
          }
          return null;
      }
      ```

      Centralising it matters: a per-endpoint check is exactly the kind of thing
      that gets forgotten when the next admin endpoint is added. In production
      this would be an `@RequireRole("admin")` annotation applied at the method
      level, or a URL-based authorisation ruleset.

      Authentication and authorisation are different questions. The filter answers
      "who are you?"; the role check answers "are you allowed to do this?".
"""


changes = 0


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


print("applying the Lab 2 solution to the fixed branch")
replace(CONTROLLER, OLD_USERS, NEW_USERS, "Lab2PrivilegeEscalationController.java (/users)")
replace(CONTROLLER, OLD_ACCOUNTS, NEW_ACCOUNTS, "Lab2PrivilegeEscalationController.java (/accounts)")
replace(CONTROLLER, OLD_TAIL, NEW_TAIL, "Lab2PrivilegeEscalationController.java (requireAdmin helper)")
replace(VERIFY, OLD_VERIFY, NEW_VERIFY, "verify-labs.sh (Lab 2 expectations)")
replace(WALKTHROUGH, OLD_WALKTHROUGH, NEW_WALKTHROUGH, "verify-walkthrough.sh (Lab 2 expectations)")
replace(VERIFY, OLD_LAB8, NEW_LAB8, "verify-labs.sh (Lab 8 probe)")
replace(VERIFY, OLD_LAB21, NEW_LAB21, "verify-labs.sh (Lab 21 probe)")
replace(META, OLD_META, NEW_META, "labs.meta.yaml (Lab 2 hint/fix)")

# The get() helper always sends alice's own token first, and curl uses the FIRST
# Authorization header it is given. A forged token passed as an extra -H to get()
# is therefore silently ignored. This repairs that intermediate state if an
# earlier run of this script wrote the probe with get() instead of curl.
for label, old_line, new_line in (
    (
        "verify-labs.sh (Lab 8 probe uses curl, not get)",
        '  OUT="$(get "$API/api/a10/transfers/history" -H "Authorization: Bearer $FORGED")"',
        '  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"',
    ),
    (
        "verify-labs.sh (Lab 21 probe uses curl, not get)",
        '  OUT="$(get "$API/api/a10/transfers/history" -H "Authorization: Bearer $FORGED")"',
        '  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"',
    ),
):
    replace(VERIFY, old_line, new_line, label)

# The controller needs HttpStatus for the 403.
text = CONTROLLER.read_text(encoding="utf-8")
needed = "import org.springframework.http.HttpStatus;"
if needed not in text:
    anchor = "import org.springframework.http.ResponseEntity;"
    text = text.replace(anchor, f"{anchor}\n{needed}", 1)
    CONTROLLER.write_text(text, encoding="utf-8")
    print(f"  + Lab2PrivilegeEscalationController.java: added '{needed}'")
    changes += 1
else:
    print(f"  = Lab2PrivilegeEscalationController.java: '{needed}' already present")

print()
if changes:
    print(f"{changes} change(s) applied.")
    print("Now run:")
    print("  python3 scripts/sync-labs.py")
    print("  docker compose up -d --build backend")
    print("  ./scripts/verify-labs.sh")
    print("  ./scripts/verify-walkthrough.sh")
else:
    print("nothing to do - the solution is already applied.")
