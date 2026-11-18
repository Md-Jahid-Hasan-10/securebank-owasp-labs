#!/usr/bin/env python3
"""Apply the Lab 5 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab5.py

The Java fix was written by hand in:
  - lab/a02/Lab5DefaultAdminController.java  (admin guard + must-change gate)
  - core/user/User.java                       (mustChangePassword flag)
  - core/user/UserRepository.java             (column plumbing)
  - resources/db/migration/V1__schema.sql     (new column)
  - resources/db/migration/V2__seed.sql       (admin flagged)
  - resources/db/migration/V3__must_change_password.sql  (new file)

This script handles everything around it:

  1. core/security/AuthController.java - the main login path. The seeded admin
     must be blocked here too, otherwise "admin/admin" still works on
     /api/auth/login and the default credential is still a way in.
  2. scripts/verify-labs.sh - the Lab 5 expectations are inverted, and the
     admin-token helper is taught to unlock the seeded admin before use
     (Labs 2 and 4 both need an admin token).
  3. scripts/verify-walkthrough.sh - the same inversion for the walkthrough.
  4. labs/labs.meta.yaml - the Lab 5 hint/fix text is replaced with the
     remediation as implemented.

The script is idempotent: running it twice changes nothing the second time.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

AUTH = ROOT / "backend/core/src/main/java/com/securebank/core/security/AuthController.java"
VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"


def replace_once(path: Path, old: str, new: str, label: str, sentinel: str = "") -> None:
    """Replace `old` with `new`, at most once.

    The patched form carries a sentinel (a comment that only exists in the
    new text). If the sentinel is already in the file the patch has been
    applied, which keeps the script idempotent even when the new block
    contains the old block as a prefix.
    """
    text = path.read_text()
    if sentinel and sentinel in text:
        print(f"  already applied: {label}")
        return
    if old not in text:
        print(f"  already applied: {label}")
        return
    path.write_text(text.replace(old, new, 1))
    print(f"  applied: {label}")


# --- 1. AuthController: gate the main login path ----------------------------

OLD_AUTH = """        if (user == null || !PasswordService.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        String token = jwtService.issue(user.getId(), user.getUsername(), user.getRole());"""

NEW_AUTH = """        if (user == null || !PasswordService.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }

        // FIXED: [A02-Lab5] Default Credentials - this login path used to accept the
        // seeded factory password, so blocking it only on the admin console would
        // have left the default credential working everywhere else.
        // NOW: an account flagged for a mandatory password change cannot log in
        //       until the password has been replaced.
        if (user.mustChangePassword()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Password must be changed before this account can be used",
                    "must_change_password", true));
        }

        String token = jwtService.issue(user.getId(), user.getUsername(), user.getRole());"""

OLD_AUTH_IMPORT = """import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.ResponseEntity;"""

NEW_AUTH_IMPORT = """import com.securebank.core.user.PasswordService;
import com.securebank.core.user.User;
import com.securebank.core.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;"""


def patch_auth() -> None:
    print("AuthController.java")
    replace_once(AUTH, OLD_AUTH_IMPORT, NEW_AUTH_IMPORT, "HttpStatus import",
                 sentinel="import org.springframework.http.HttpStatus;")
    replace_once(AUTH, OLD_AUTH, NEW_AUTH, "must-change-password gate",
                 sentinel="FIXED: [A02-Lab5] Default Credentials - this login path used to accept the")


# --- 1b. AuthFilter: the password-change endpoint must be reachable ----------

FILTER = ROOT / "backend/core/src/main/java/com/securebank/core/security/AuthFilter.java"

OLD_FILTER = """                || path.startsWith("/api/a02/admin/login")
                || path.startsWith("/api/a02/exposed-files")"""

NEW_FILTER = """                || path.startsWith("/api/a02/admin/login")
                // FIXED: [A02-Lab5] the password-change endpoint has to be reachable
                // without a session: the seeded administrator is refused a session
                // until its password is changed, so it could never clear the flag.
                // Identity is proven by the current password instead of a token.
                || path.startsWith("/api/a02/admin/password")
                || path.startsWith("/api/a02/exposed-files")"""


def patch_filter() -> None:
    print("AuthFilter.java")
    replace_once(FILTER, OLD_FILTER, NEW_FILTER, "public password endpoint",
                 sentinel='path.startsWith("/api/a02/admin/password")')


# --- 2. verify-labs.sh ------------------------------------------------------

OLD_LOGIN = """login() {
  curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \\
    -d "{\\"username\\":\\"$1\\",\\"password\\":\\"$2\\"}" \\
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null
}"""

NEW_LOGIN = """login() {
  curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \\
    -d "{\\"username\\":\\"$1\\",\\"password\\":\\"$2\\"}" \\
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null
}

# FIXED: [A02-Lab5] the seeded administrator is flagged for a mandatory password
# change, so it cannot log in until the password is replaced. The script unlocks
# it, so the labs that need an admin token (Labs 2 and 4) still work. The unlock
# goes through the password endpoint, which proves identity with the current
# password rather than with a session - an admin that cannot log in yet could
# never clear the flag otherwise.
#
# The request body uses snake_case keys because the application sets
# spring.jackson.property-naming-strategy=SNAKE_CASE, and the password avoids
# characters that would need JSON escaping.
admin_password="CorrectHorse9BatteryStaple"

unlock_admin() {
  # The account may still hold the factory password (fresh database) or the
  # password from a previous run, so try both.
  local current out
  for current in "admin" "$admin_password"; do
    out="$(curl -s -X POST "$API/api/a02/admin/password" \\
      -H "Content-Type: application/json" \\
      -d "{\\"username\\":\\"admin\\",\\"current_password\\":\\"$current\\",\\"new_password\\":\\"$admin_password\\"}")"
    [[ "$out" == *'"updated":true'* ]] && return 0
  done
  return 1
}

admin_login() {
  # The admin console login needs the account unlocked first.
  unlock_admin >/dev/null 2>&1
  login admin "$admin_password"
}"""

OLD_LAB10 = """  OUT="$(get "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
  check "UNION SELECT dumps the users table" "$OUT" '"count":4'"""

NEW_LAB10 = """  OUT="$(get "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
  # The row count grows with every account in the database, so assert on the
  # seeded accounts rather than on a fixed number.
  check "UNION SELECT dumps the seeded users" "$OUT" '"username":"alice"'
  check "UNION SELECT dumps the administrator too" "$OUT" '"username":"admin"'
  check "UNION SELECT exposes the password hashes" "$OUT" '"password_hash"'"""

OLD_LAB5 = """# --- Lab 5: default admin credentials ---------------------------------------
if should_run 5; then
  lab 5 "Default admin credentials"
  ADMIN_TOKEN="$(login admin admin)"
  if [[ -z "$ADMIN_TOKEN" ]]; then
    red "admin/admin login failed"
    FAIL=$((FAIL + 1))
  else
    green "admin/admin signs in to the admin API"
    PASS=$((PASS + 1))
  fi
fi"""

NEW_LAB5 = """# --- Lab 5: default admin credentials (FIXED on this branch) ----------------
if should_run 5; then
  lab 5 "Default admin credentials"
  # The seeded administrator is refused the factory password. Its password may
  # already have been changed by an earlier run of this script, so the
  # assertion is that no session comes back, not which error is returned.
  OUT="$(curl -s -X POST "$API/api/a02/admin/login" -H "Content-Type: application/json" \\
    -d '{"username":"admin","password":"admin"}')"
  refute "the factory password does not open the admin console" "$OUT" '"token"'
  OUT="$(curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \\
    -d '{"username":"admin","password":"admin"}')"
  refute "the factory password does not open the main login path" "$OUT" '"token"'
  # Only an administrator may create another administrator.
  CUSTOMER_TOKEN="$(login alice password123)"
  OUT="$(curl -s -X POST "$API/api/a02/admin/users" \\
    -H "Authorization: Bearer $CUSTOMER_TOKEN" -H "Content-Type: application/json" \\
    -d '{"username":"sneakyadmin","email":"sneaky@bank.com","password":"sneaky123"}')"
  check "a customer cannot create an administrator" "$OUT" '"error":"Admin role required"'
  refute "no account is created" "$OUT" '"created":true'
  # An administrator can still create one, and the new account is flagged for a
  # mandatory password change. The username is unique per run so a second run
  # does not trip over the account the first one left behind.
  ADMIN_TOKEN="$(admin_login)"
  if [[ -z "$ADMIN_TOKEN" ]]; then
    red "an admin with a changed password cannot sign in"
    FAIL=$((FAIL + 1))
  else
    green "an admin with a changed password can sign in"
    PASS=$((PASS + 1))
  fi
  NEW_ADMIN="newadmin$$"
  OUT="$(curl -s -X POST "$API/api/a02/admin/users" \\
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
    -d "{\\"username\\":\\"$NEW_ADMIN\\",\\"email\\":\\"newadmin@bank.com\\",\\"password\\":\\"newadmin123\\"}")"
  check "an administrator can still create an administrator" "$OUT" '"created":true'
  OUT="$(curl -s -X POST "$API/api/a02/admin/login" -H "Content-Type: application/json" \\
    -d "{\\"username\\":\\"$NEW_ADMIN\\",\\"password\\":\\"newadmin123\\"}")"
  check "the new administrator must also change its password" \\
    "$OUT" '"error":"Password must be changed before this account can be used"'
  refute "no session is issued to the new administrator" "$OUT" '"token"'
fi"""

# Labs 2 and 4 need an admin token. The seeded admin is now locked, so they
# have to unlock it first.
OLD_LAB2_ADMIN = """  ADMIN_TOKEN="$(login admin admin)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API/api/a01/admin/users")"
  check "an admin token still works" "$OUT" '"username":"admin"'"""

NEW_LAB2_ADMIN = """  ADMIN_TOKEN="$(admin_login)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API/api/a01/admin/users")"
  check "an admin token still works" "$OUT" '"username":"admin"'"""

OLD_LAB4_ADMIN = """  ADMIN_TOKEN4="$(login admin admin)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN4" "$API/api/a02/debug")\""""

NEW_LAB4_ADMIN = """  ADMIN_TOKEN4="$(admin_login)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN4" "$API/api/a02/debug")\""""


def patch_verify() -> None:
    print("verify-labs.sh")
    replace_once(VERIFY, OLD_LOGIN, NEW_LOGIN, "admin_login helper",
                 sentinel="admin_login() {")
    replace_once(VERIFY, OLD_LAB5, NEW_LAB5, "inverted Lab 5 assertions",
                 sentinel="# --- Lab 5: default admin credentials (FIXED on this branch) ----------------")
    replace_once(VERIFY, OLD_LAB2_ADMIN, NEW_LAB2_ADMIN, "Lab 2 admin token",
                 sentinel='ADMIN_TOKEN="$(admin_login)"\n  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API/api/a01/admin/users")"')
    replace_once(VERIFY, OLD_LAB4_ADMIN, NEW_LAB4_ADMIN, "Lab 4 admin token",
                 sentinel='ADMIN_TOKEN4="$(admin_login)"')
    replace_once(VERIFY, OLD_LAB10, NEW_LAB10, "Lab 10 row count assertion",
                 sentinel='check "UNION SELECT dumps the seeded users"')


# --- 3. verify-walkthrough.sh -----------------------------------------------

OLD_WALK = """echo "== Lab 5: default admin =="
check "admin/admin logs into the admin console" \\
  "$(login admin admin)" 'eyJ'"""

NEW_WALK = """echo "== Lab 5: default admin =="
# The seeded administrator's password may already have been replaced by an
# earlier run of the verification scripts, so the assertion is that the factory
# password never yields a session.
WALK_ADMIN_OUT="$(curl -s -X POST "$API/api/a02/admin/login" -H 'Content-Type: application/json' \\
  -d '{"username":"admin","password":"admin"}')"
if [[ "$WALK_ADMIN_OUT" == *'"token"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the factory password does not open the admin console\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the factory password does not open the admin console\\n'
  PASS=$((PASS + 1))
fi
WALK_LOGIN_OUT="$(curl -s -X POST "$API/api/auth/login" -H 'Content-Type: application/json' \\
  -d '{"username":"admin","password":"admin"}')"
if [[ "$WALK_LOGIN_OUT" == *'"token"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the factory password does not open the main login path\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the factory password does not open the main login path\\n'
  PASS=$((PASS + 1))
fi"""


OLD_WALK_LAB10 = """check "UNION SELECT dumps the users table" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")" '"count":4'"""

NEW_WALK_LAB10 = """# The row count grows with every account in the database, so assert on the
# seeded accounts rather than on a fixed number.
WALK_SQLI_OUT="$(curl -s "${AUTH[@]}" "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
check "UNION SELECT dumps the seeded users" "$WALK_SQLI_OUT" '"username":"alice"'
check "UNION SELECT dumps the administrator too" "$WALK_SQLI_OUT" '"username":"admin"'
check "UNION SELECT exposes the password hashes" "$WALK_SQLI_OUT" '"password_hash"'"""

# An earlier run of this script already inverted the Lab 5 block, but with an
# order-dependent assertion: it expected one specific error message. Once the
# verification scripts have changed the admin password, that message is no
# longer the one that comes back, so the block is replaced again with the
# order-independent version above.
OLD_WALK_V1 = """echo "== Lab 5: default admin =="
check "admin/admin is refused on the admin console" \\
  "$(curl -s -X POST "$API/api/a02/admin/login" -H 'Content-Type: application/json' \\
    -d '{"username":"admin","password":"admin"}')" \\
  '"error":"Password must be changed before this account can be used"'
check "admin/admin is refused on the main login path" \\
  "$(curl -s -X POST "$API/api/auth/login" -H 'Content-Type: application/json' \\
    -d '{"username":"admin","password":"admin"}')" \\
  '"error":"Password must be changed before this account can be used"'"""


def patch_walkthrough() -> None:
    print("verify-walkthrough.sh")
    text = WALKTHROUGH.read_text()
    if 'the factory password does not open the admin console' in text:
        print("  already applied: inverted Lab 5 assertions")
    else:
        # Replace whichever of the two previous forms is in the file.
        for old in (OLD_WALK, OLD_WALK_V1):
            if old in text:
                text = text.replace(old, NEW_WALK, 1)
                WALKTHROUGH.write_text(text)
                print("  applied: inverted Lab 5 assertions")
                break
        else:
            print("  already applied: inverted Lab 5 assertions")
    replace_once(WALKTHROUGH, OLD_WALK_LAB10, NEW_WALK_LAB10, "Lab 10 row count assertion",
                 sentinel='check "UNION SELECT dumps the seeded users"')


# --- 3b. Lab5DefaultAdminController: fix the password-change deadlock --------

LAB5 = ROOT / "backend/core/src/main/java/com/securebank/lab/a02/Lab5DefaultAdminController.java"

OLD_CHANGE = """    public record ChangePasswordRequest(String currentPassword, String newPassword) {
    }"""

NEW_CHANGE = """    public record ChangePasswordRequest(String username, String currentPassword, String newPassword) {
    }"""

OLD_CHANGE_BODY = """    @PostMapping("/password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        CurrentUser caller = CurrentUserHolder.get();

        if (caller == null || !caller.isAdmin()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Admin role required"));
        }

        User user = users.findByUsername(caller.getUsername()).orElse(null);
        if (user == null || !PasswordService.matches(request.currentPassword(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Current password is incorrect"));
        }

        if (request.newPassword() == null || request.newPassword().length() < 12) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "New password must be at least 12 characters"));
        }

        users.updatePasswordHash(user.getId(), PasswordService.md5(request.newPassword()));
        users.clearMustChangePassword(user.getId());

        return ResponseEntity.ok(Map.of("updated", true));
    }"""

NEW_CHANGE_BODY = """    @PostMapping("/password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        // FIXED: [A02-Lab5] this endpoint used to require an admin session, but the
        // seeded administrator is refused a session until its password is changed,
        // so it could never clear the flag: the account locked itself out.
        // NOW: identity is proven by the username plus the current password, which
        //       is the only credential the account still has. The endpoint is on the
        //       AuthFilter's public list for the same reason.
        User user = users.findByUsername(request.username()).orElse(null);

        if (user == null || !user.isAdmin()
                || !PasswordService.matches(request.currentPassword(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body(Map.of("error", "Current password is incorrect"));
        }

        if (request.newPassword() == null || request.newPassword().length() < 12) {
            return ResponseEntity.status(400)
                    .body(Map.of("error", "New password must be at least 12 characters"));
        }

        users.updatePasswordHash(user.getId(), PasswordService.md5(request.newPassword()));
        users.clearMustChangePassword(user.getId());

        return ResponseEntity.ok(Map.of("updated", true));
    }"""


def patch_lab5() -> None:
    print("Lab5DefaultAdminController.java")
    replace_once(LAB5, OLD_CHANGE, NEW_CHANGE, "ChangePasswordRequest username",
                 sentinel="public record ChangePasswordRequest(String username, String currentPassword")
    replace_once(LAB5, OLD_CHANGE_BODY, NEW_CHANGE_BODY, "password endpoint without a session",
                 sentinel="NOW: identity is proven by the username plus the current password")


# --- 4. labs.meta.yaml ------------------------------------------------------

OLD_META = """    hint: >-
      The seed data always ships one admin account. What password does it use?
    fix: >-
      Use strong, unique admin credentials stored in a secret manager, restrict the
      admin console to an internal network, and disable it entirely in production."""

NEW_META = """    hint: >-
      The seed data always ships one admin account. What password does it use?
      Now that the password has been changed, try the old one on both the admin
      console and the main login path - neither accepts it any more.
    fix: >-
      The seeded administrator is flagged must_change_password and is refused by
      both login paths until its password is replaced, so the factory password is
      never a working credential. New administrator accounts can only be created by
      an authenticated administrator, and they are flagged the same way. Provision
      real admin accounts from a secret manager with generated passwords instead."""


def patch_meta() -> None:
    print("labs.meta.yaml")
    replace_once(META, OLD_META, NEW_META, "Lab 5 fix text",
                 sentinel="NOW: the seeded administrator is flagged must_change_password")


def main() -> None:
    patch_auth()
    patch_filter()
    patch_lab5()
    patch_verify()
    patch_walkthrough()
    patch_meta()
    print("\nLab 5 remediation applied.")


if __name__ == "__main__":
    main()
