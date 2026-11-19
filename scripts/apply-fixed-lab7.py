#!/usr/bin/env python3
"""Apply the Lab 7 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab7.py

The Java fix was written in:
  - core/user/PasswordService.java                (bcrypt hash + checkpw)
  - lab/a04/Lab7CryptoController.java              (hashes redacted, cracker gone)
  - lab/a02/Lab5DefaultAdminController.java        (bcrypt for created/reset admins)
  - lab/a07/Lab19ResetController.java              (bcrypt for the reset password)
  - lab/a05/Lab10SqlInjectionController.java       (password verified in Java)
  - core/user/User.java                            (javadoc)

The supporting changes are made here:
  - backend/core/pom.xml                           (spring-security-crypto for bcrypt)
  - resources/db/migration/V1__schema.sql          (wider hash column)
  - resources/db/migration/V2__seed.sql            (bcrypt seed hashes)
  - resources/db/migration/V4__bcrypt_passwords.sql (new migration for existing volumes)
  - scripts/verify-labs.sh                         (the Lab 7 expectations are inverted)
  - scripts/verify-walkthrough.sh                  (the same inversion for the walkthrough)
  - labs/labs.meta.yaml                            (the Lab 7 hint/fix text)

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

POM = ROOT / "backend/core/pom.xml"
SCHEMA = ROOT / "backend/core/src/main/resources/db/migration/V1__schema.sql"
SEED = ROOT / "backend/core/src/main/resources/db/migration/V2__seed.sql"
MIGRATION = ROOT / "backend/core/src/main/resources/db/migration/V4__bcrypt_passwords.sql"
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


def write_if_absent(path: Path, content: str, label: str, sentinel: str) -> None:
    """Create `path` with `content`, unless it is already there."""
    if path.exists():
        if sentinel in path.read_text():
            print(f"  already applied: {label}")
            return
        path.write_text(content)
        print(f"  applied: {label}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"  applied: {label}")


# --- 1. pom.xml: bcrypt ------------------------------------------------------

OLD_POM = """    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-jdbc</artifactId>
    </dependency>"""

NEW_POM = """    <!--
      FIXED: [A04-Lab7] Cryptographic Failure - bcrypt is used for password hashing.
      Only spring-security-crypto is pulled in, NOT spring-boot-starter-security:
      the starter would auto-configure the whole security filter chain and silently
      remediate Labs 1, 2, 15, 18, 21 and 25. The crypto module on its own provides
      BCrypt without any auto-configuration.
    -->
    <dependency>
      <groupId>org.springframework.security</groupId>
      <artifactId>spring-security-crypto</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-jdbc</artifactId>
    </dependency>"""


def patch_pom() -> None:
    print("backend/core/pom.xml")
    replace_once(POM, OLD_POM, NEW_POM, "spring-security-crypto dependency",
                 sentinel="FIXED: [A04-Lab7] Cryptographic Failure - bcrypt is used for password hashing.")


# --- 2. V1__schema.sql: widen the hash column --------------------------------

OLD_SCHEMA = """-- SecureBank Labs — schema
-- Intentionally vulnerable training target. Passwords are stored as unsalted MD5 (Lab 7).

CREATE TABLE users (
                       id              BIGSERIAL PRIMARY KEY,
                       username        VARCHAR(64)  NOT NULL UNIQUE,
                       email           VARCHAR(255) NOT NULL,
                       password_hash   VARCHAR(64)  NOT NULL,   -- VULN: [A04-Lab7] unsalted MD5 hex"""

NEW_SCHEMA = """-- SecureBank Labs — schema
-- FIXED: [A04-Lab7] Passwords are stored as bcrypt hashes with a unique salt per
-- user. The column is 255 characters wide because a bcrypt hash is 60 characters.

CREATE TABLE users (
                       id              BIGSERIAL PRIMARY KEY,
                       username        VARCHAR(64)  NOT NULL UNIQUE,
                       email           VARCHAR(255) NOT NULL,
                       password_hash   VARCHAR(255) NOT NULL,   -- FIXED: [A04-Lab7] bcrypt hash"""


def patch_schema() -> None:
    print("V1__schema.sql")
    replace_once(SCHEMA, OLD_SCHEMA, NEW_SCHEMA, "wider hash column",
                 sentinel="FIXED: [A04-Lab7] Passwords are stored as bcrypt hashes with a unique salt per")


# --- 3. V2__seed.sql: bcrypt seed hashes ------------------------------------

OLD_SEED = """-- SecureBank Labs — seed data
-- Password hashes are unsalted MD5 (Lab 7). Verified values:
--   password123 -> 482c811da5d5b4bc6d497ffa98491e38
--   qwerty      -> d8578edf8458ce06fbc5bb76a58c5ca4
--   admin       -> 21232f297a57a5a743894a0e4a801fc3
--   charlie     -> bf779e0933a882808585d19455cd7937
"""

NEW_SEED = """-- SecureBank Labs — seed data
--
-- FIXED: [A04-Lab7] Cryptographic Failure - the password hashes are no longer
-- unsalted MD5 digests. They are bcrypt hashes (cost 12), each with its own
-- random salt, so the same password hashes to a different stored value for every
-- account. The plaintext passwords are unchanged, so the seeded accounts still
-- work for the labs:
--   alice   -> password123
--   bob     -> qwerty
--   admin   -> admin
--   charlie -> charlie
"""

SEED_ROWS = [
    ("alice", "$2a$12$rRbHhLMozsJ2kJQ/v0bBwO/x.IUWHplP8AojZ2YZXdHF4IFVcVVVW"),
    ("bob", "$2a$12$.3TQGXOST0NkP8GgqaM66enor5XLhi4pzpG7spXwoSJhUQW7JiDwW"),
    ("admin", "$2a$12$bYKrnmss.vgt6WKRqNNwhOQxHE6KgIdmrUNf57Mc0Cj6TFFJ/KuyS"),
    ("charlie", "$2a$12$gx0CF8X71VHBfmym7CN74uKosWoW0YMAtaGIaYlspZoOum.qqQseK"),
]

OLD_SEED_ROWS = [
    ("alice", "482c811da5d5b4bc6d497ffa98491e38"),
    ("bob", "d8578edf8458ce06fbc5bb76a58c5ca4"),
    ("admin", "21232f297a57a5a743894a0e4a801fc3"),
    ("charlie", "bf779e0933a882808585d19455cd7937"),
]


def patch_seed() -> None:
    print("V2__seed.sql")
    replace_once(SEED, OLD_SEED, NEW_SEED, "seed comment",
                 sentinel="FIXED: [A04-Lab7] Cryptographic Failure - the password hashes are no longer")
    for (old_user, old_hash), (new_user, new_hash) in zip(OLD_SEED_ROWS, SEED_ROWS):
        replace_once(SEED, f"'{old_hash}'", f"'{new_hash}'", f"{new_user} seed hash",
                     sentinel=new_hash)


# --- 4. V4__bcrypt_passwords.sql: new migration -----------------------------

MIGRATION_CONTENT = """-- FIXED: [A04-Lab7] Cryptographic Failure - moves the stored passwords from
-- unsalted MD5 to bcrypt.
--
-- V1__schema.sql already carries the wider column, but Flyway only runs each
-- migration once, so an existing database needs this ALTER to pick it up.
ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(255);

-- The MD5 digests are replaced with bcrypt hashes of the same passwords. The
-- plaintexts are the seeded ones, so the accounts keep working for the labs:
--   alice   -> password123
--   bob     -> qwerty
--   admin   -> admin
--   charlie -> charlie
--
-- Each bcrypt hash carries its own random salt, so every account has a
-- different stored value even where two accounts share a password.
UPDATE users SET password_hash = '$2a$12$rRbHhLMozsJ2kJQ/v0bBwO/x.IUWHplP8AojZ2YZXdHF4IFVcVVVW' WHERE username = 'alice';
UPDATE users SET password_hash = '$2a$12$.3TQGXOST0NkP8GgqaM66enor5XLhi4pzpG7spXwoSJhUQW7JiDwW' WHERE username = 'bob';
UPDATE users SET password_hash = '$2a$12$bYKrnmss.vgt6WKRqNNwhOQxHE6KgIdmrUNf57Mc0Cj6TFFJ/KuyS' WHERE username = 'admin';
UPDATE users SET password_hash = '$2a$12$gx0CF8X71VHBfmym7CN74uKosWoW0YMAtaGIaYlspZoOum.qqQseK' WHERE username = 'charlie';

-- Any account created after the seed still holds an MD5 digest, because the
-- admin API used to hash with MD5. Those are reset to a bcrypt hash of the
-- factory password, so no MD5 digest survives the migration.
UPDATE users SET password_hash = '$2a$12$bYKrnmss.vgt6WKRqNNwhOQxHE6KgIdmrUNf57Mc0Cj6TFFJ/KuyS'
 WHERE username <> 'alice' AND username <> 'bob' AND username <> 'charlie'
   AND password_hash NOT LIKE '$2a$%';
"""


def patch_migration() -> None:
    print("V4__bcrypt_passwords.sql")
    write_if_absent(MIGRATION, MIGRATION_CONTENT, "bcrypt migration",
                     "moves the stored passwords from")


# --- 5. verify-labs.sh: invert the Lab 7 assertions --------------------------

OLD_LAB7 = """# --- Lab 7: MD5 hashes ------------------------------------------------------
if should_run 7; then
  lab 7 "Unsalted MD5 password hashes"
  OUT="$(get "$API/api/a04/hashes")"
  check "hashes endpoint returns MD5 digests" "$OUT" '482c811da5d5b4bc6d497ffa98491e38'
  check "hashes endpoint reports no salt" "$OUT" '"salted":false'
  OUT="$(get "$API/api/a04/crack")"
  check "alice's password is cracked in-app" "$OUT" 'password123'
fi"""

NEW_LAB7 = """# --- Lab 7: MD5 hashes (FIXED on this branch) --------------------------------
if should_run 7; then
  lab 7 "Unsalted MD5 password hashes"
  OUT="$(get "$API/api/a04/hashes")"
  # The stored hashes are no longer handed out at all.
  refute "the hashes endpoint no longer returns MD5 digests" "$OUT" '482c811da5d5b4bc6d497ffa98491e38'
  refute "no seeded password hash is disclosed" "$OUT" '$2a$12$'
  check "the hashes endpoint reports a salted algorithm" "$OUT" '"salted":true'
  check "the hashes endpoint reports bcrypt" "$OUT" '"algorithm":"bcrypt"'
  check "the hashes are redacted" "$OUT" '"password_hash":"(redacted)"'
  # The in-process cracker is gone.
  OUT="$(get "$API/api/a04/crack")"
  refute "alice's password is not cracked in-app" "$OUT" 'password123'
  refute "no password is cracked in-app" "$OUT" '"cracked":{"alice"'
  # And the hashes themselves are bcrypt in the database, not MD5. The search
  # endpoint still returns the hash for a genuine match, so a normal search term
  # shows what is actually stored.
  OUT="$(get "$API/api/a05/transfers/search?q=alice")"
  check "the stored hashes are bcrypt" "$OUT" '$2a$12$'
  refute "no MD5 digest survives in the database" "$OUT" '482c811da5d5b4bc6d497ffa98491e38'
  # A legitimate login still works with the seeded password. The login helper
  # returns the raw token, so the assertion is that a token came back.
  OUT="$(login alice password123)"
  check "alice can still log in with her seeded password" "$OUT" 'eyJ'
fi"""


def patch_verify() -> None:
    print("verify-labs.sh")
    replace_once(VERIFY, OLD_LAB7, NEW_LAB7, "inverted Lab 7 assertions",
                 sentinel="# --- Lab 7: MD5 hashes (FIXED on this branch) --------------------------------")


# --- 6. verify-walkthrough.sh: invert the Lab 7 assertions -------------------

OLD_WALK = """echo "== Lab 7: MD5 =="
check "GET /api/a04/hashes" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a04/hashes")" '482c811da5d5b4bc6d497ffa98491e38'
check "GET /api/a04/crack" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a04/crack")" 'password123'"""

NEW_WALK = """echo "== Lab 7: MD5 (fixed on this branch) =="
WALK_HASHES_OUT="$(curl -s "${AUTH[@]}" "$API/api/a04/hashes")"
if [[ "$WALK_HASHES_OUT" == *'482c811da5d5b4bc6d497ffa98491e38'* ]]; then
  printf '\\033[31m  FAIL\\033[0m GET /api/a04/hashes does not return MD5 digests\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m GET /api/a04/hashes does not return MD5 digests\\n'
  PASS=$((PASS + 1))
fi
if [[ "$WALK_HASHES_OUT" == *'password_hash":"(redacted)"'* ]]; then
  printf '\\033[32m  PASS\\033[0m the hashes are redacted\\n'
  PASS=$((PASS + 1))
else
  printf '\\033[31m  FAIL\\033[0m the hashes are redacted\\n'
  FAIL=$((FAIL + 1))
fi
WALK_CRACK_OUT="$(curl -s "${AUTH[@]}" "$API/api/a04/crack")"
if [[ "$WALK_CRACK_OUT" == *'password123'* ]]; then
  printf '\\033[31m  FAIL\\033[0m GET /api/a04/crack does not crack the password\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m GET /api/a04/crack does not crack the password\\n'
  PASS=$((PASS + 1))
fi
WALK_LOGIN_OUT="$(curl -s -X POST "$API/api/auth/login" -H 'Content-Type: application/json' \\
  -d '{"username":"alice","password":"password123"}')"
if [[ "$WALK_LOGIN_OUT" == *'"token"'* ]]; then
  printf '\\033[32m  PASS\\033[0m alice can still log in with her seeded password\\n'
  PASS=$((PASS + 1))
else
  printf '\\033[31m  FAIL\\033[0m alice can still log in with her seeded password\\n'
  FAIL=$((FAIL + 1))
fi"""


def patch_walkthrough() -> None:
    print("verify-walkthrough.sh")
    replace_once(WALKTHROUGH, OLD_WALK, NEW_WALK, "inverted Lab 7 assertions",
                 sentinel='echo "== Lab 7: MD5 (fixed on this branch) =="')


# --- 7. labs.meta.yaml: the hint and fix text -------------------------------

OLD_META = """    hint: >-
      `hashcat -m 0` is raw MD5. Why does the absence of a salt matter so much?
    fix: >-
      Use a deliberately slow, salted password hashing function:

      ```java
      String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
      boolean ok = BCrypt.checkpw(password, hash);
      ```

      Never use MD5, SHA-1 or SHA-256 alone for passwords.
    source: core/src/main/java/com/securebank/lab/a04/Lab7CryptoController.java"""

NEW_META = """    hint: >-
      `hashcat -m 0` is raw MD5. Why does the absence of a salt matter so much?
      The hashes are no longer MD5 and the endpoint no longer hands them out -
      try it and see what comes back.
    fix: >-
      Passwords are stored with bcrypt, a deliberately slow, salted password
      hashing function:

      ```java
      String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
      boolean ok = BCrypt.checkpw(password, hash);
      ```

      Each hash carries its own random salt, so the same password produces a
      different stored value for every account and a single rainbow table no
      longer attacks them all at once. Each verification attempt costs roughly
      100ms of CPU, so an offline guess is orders of magnitude more expensive
      than it was against an MD5 digest. Never use MD5, SHA-1 or SHA-256 alone
      for passwords.

      The hash store is no longer exposed through the API either: `/api/a04/hashes`
      reports the algorithm and redacts the stored values, and the in-process
      cracker that used to demonstrate the offline attack has been removed.
    source: core/src/main/java/com/securebank/lab/a04/Lab7CryptoController.java"""


def patch_meta() -> None:
    print("labs.meta.yaml")
    replace_once(META, OLD_META, NEW_META, "Lab 7 fix text",
                 sentinel="The hash store is no longer exposed through the API either")


def main() -> None:
    patch_pom()
    patch_schema()
    patch_seed()
    patch_migration()
    patch_verify()
    patch_walkthrough()
    patch_meta()
    print("\nLab 7 remediation applied.")


if __name__ == "__main__":
    main()
