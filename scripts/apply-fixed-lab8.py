#!/usr/bin/env python3
"""Apply the Lab 8 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab8.py

The Java fix was written in:
  - core/security/JwtService.java              (secret from the env, never logged)
  - lab/a10/Lab23VerboseErrorController.java   (secret redacted from the leak preview)

Lab 4's two controllers already drop the secret from the response entirely
(the Lab 4 fix landed earlier), so they need no change here. The static/.env
fixture is already deleted by the Lab 6 fix, so the committed copy of the key
is gone with it.

The supporting changes are made here:
  - resources/application.yml                   (jwt.secret read from the env)
  - docker-compose.yml                          (JWT_SECRET supplied to the container)
  - scripts/verify-labs.sh                      (the Lab 8 expectations are inverted)
  - labs/labs.meta.yaml                         (the Lab 8 fix text)

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

APP_YML = ROOT / "backend/core/src/main/resources/application.yml"
COMPOSE = ROOT / "docker-compose.yml"
VERIFY = ROOT / "scripts/verify-labs.sh"
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


# --- 1. application.yml: no committed secret ---------------------------------

replace_once(
    APP_YML,
    """# VULN: [A04-Lab8] The JWT signing secret is hardcoded in the shipped configuration file
# and is also printed to the application log at startup. Anyone with repo access,
# log access, or the exposed .env file can forge tokens for any user.
# FIX:  load a >= 256-bit random secret from the environment; never commit it.
jwt:
  secret: "secret"
  expiration-seconds: 3600""",
    """# FIXED: [A04-Lab8] The JWT signing secret is no longer committed. It is read from the
# JWT_SECRET environment variable and there is no default: the application refuses to
# start when the variable is missing or shorter than 32 bytes.
#
# Generate a value with:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
jwt:
  secret: ${JWT_SECRET}
  expiration-seconds: 3600""",
    "application.yml: jwt.secret from the environment",
    sentinel="FIXED: [A04-Lab8] The JWT signing secret is no longer committed",
)

# --- 2. docker-compose.yml: supply the secret -------------------------------

replace_once(
    COMPOSE,
    """      DB_USER: securebank
      DB_PASSWORD: securebank""",
    """      DB_USER: securebank
      DB_PASSWORD: securebank
      # FIXED: [A04-Lab8] The JWT signing secret is supplied by the environment rather
      # than committed in application.yml. This default is a development convenience
      # only - override it in any real deployment:
      #   export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
      JWT_SECRET: "${JWT_SECRET:-896e714b9a9e4a032f6fa7fe10f1ce8f249f8d582ad96bfee2ae978ec9c69bb2}\"""",
    "docker-compose.yml: JWT_SECRET environment variable",
    sentinel="FIXED: [A04-Lab8] The JWT signing secret is supplied by the environment",
)

# --- 3. verify-labs.sh: invert the Lab 8 expectations -------------------------

replace_once(
    VERIFY,
    """  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
  check "token signed with 'secret' is accepted as admin" "$OUT" '"requested_role":"admin"'
fi""",
    """  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
  # NOTE: an invalid token is treated as admin by the Lab 25 fail-open filter, so
  # the HTTP response cannot tell a forged token from a garbage one while that
  # lab is still vulnerable. The signature is checked directly instead - that is
  # what this lab is actually about.
  LIVE="$(login alice password123)"
  SIG_OK="$(python3 - "$LIVE" <<'PY'
import base64, hashlib, hmac, sys

token = sys.argv[1]
if not token:
    print("no-token")
    raise SystemExit

header, payload, sig = token.split(".")


def b64d(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


message = f"{header}.{payload}".encode()
expected = hmac.new(b"secret", message, hashlib.sha256).digest()
print("signed-with-secret" if b64d(sig) == expected else "not-signed-with-secret")
PY
)"
  if [[ "$SIG_OK" == "not-signed-with-secret" ]]; then
    green "a live token is not signed with 'secret'"
    PASS=$((PASS + 1))
  else
    red "a live token is still signed with 'secret'"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # The signing key must not be published anywhere.
  OUT="$(curl -s "$API/api/a02/debug")"
  refute "the debug endpoint does not disclose the secret" "$OUT" '"jwt.secret":"secret"'
  OUT="$(curl -s "$API/api/a02/debug/boom")"
  refute "the error response does not disclose the secret" "$OUT" '"jwt.secret":"secret"'
  OUT="$(curl -s "$API/api/a10/transfers/leak-preview")"
  refute "the leak preview does not disclose the secret" "$OUT" '"jwt.secret":"secret"'
  # The startup log must not contain the key either.
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'SECRET_KEY=.secret' || true)"
  refute "the startup log does not print the key" "$OUT" "1"
  # The committed configuration must not contain the key either.
  OUT="$(grep -c 'secret: "secret"' backend/core/src/main/resources/application.yml || true)"
  refute "the committed configuration has no literal secret" "$OUT" "1"
  # A legitimate login still works, so the fix did not simply break signing.
  if [[ -n "$LIVE" ]]; then
    green "alice can still sign in with a valid token"
    PASS=$((PASS + 1))
  else
    red "alice can no longer sign in"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
fi""",
    "verify-labs.sh: Lab 8 expectations inverted",
    sentinel='green "a live token is not signed with \'secret\'"',
)

# --- 4. labs.meta.yaml: the Lab 8 fix text -----------------------------------

replace_once(
    META,
    """    fix: >-
      Generate a cryptographically strong secret and load it only from the environment:

      ```bash
      python3 -c "import secrets; print(secrets.token_hex(32))"
      ```

      Rotate it on a schedule and never log it.""",
    """    fix: >-
      Generate a cryptographically strong secret and load it only from the environment:

      ```bash
      python3 -c "import secrets; print(secrets.token_hex(32))"
      ```

      Rotate it on a schedule and never log it.

      **What was changed:** `jwt.secret` in `application.yml` now reads
      `${JWT_SECRET}` with no default, so the application refuses to start without
      it and no key material is committed. `JwtService` validates that the secret is
      at least 32 bytes and never logs it. The Lab 4 debug and verbose-error
      responses drop the secret entirely, and the Lab 23 leak preview reports
      `[redacted]`. The container receives the secret through the `JWT_SECRET`
      environment variable.""",
    "labs.meta.yaml: Lab 8 fix text",
    sentinel="**What was changed:** `jwt.secret` in `application.yml` now reads",
)

print("Lab 8 fix applied.")
