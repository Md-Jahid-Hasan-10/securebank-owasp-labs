#!/usr/bin/env python3
"""Apply the Lab 18 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab18.py

The Java fix was written in:
  - lab/a07/Lab18SessionController.java   (the session id is regenerated on login)
  - core/security/WebConfig.java          (the CORS marker is updated)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 18 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 18 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 18 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 18: session fixation -----------------------------------------------
if should_run 18; then
  lab 18 "Session fixation"
  COOKIE_JAR="$(mktemp)"
  SID="$(curl -s -c "$COOKIE_JAR" -X POST "$API/api/a07/session/init" \\
    | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)"
  curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$API/api/a07/auth/login-session" \\
    -H "Content-Type: application/json" \\
    -d '{"username":"alice","password":"password123"}' >/dev/null
  OUT="$(curl -s -b "$COOKIE_JAR" "$API/api/a07/session/whoami")"
  check "the pre-login session id is now authenticated" "$OUT" '"username":"alice"'
  check "the session id was not regenerated" "$OUT" "\\"session_id\\":\\"$SID\\""
  rm -f "$COOKIE_JAR"
fi""",
    """# --- Lab 18: session fixation (FIXED on this branch) -------------------------
if should_run 18; then
  lab 18 "Session fixation"
  COOKIE_JAR="$(mktemp)"
  SID="$(curl -s -c "$COOKIE_JAR" -X POST "$API/api/a07/session/init" \\
    | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)"
  OUT="$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$API/api/a07/auth/login-session" \\
    -H "Content-Type: application/json" \\
    -d '{"username":"alice","password":"password123"}')"
  check "the login succeeds" "$OUT" '"username":"alice"'
  refute "the session id was regenerated on login" "$OUT" "\\"session_id\\":\\"$SID\\""
  check "the response confirms the id changed" "$OUT" '"session_id_changed_on_login":true'
  # The old, planted session id must no longer be authenticated. The cookie jar
  # now holds the NEW id, so the check is that the new session works while the
  # old id is dead: presenting the old id directly must not authenticate.
  OUT="$(curl -s -b "$COOKIE_JAR" "$API/api/a07/session/whoami")"
  check "the new session id is authenticated" "$OUT" '"username":"alice"'
  OUT="$(curl -s -H "Cookie: JSESSIONID=$SID" "$API/api/a07/session/whoami")"
  refute "the pre-login session id is no longer authenticated" "$OUT" '"username":"alice"'
  rm -f "$COOKIE_JAR"
fi""",
    "verify-labs.sh: Lab 18 expectations inverted",
    sentinel='check "the response confirms the id changed"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 18 expectations ------------------

replace_once(
    WALKTHROUGH,
    """check "the pre-login session id is now authenticated" \\
  "$(curl -s -b "$JAR" "$API/api/a07/session/whoami")" '"username":"alice"'
check "the session id was not regenerated" \\
  "$(curl -s -b "$JAR" "$API/api/a07/session/whoami")" "$SID"
rm -f "$JAR\"""",
    """if [[ "$(curl -s -b "$JAR" "$API/api/a07/session/whoami")" == *'"username":"alice"'* ]]; then
  printf '\\033[32m  PASS\\033[0m the new session id is authenticated\\n'
  PASS=$((PASS + 1))
else
  printf '\\033[31m  FAIL\\033[0m the new session id is not authenticated\\n'
  FAIL=$((FAIL + 1))
fi
# The cookie jar now holds the NEW id, so the old, planted id is presented
# directly. It must no longer authenticate.
if [[ "$(curl -s -H "Cookie: JSESSIONID=$SID" "$API/api/a07/session/whoami")" == *'"username":"alice"'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the pre-login session id is still authenticated\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the pre-login session id is no longer authenticated\\n'
  PASS=$((PASS + 1))
fi
rm -f "$JAR\"""",
    "verify-walkthrough.sh: Lab 18 expectation inverted",
    sentinel="the pre-login session id is no longer authenticated",
)

# --- 3. labs.meta.yaml: the Lab 18 fix text -----------------------------------

replace_once(
    META,
    """      Spring's `request.changeSessionId()` is the equivalent.
    source: core/src/main/java/com/securebank/lab/a07/Lab18SessionController.java""",
    """      Spring's `request.changeSessionId()` is the equivalent.

      **What was changed:** the session id is now rotated at the exact moment the
      identity is attached to the session, using `request.changeSessionId()`. The
      id that existed before the login is abandoned, so an attacker who planted a
      cookie beforehand is left holding a session that is no longer
      authenticated. The response also reports `session_id_changed_on_login`.
    source: core/src/main/java/com/securebank/lab/a07/Lab18SessionController.java""",
    "labs.meta.yaml: Lab 18 fix text",
    sentinel="**What was changed:** the session id is now rotated at the exact moment",
)

print("Lab 18 fix applied.")
