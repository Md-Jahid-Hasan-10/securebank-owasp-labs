#!/usr/bin/env python3
"""Apply the Lab 21 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab21.py

The Java fix was written in:
  - core/security/JwtService.java   (decode() delegates to decodeStrict(), exp claim added)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 21 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 21 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 21 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 21: JWT alg:none ---------------------------------------------------
if should_run 21; then
  lab 21 "JWT algorithm confusion"
  FORGED="$(python3 - <<'PY'
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

header = b64url({"alg": "none", "typ": "JWT"})
payload = b64url({"user_id": 3, "username": "admin", "role": "admin"})
print(f"{header}.{payload}.")
PY
)"
  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
  check "unsigned alg:none token is accepted as admin" "$OUT" '"requested_role":"admin"'
fi""",
    """# --- Lab 21: JWT alg:none (FIXED on this branch) -----------------------------
if should_run 21; then
  lab 21 "JWT algorithm confusion"
  FORGED="$(python3 - <<'PY'
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

header = b64url({"alg": "none", "typ": "JWT"})
payload = b64url({"user_id": 3, "username": "admin", "role": "admin"})
print(f"{header}.{payload}.")
PY
)"
  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
  refute "the unsigned alg:none token is no longer accepted as admin" "$OUT" '"requested_role":"admin"'
  # A legitimate login must still work, so the fix did not simply break signing.
  OUT="$(curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \\
    -d '{"username":"alice","password":"password123"}')"
  check "a legitimate login still returns a token" "$OUT" '"token"'
fi""",
    "verify-labs.sh: Lab 21 expectations inverted",
    sentinel='refute "the unsigned alg:none token is no longer accepted as admin"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 21 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 25: auth bypass =="
check "a garbage token is accepted" \\
  "$(curl -s -o /dev/null -w '%{http_code}' \\
     -H "Authorization: Bearer THISISNOTAVALIDTOKEN" \\
     "$API/api/a10/transfers/history")" '200'""",
    """echo "== Lab 25: auth bypass =="
if [[ "$(curl -s -o /dev/null -w '%{http_code}' \\
     -H "Authorization: Bearer THISISNOTAVALIDTOKEN" \\
     "$API/api/a10/transfers/history")" == '200' ]]; then
  printf '\\033[31m  FAIL\\033[0m a garbage token is still accepted\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m a garbage token is no longer accepted\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 25 expectation inverted",
    sentinel="a garbage token is no longer accepted",
)

# --- 3. labs.meta.yaml: the Lab 21 fix text -----------------------------------

replace_once(
    META,
    """      Never pass `options={"verify_signature": false}`, and reject `alg: none`
      outright.
    source: core/src/main/java/com/securebank/core/security/JwtService.java""",
    """      Never pass `options={"verify_signature": false}`, and reject `alg: none`
      outright.

      **What was changed:** `decode()` no longer reads the token's own header. It
      delegates straight to the strict parser, which pins HS256, verifies the
      signature against the environment-supplied key and enforces the expiry, so
      there is no algorithm to confuse and an unsigned token has no signature to
      verify. The header-parsing helpers (`decodeSegment`, `padBase64`,
      `parseJsonObject`) have been deleted. The issued token now also carries an
      `exp` claim, so a stolen token expires on its own.
    source: core/src/main/java/com/securebank/core/security/JwtService.java""",
    "labs.meta.yaml: Lab 21 fix text",
    sentinel="**What was changed:** `decode()` no longer reads the token's own header",
)

print("Lab 21 fix applied.")
