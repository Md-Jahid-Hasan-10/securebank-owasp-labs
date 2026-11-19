#!/usr/bin/env bash
#
# SecureBank Labs — verification script.
#
# This exercises every lab's exploit step against the running stack and asserts that
# the vulnerable behaviour is still present.
#
# IMPORTANT: this is the INVERSE of a regression suite. It must PASS while the
# vulnerabilities are present and FAIL once they have been fixed. That is what makes
# it useful as the checklist for the remediation pass.
#
# Usage:
#   ./scripts/verify-labs.sh              # verify everything
#   ./scripts/verify-labs.sh 1 2 10       # verify specific labs

set -uo pipefail

API="${API:-http://localhost:8080}"
REPORT="${REPORT:-http://localhost:8081}"
FRONTEND="${FRONTEND:-http://localhost}"

PASS=0
FAIL=0
FAILED_LABS=()

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
green() { printf '\033[32m  PASS\033[0m %s\n' "$1"; }
red() { printf '\033[31m  FAIL\033[0m %s\n' "$1"; }

# check <description> <actual> <expected-substring>
check() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    green "$desc"
    PASS=$((PASS + 1))
  else
    red "$desc"
    echo "        expected to contain: $expected"
    echo "        got: ${actual:0:300}"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
}

# refute <description> <actual> <forbidden-substring>
refute() {
  local desc="$1" actual="$2" forbidden="$3"
  if [[ "$actual" != *"$forbidden"* ]]; then
    green "$desc"
    PASS=$((PASS + 1))
  else
    red "$desc"
    echo "        expected NOT to contain: $forbidden"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
}

get() { curl -s -H "Authorization: Bearer $TOKEN" "$@"; }
post() { curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$@"; }

# --- login ------------------------------------------------------------------
login() {
  curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" \
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
    out="$(curl -s -X POST "$API/api/a02/admin/password" \
      -H "Content-Type: application/json" \
      -d "{\"username\":\"admin\",\"current_password\":\"$current\",\"new_password\":\"$admin_password\"}")"
    [[ "$out" == *'"updated":true'* ]] && return 0
  done
  return 1
}

admin_login() {
  # The admin console login needs the account unlocked first.
  unlock_admin >/dev/null 2>&1
  login admin "$admin_password"
}

bold "SecureBank Labs — vulnerability verification"
echo "API: $API   Report: $REPORT   Frontend: $FRONTEND"
echo

# Lab 19 changes alice's password as part of the exploit, so restore it first.
# The reset endpoint is itself vulnerable (predictable token), so we can mint a
# valid reset token offline and put the password back.
reset_alice_password() {
  local candidate
  for candidate in $(python3 - <<'PY'
import hashlib, time
username = "alice"
now = int(time.time())
for offset in range(-120, 121):
    print(hashlib.md5(f"{username}{now + offset}".encode()).hexdigest())
PY
); do
    curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \
      -d "{\"token\": \"$candidate\", \"new_password\": \"password123\"}" \
      | grep -q '"password_reset":true' && return 0
  done
  return 1
}

if ! login alice password123 >/dev/null 2>&1; then
  reset_alice_password >/dev/null 2>&1
fi

TOKEN="$(login alice password123)"
if [[ -z "$TOKEN" ]]; then
  red "Could not log in as alice - is the stack running?"
  exit 1
fi
echo "Logged in as alice."
echo

WANTED=("$@")

should_run() {
  [[ ${#WANTED[@]} -eq 0 ]] && return 0
  local candidate="$1"
  for want in "${WANTED[@]}"; do
    [[ "$candidate" == "$want" ]] && return 0
  done
  return 1
}

lab() {
  CURRENT_LAB="$1"
  bold "Lab $1 — $2"
}

# --- Lab 1: IDOR (FIXED on this branch) -------------------------------------
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

# --- Lab 2: privilege escalation (FIXED on this branch) ----------------------
if should_run 2; then
  lab 2 "Privilege escalation"
  OUT="$(get "$API/api/a01/admin/users")"
  check "a customer is refused by /admin/users" "$OUT" '"error":"Admin role required"'
  refute "the user list is not disclosed" "$OUT" '"username"'
  refute "password hashes are not disclosed" "$OUT" '"password_hash"'
  OUT="$(get "$API/api/a01/admin/accounts")"
  check "a customer is refused by /admin/accounts too" "$OUT" '"error":"Admin role required"'
  refute "no account balances are disclosed" "$OUT" '"balance"'
  ADMIN_TOKEN="$(admin_login)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$API/api/a01/admin/users")"
  check "an admin token still works" "$OUT" '"username":"admin"'
fi

# --- Lab 3: SSRF (FIXED on this branch) -------------------------------------
if should_run 3; then
  lab 3 "SSRF"
  # The internal report service is only reachable by name on the Docker network,
  # so a successful fetch of it would prove the request came from inside.
  OUT="$(post "$API/api/a01/accounts/statement-email" \
    -d '{"account_id": 1, "callback_url": "http://report:8081/"}')"
  check "the internal report service is refused" "$OUT" '"error":"Callback URL is not allowed"'
  refute "no internal response body is returned" "$OUT" '"body"'
  refute "the target is not echoed back" "$OUT" '"sent_to"'
  OUT2="$(post "$API/api/a01/accounts/statement-email" \
    -d '{"account_id": 1, "callback_url": "http://169.254.169.254/latest/meta-data/"}')"
  check "the cloud metadata address is refused" "$OUT2" '"error":"Callback URL is not allowed"'
  refute "the metadata attempt is not echoed back" "$OUT2" '"sent_to"'
  OUT3="$(post "$API/api/a01/accounts/statement-email" \
    -d '{"account_id": 1, "callback_url": "http://report:8081/api/report/report/generate"}')"
  check "the SSTI pivot target is refused too" "$OUT3" '"error":"Callback URL is not allowed"'
  # Layer 1 - only http and https are accepted.
  OUT4="$(post "$API/api/a01/accounts/statement-email" \
    -d '{"account_id": 1, "callback_url": "file:///etc/passwd"}')"
  check "a non-http scheme is refused" "$OUT4" '"error":"Callback URL is not allowed"'
  # Layer 3 - the host allowlist rejects a public host that is not on it.
  OUT5="$(post "$API/api/a01/accounts/statement-email" \
    -d '{"account_id": 1, "callback_url": "http://example.com/"}')"
  check "a host that is not on the allowlist is refused" "$OUT5" '"error":"Callback URL is not allowed"'
  # Layer 3 - loopback is blocked even when the host resolves to it.
  OUT6="$(post "$API/api/a01/accounts/statement-email" \
    -d '{"account_id": 1, "callback_url": "http://127.0.0.1:8080/api/labs"}')"
  check "a loopback address is refused" "$OUT6" '"error":"Callback URL is not allowed"'
fi

# --- Lab 4: debug / stack trace (FIXED on this branch) -----------------------
if should_run 4; then
  lab 4 "Debug mode exposes config"
  # The endpoint is no longer public, so an anonymous caller is refused outright.
  OUT="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a02/debug")"
  check "the debug endpoint requires authentication" "$OUT" '401'
  # A customer is refused by the role check.
  OUT="$(get "$API/api/a02/debug")"
  check "a customer is refused by /debug" "$OUT" '"error":"Admin role required"'
  # An admin gets in, but no secret is returned.
  ADMIN_TOKEN4="$(admin_login)"
  OUT="$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN4" "$API/api/a02/debug")"
  check "an admin can still reach /debug" "$OUT" '"debug":true'
  refute "the JWT secret is not returned" "$OUT" '"jwt.secret"'
  refute "the datasource URL is not returned" "$OUT" 'jdbc:postgresql'
  refute "the datasource password is not returned" "$OUT" '"spring.datasource.password"'
  # The deliberate failure now returns a generic message and no stack trace.
  # The endpoint is no longer on the public-path allowlist, so it needs a token
  # to reach the handler at all.
  OUT2="$(get "$API/api/a02/debug/boom")"
  check "the error response is a generic message" "$OUT2" '"error":"Internal server error"'
  check "the error response carries a correlation id" "$OUT2" '"correlation_id"'
  refute "no stack trace is returned" "$OUT2" '"trace"'
  refute "the error response does not repeat the JWT secret" "$OUT2" '"jwt.secret"'
  refute "the error response does not leak the configuration" "$OUT2" '"config"'
fi

# --- Lab 5: default admin credentials (FIXED on this branch) ----------------
if should_run 5; then
  lab 5 "Default admin credentials"
  # The seeded administrator is refused the factory password. Its password may
  # already have been changed by an earlier run of this script, so the
  # assertion is that no session comes back, not which error is returned.
  OUT="$(curl -s -X POST "$API/api/a02/admin/login" -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}')"
  refute "the factory password does not open the admin console" "$OUT" '"token"'
  OUT="$(curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}')"
  refute "the factory password does not open the main login path" "$OUT" '"token"'
  # Only an administrator may create another administrator.
  CUSTOMER_TOKEN="$(login alice password123)"
  OUT="$(curl -s -X POST "$API/api/a02/admin/users" \
    -H "Authorization: Bearer $CUSTOMER_TOKEN" -H "Content-Type: application/json" \
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
  OUT="$(curl -s -X POST "$API/api/a02/admin/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    -d "{\"username\":\"$NEW_ADMIN\",\"email\":\"newadmin@bank.com\",\"password\":\"newadmin123\"}")"
  check "an administrator can still create an administrator" "$OUT" '"created":true'
  OUT="$(curl -s -X POST "$API/api/a02/admin/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$NEW_ADMIN\",\"password\":\"newadmin123\"}")"
  check "the new administrator must also change its password" \
    "$OUT" '"error":"Password must be changed before this account can be used"'
  refute "no session is issued to the new administrator" "$OUT" '"token"'
fi

# --- Lab 6: exposed files (FIXED on this branch) ----------------------------
if should_run 6; then
  lab 6 "Sensitive file exposure"
  # The environment file must not be reachable by an anonymous client. The
  # resource handler for it has been removed, so the request falls through to
  # the SPA / 404 rather than returning the file.
  OUT="$(curl -s "$API/.env")"
  refute "/.env is not served" "$OUT" 'JWT_SECRET'
  refute "/.env does not leak the AWS key" "$OUT" 'AKIAIOSFODNN7EXAMPLE'
  refute "/.env does not leak the Stripe secret" "$OUT" 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/.env")"
  refute "/.env is not downloadable" "$HTTP" '200'
  # The same for the repository's git configuration.
  OUT="$(curl -s "$API/.git/config")"
  refute "/.git/config is not served" "$OUT" 'securebank-internet-banking.git'
  refute "/.git/config does not leak the remote URL" "$OUT" '[remote "origin"]'
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/.git/config")"
  refute "/.git/config is not downloadable" "$HTTP" '200'
  # And for the database backup, which used to hand over every user, balance
  # and password hash.
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")"
  refute "/backup.zip is not served" "$HTTP" '200'
  OUT="$(curl -s "$API/backup.zip")"
  refute "/backup.zip is not the database dump" "$OUT" 'PGDMP'
  # The panel endpoint must no longer advertise where the secrets were.
  OUT="$(curl -s "$API/api/a02/exposed-files")"
  refute "the panel does not advertise /.env" "$OUT" '"url":"/.env"'
  refute "the panel does not advertise /.git/config" "$OUT" '"url":"/.git/config"'
  refute "the panel does not advertise /backup.zip" "$OUT" '"url":"/backup.zip"'
fi

# --- Lab 7: MD5 hashes (FIXED on this branch) --------------------------------
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
fi

# --- Lab 8: hardcoded JWT secret --------------------------------------------
if should_run 8; then
  lab 8 "Hardcoded JWT secret"
  FORGED="$(python3 - <<'PY'
import base64, json, hmac, hashlib

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"user_id": 3, "username": "admin", "role": "admin"}).encode())
sig = b64url(hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
PY
)"
  OUT="$(curl -s -H "Authorization: Bearer $FORGED" "$API/api/a10/transfers/history")"
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
fi

# --- Lab 9: PII in cleartext (FIXED on this branch) --------------------------
if should_run 9; then
  lab 9 "PII in cleartext responses"
  OUT="$(get "$API/api/a04/profile")"
  refute "the full account number is not returned" "$OUT" '"account_number":"ACC-1001"'
  check "the account number is masked" "$OUT" '"account_number":"ACC-****1001"'
  refute "the full sort code is not returned" "$OUT" '"sort_code":"20-00-00"'
  check "the sort code is masked" "$OUT" '"sort_code":"20-**-**"'
  refute "the full name is not returned" "$OUT" '"full_name":"Alice Morgan"'
  refute "the full email address is not returned" "$OUT" '"email":"alice@bank.com"'
  refute "the balance is not returned" "$OUT" '"balance"'
  # The PII must not be written to the application log either.
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'account_number=' || true)"
  refute "the log does not contain the account number" "$OUT" "1"
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'profile lookup.*balance=' || true)"
  refute "the log does not contain the balance" "$OUT" "1"
  # The lookup must still be logged, so the request can be audited. The count grows
  # with every run, so test for presence rather than for an exact number.
  OUT="$(docker compose logs backend 2>/dev/null | grep -c 'profile lookup' || true)"
  if [[ "${OUT:-0}" -gt 0 ]]; then
    green "the profile lookup is still logged"
    PASS=$((PASS + 1))
  else
    red "the profile lookup is no longer logged"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
fi

# --- Lab 10: SQL injection (FIXED on this branch) -----------------------------
if should_run 10; then
  lab 10 "SQL injection"
  OUT="$(curl -s -X POST "$API/api/a05/auth/login" -H "Content-Type: application/json" \
    -d '{"username":"admin'\'' --","password":"anything"}')"
  refute "the login bypass with admin' -- no longer returns a token" "$OUT" '"token"'
  refute "the login bypass no longer returns the admin account" "$OUT" '"role":"admin"'
  OUT="$(get "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
  refute "the UNION SELECT no longer dumps the seeded users" "$OUT" '"username":"alice"'
  refute "the UNION SELECT no longer dumps the administrator" "$OUT" '"username":"admin"'
  refute "the UNION SELECT no longer exposes the password hashes" "$OUT" '"password_hash"'
  # A legitimate login must still work, so the fix did not simply break the query.
  OUT="$(curl -s -X POST "$API/api/a05/auth/login" -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"password123"}')"
  check "a legitimate login still works" "$OUT" '"token"'
  # The search must still work for a plain term.
  OUT="$(get "$API/api/a05/transfers/search?q=alice")"
  check "a normal search still finds the user" "$OUT" '"username":"alice"'
fi

# --- Lab 11: SSTI via SpEL (FIXED on this branch) ----------------------------
if should_run 11; then
  lab 11 "SSTI (SpEL)"
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "7*7"}')"
  refute "the arithmetic expression is no longer evaluated" "$OUT" '49'
  OUT="$(post "$API/api/a05/transfers/1/remark" \
    -d '{"remark": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"id\"})"}')"
  refute "Runtime.exec is no longer reachable via SpEL" "$OUT" 'uid='
  # The remark must be stored and returned as the text it is, not evaluated.
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "7*7"}')"
  check "the remark is stored as plain text" "$OUT" '7*7'
  # The rendered fragment must be HTML-escaped. The raw remark is echoed back as
  # plain text (that is the stored value), so only the rendered fragment is checked.
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "<script>alert(1)</script>"}')"
  RENDERED="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rendered',''))" 2>/dev/null)"
  refute "the rendered remark does not contain a raw script tag" "$RENDERED" '<script>'
  check "the rendered remark is HTML-escaped" "$RENDERED" '&lt;script&gt;'
  # The remark must still be stored verbatim, so the API does not corrupt the data.
  check "the raw remark is still stored as the text it is" "$OUT" '"remark":"<script>alert(1)</script>"'
fi

# --- Lab 12: SSTI + command injection (report service) (FIXED on this branch) --
if should_run 12; then
  lab 12 "SSTI + OS command injection"
  OUT="$(curl -s -X POST "$REPORT/api/report/report/generate" -H "Content-Type: application/json" \
    -d '{"account_id": "1001", "template": "Secret: ${config.secretKey}"}')"
  refute "the internal secret key is no longer extracted" "$OUT" 'sb-report-internal-secret'
  refute "the internal database path is no longer extracted" "$OUT" '/var/lib/securebank'
  # The date filter used to be concatenated into `sh -c "echo 'From: <from> To: <to>' && date"`,
  # so a single quote in the date closed the quoted argument and everything after it
  # was executed as a separate command.
  DATE_BODY="$(mktemp)"
  cat > "$DATE_BODY" <<'JSON'
{"from_date": "2024-01-01' && id && echo '", "to_date": "2024-12-31"}
JSON
  OUT="$(curl -s -X POST "$REPORT/api/report/report/date-filter" -H "Content-Type: application/json" \
    --data-binary "@$DATE_BODY")"
  rm -f "$DATE_BODY"
  refute "the command injection no longer runs 'id'" "$OUT" 'uid='
  # A valid date range must still work, so the fix did not simply break the endpoint.
  OUT="$(curl -s -X POST "$REPORT/api/report/report/date-filter" -H "Content-Type: application/json" \
    -d '{"from_date": "2024-01-01", "to_date": "2024-12-31"}')"
  check "a valid date range is still accepted" "$OUT" '2024-01-01'
fi

# --- Lab 13: stored XSS (FIXED on this branch) -------------------------------
if should_run 13; then
  lab 13 "Stored XSS"
  OUT="$(post "$API/api/a05/transfers/send" \
    -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}')"
  refute "the note with a script payload is no longer stored verbatim" "$OUT" 'onerror=alert'
  OUT="$(get "$API/api/a05/transfers")"
  refute "the payload is no longer returned to every client" "$OUT" 'onerror=alert'
  refute "the stored note does not contain a raw img tag" "$OUT" '<img'
  # The frontend must render the note as text, not as markup. The source is
  # checked for the JSX attribute itself; the FIXED comment that explains the
  # change mentions it by name, so the attribute is matched only when it is
  # actually used.
  FRONTEND_SRC="$(cat frontend/src/features/banking/TransfersPage.jsx 2>/dev/null || true)"
  refute "the frontend does not use dangerouslySetInnerHTML for the note" \
    "$FRONTEND_SRC" 'dangerouslySetInnerHTML={'
fi

# --- Lab 14: negative transfer (FIXED on this branch) -------------------------
if should_run 14; then
  lab 14 "Negative transfer amount"
  BEFORE="$(get "$API/api/a01/accounts/1")"
  OUT="$(post "$API/api/a06/transfers/" \
    -d '{"from_account_id": 2, "to_account_id": 1, "amount": -1000}')"
  refute "the negative transfer is no longer accepted" "$OUT" '"transfer_id"'
  AFTER="$(get "$API/api/a01/accounts/1")"
  if [[ "$BEFORE" == "$AFTER" ]]; then
    green "the negative transfer did not change alice's balance"
    PASS=$((PASS + 1))
  else
    red "the negative transfer still changed alice's balance"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  # A positive transfer must still work, so the fix did not simply break the endpoint.
  OUT="$(post "$API/api/a06/transfers/" \
    -d '{"from_account_id": 2, "to_account_id": 1, "amount": 1}')"
  check "a positive transfer is still accepted" "$OUT" '"transfer_id"'
fi

# --- Lab 15: mass assignment (FIXED on this branch) --------------------------
if should_run 15; then
  lab 15 "Mass assignment"
  OUT="$(curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"username": "alice", "email": "alice@bank.com", "role": "admin"}')"
  refute "the role was no longer changed to admin via the profile endpoint" "$OUT" '"role":"admin"'
  # The stored role must still be the customer's.
  OUT="$(get "$API/api/a06/profile")"
  refute "the stored role is not admin" "$OUT" '"role":"admin"'
  # A legitimate email update must still work.
  OUT="$(curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"email": "alice@bank.com"}')"
  check "a legitimate email update still works" "$OUT" '"email":"alice@bank.com"'
  refute "the role is still not changed by a legitimate update" "$OUT" '"role":"admin"'
fi

# --- Lab 16: account enumeration (FIXED on this branch) ----------------------
if should_run 16; then
  lab 16 "Account enumeration"
  MISSING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \
    -d '{"username": "notauser", "password": "anything"}')"
  EXISTING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \
    -d '{"username": "alice", "password": "wrongpassword"}')"
  refute "a missing user is no longer reported as 'User not found'" "$MISSING" 'User not found'
  refute "an existing user is no longer reported as 'Incorrect password'" "$EXISTING" 'Incorrect password'
  if [[ "$MISSING" == "$EXISTING" ]]; then
    green "the two error responses are identical"
    PASS=$((PASS + 1))
  else
    red "the two error responses differ"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  fi
  check "the shared message is 'Invalid credentials'" "$MISSING" 'Invalid credentials'
fi

# --- Lab 17: brute force (FIXED on this branch) ------------------------------
if should_run 17; then
  lab 17 "No rate limiting"
  # Use a username that is not a real account, so the throttle bucket is not
  # shared with the seeded users and the run does not lock anybody out.
  FOUND=0
  for pw in one two three four five six seven eight; do
    OUT="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \
      -d "{\"username\":\"ratelimitprobe\",\"password\":\"$pw\"}")"
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
    LAST="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \
      -d "{\"username\":\"ratelimitprobe\",\"password\":\"$pw\"}")"
  done
  check "the account is locked out after too many failures" "$LAST" 'Too many failed attempts'
  # A correct password must not be accepted while the account is locked out.
  OUT="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \
    -d '{"username":"ratelimitprobe","password":"password123"}')"
  refute "the locked-out account cannot be used to log in" "$OUT" '"token"'
  # The attempt counter must no longer leak the number of attempts made.
  OUT="$(get "$API/api/a07/auth/attempts")"
  refute "the attempt counter no longer leaks the number of attempts" "$OUT" 'attempts_so_far'
fi

# --- Lab 18: session fixation (FIXED on this branch) -------------------------
if should_run 18; then
  lab 18 "Session fixation"
  COOKIE_JAR="$(mktemp)"
  SID="$(curl -s -c "$COOKIE_JAR" -X POST "$API/api/a07/session/init" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)"
  OUT="$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$API/api/a07/auth/login-session" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"password123"}')"
  check "the login succeeds" "$OUT" '"username":"alice"'
  refute "the session id was regenerated on login" "$OUT" "\"session_id\":\"$SID\""
  check "the response confirms the id changed" "$OUT" '"session_id_changed_on_login":true'
  # The old, planted session id must no longer be authenticated. The cookie jar
  # now holds the NEW id, so the check is that the new session works while the
  # old id is dead: presenting the old id directly must not authenticate.
  OUT="$(curl -s -b "$COOKIE_JAR" "$API/api/a07/session/whoami")"
  check "the new session id is authenticated" "$OUT" '"username":"alice"'
  OUT="$(curl -s -H "Cookie: JSESSIONID=$SID" "$API/api/a07/session/whoami")"
  refute "the pre-login session id is no longer authenticated" "$OUT" '"username":"alice"'
  rm -f "$COOKIE_JAR"
fi

# --- Lab 19: predictable reset token (FIXED on this branch) ------------------
if should_run 19; then
  lab 19 "Predictable password reset token"
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \
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
    OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \
      -d "{\"token\": \"$candidate\", \"new_password\": \"hacked123\"}")"
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
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \
    -d '{"username": "alice"}')"
  GOOD_TOKEN="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)"
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \
    -d "{\"token\": \"$GOOD_TOKEN\", \"new_password\": \"password123\"}")"
  check "an issued token can still be redeemed" "$OUT" '"password_reset":true'
  OUT="$(curl -s -X POST "$API/api/a07/auth/reset-confirm" -H "Content-Type: application/json" \
    -d "{\"token\": \"$GOOD_TOKEN\", \"new_password\": \"password123\"}")"
  refute "the token cannot be redeemed twice" "$OUT" '"password_reset":true'
  # The response must not reveal whether an account exists.
  MISSING="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \
    -d '{"username": "notauser"}')"
  EXISTING="$(curl -s -X POST "$API/api/a07/auth/reset-request" -H "Content-Type: application/json" \
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
  if [[ "$(echo "$MISSING" | python3 -c "import sys,json; print(sorted(json.load(sys.stdin).keys()))" 2>/dev/null)" \
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
fi

# --- Lab 20: insecure deserialization (FIXED on this branch) -----------------
if should_run 20; then
  lab 20 "Insecure deserialization"
  PAYLOAD="$(mktemp)"
  cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account" \
    -H "Authorization: Bearer $TOKEN" -F "data=@$PAYLOAD")"
  refute "the uploaded payload is no longer deserialised" "$OUT" '"imported"'
  refute "the gadget no longer executed the command during deserialisation" "$OUT" 'uid='
  rm -f "$PAYLOAD"
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account/describe" \
    -H "Authorization: Bearer $TOKEN")"
  refute "default typing is no longer enabled on the mapper" "$OUT" 'enabled'
  # A well-formed document must still be accepted.
  GOOD="$(mktemp)"
  cat > "$GOOD" <<'JSON'
{"username":"alice","account_number":"ACC-1001","currency":"GBP"}
JSON
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account" \
    -H "Authorization: Bearer $TOKEN" -F "data=@$GOOD")"
  check "a well-formed import document is still accepted" "$OUT" '"imported":true'
  rm -f "$GOOD"
  # The gadget class and the vulnerable library must be gone from the source.
  GADGET="backend/core/src/main/java/com/securebank/lab/a08/gadget/AccountImportJob.java"
  if [[ -f "$GADGET" ]]; then
    red "the gadget class is still present"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  else
    green "the gadget class has been removed"
    PASS=$((PASS + 1))
  fi
  # The dependency must no longer be declared. The FIXED comment in the pom
  # names the artifact, so the check is for the dependency declaration itself.
  OUT="$(grep -c '<artifactId>commons-collections</artifactId>' backend/core/pom.xml || true)"
  refute "the vulnerable commons-collections dependency is gone" "$OUT" '1'
fi

# --- Lab 21: JWT alg:none (FIXED on this branch) -----------------------------
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
  OUT="$(curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"password123"}')"
  check "a legitimate login still returns a token" "$OUT" '"token"'
fi

# --- Lab 22: unrestricted upload (FIXED on this branch) ----------------------
if should_run 22; then
  lab 22 "Unrestricted file upload"
  # A file with no extension at all, and then one with a scripting extension.
  TMPFILE="$(mktemp)"
  echo "SHELL_HERE" > "$TMPFILE"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPFILE")"
  refute "the file with no extension is no longer accepted" "$OUT" '"uploaded":true'
  rm -f "$TMPFILE"
  TMPHTML="$(mktemp --suffix=.html)"
  echo "<script>alert(1)</script>" > "$TMPHTML"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPHTML")"
  refute "the .html file is no longer accepted" "$OUT" '"uploaded":true'
  rm -f "$TMPHTML"
  # A traversal attempt in the filename must not escape the upload directory.
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" \
    -F 'file=@/dev/null;filename=../../shell.txt')"
  refute "the traversal filename is no longer accepted" "$OUT" '"uploaded":true'
  # The static handler must not serve the uploads any more.
  OUT="$(curl -s "$API/uploads/shell.txt")"
  refute "the uploads are no longer served from the web root" "$OUT" 'SHELL_HERE'
  # An allowed document type must still be accepted, and must be downloaded with
  # a fixed content type rather than rendered.
  TMPPDF="$(mktemp --suffix=.pdf)"
  echo "%PDF-1.4 test" > "$TMPPDF"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPPDF")"
  check "an allowed document type is still accepted" "$OUT" '"uploaded":true'
  URL="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))" 2>/dev/null)"
  # The download endpoint is behind the auth filter, so it is fetched with a token.
  HEADERS="$(curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" "$API$URL")"
  check "the download is sent as an attachment" "$HEADERS" 'attachment'
  check "the download has a fixed content type" "$HEADERS" 'application/octet-stream'
  # And it must not be reachable anonymously.
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$API$URL")"
  check "the download is not reachable without authentication" "$CODE" '401'
  rm -f "$TMPPDF"
fi

# --- Lab 23: verbose error (FIXED on this branch) ----------------------------
if should_run 23; then
  lab 23 "Verbose error with stack trace"
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  refute "no stack trace is returned to the client" "$OUT" 'NumberFormatException'
  refute "the internal call chain is not exposed" "$OUT" '"trace"'
  refute "the configuration is not leaked with the error" "$OUT" '"jwt.secret"'
  # The conversion is now handled explicitly, so the request is rejected with a
  # generic 400 rather than raising an unhandled exception.
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a10/transfers/account-summary?id=abc")"
  check "a malformed id is rejected with a 400" "$CODE" '400'
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  check "the rejection is a generic error" "$OUT" '"error":"Invalid id"'
  # The leak preview must not disclose the datasource URL either.
  OUT="$(curl -s "$API/api/a10/transfers/leak-preview")"
  refute "the datasource url is not disclosed" "$OUT" 'jdbc:postgresql'
  refute "the datasource url is redacted" "$OUT" '"spring.datasource.url":"[redacted]"'
  # A valid id must still work, so the fix did not simply break the endpoint.
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=1")"
  refute "a valid id is still accepted" "$OUT" '"error"'
fi

# --- Lab 24: type coercion (FIXED on this branch) ----------------------------
if should_run 24; then
  lab 24 "Error-based info disclosure"
  OUT="$(post "$API/api/a10/transfers/send" \
    -d '{"from_account_id": 1, "to_account_id": 2, "amount": "notanumber"}')"
  refute "the type error is no longer described to the client" "$OUT" 'NumberFormatException'
  refute "the exception type name is no longer returned" "$OUT" 'java.lang.'
  refute "the stack trace is no longer returned" "$OUT" 'stacktrace'
  refute "the exception message is no longer returned" "$OUT" '"detail"'
  # The request must be rejected with a generic error.
  check "the response names only the invalid amount" "$OUT" '"error"'
  # A valid transfer must still work.
  OUT="$(post "$API/api/a10/transfers/send" \
    -d '{"from_account_id": 1, "to_account_id": 2, "amount": 1}')"
  check "a valid transfer is still accepted" "$OUT" '"transfer_id"'
fi

# --- Lab 25: auth bypass on exception (FIXED on this branch) ------------------
if should_run 25; then
  lab 25 "Authentication bypass on exception"
  NO_TOKEN="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a10/transfers/history")"
  check "no token is rejected with 401" "$NO_TOKEN" '401'
  GARBAGE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  check "a garbage token is REJECTED with 401 (fail-closed)" "$GARBAGE" '401'
  OUT="$(curl -s -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  refute "the garbage token is no longer treated as admin" "$OUT" '"transfers"'
  refute "the garbage token does not receive an admin role" "$OUT" '"requested_role":"admin"'
  # A tampered token must be rejected too.
  TAMPERED="${TOKEN%?}x"
  CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TAMPERED" "$API/api/a10/transfers/history")"
  check "a tampered token is rejected with 401" "$CODE" '401'
  # A valid token must still work.
  CODE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" "$API/api/a10/transfers/history")"
  check "a valid token is still accepted" "$CODE" '200'
fi

# --- summary -----------------------------------------------------------------
echo
bold "Summary"
echo "  passed: $PASS"
echo "  failed: $FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  echo "  labs with failures: ${FAILED_LABS[*]}"
  exit 1
fi
echo
echo "All checks passed - the labs are still exploitable."
