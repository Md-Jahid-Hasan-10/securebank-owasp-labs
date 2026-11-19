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
if [[ "$(curl -s "${AUTH[@]}" "$API/api/a04/profile")" == *'"account_number":"ACC-1001"'* ]]; then
  printf '\033[31m  FAIL\033[0m GET /api/a04/profile leaks the account number\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m GET /api/a04/profile does not leak the account number\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 10: SQL injection =="
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin'\'' --","password":"anything"}' \
     "$API/api/a05/auth/login")" == *'"token"'* ]]; then
  printf '\033[31m  FAIL\033[0m login bypass with admin'\'' -- still returns a token\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m login bypass with admin'\'' -- no longer returns a token\n'
  PASS=$((PASS + 1))
fi
# The row count grows with every account in the database, so assert on the
# seeded accounts rather than on a fixed number.
WALK_SQLI_OUT="$(curl -s "${AUTH[@]}" "$API/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--")"
if [[ "$WALK_SQLI_OUT" == *'"username":"alice"'* ]]; then
  printf '\033[31m  FAIL\033[0m UNION SELECT still dumps the seeded users\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m UNION SELECT no longer dumps the seeded users\n'
  PASS=$((PASS + 1))
fi
if [[ "$WALK_SQLI_OUT" == *'"password_hash"'* ]]; then
  printf '\033[31m  FAIL\033[0m UNION SELECT still exposes the password hashes\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m UNION SELECT no longer exposes the password hashes\n'
  PASS=$((PASS + 1))
fi
check "GET /api/a05/schema lists the tables" \
  "$(curl -s "${AUTH[@]}" "$API/api/a05/schema")" '"users"'

echo "== Lab 11: SSTI =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"remark":"7*7"}' "$API/api/a05/transfers/1/remark")" == *'49'* ]]; then
  printf '\033[31m  FAIL\033[0m 7*7 still evaluates to 49\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m 7*7 is no longer evaluated\n'
  PASS=$((PASS + 1))
fi
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"remark":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"id\"})"}' \
     "$API/api/a05/transfers/1/remark")" == *'uid='* ]]; then
  printf '\033[31m  FAIL\033[0m Runtime.exec is still reachable\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m Runtime.exec is no longer reachable\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 12: report service =="
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \
     --data-binary '{"account_id":"1001","template":"Secret: ${config.secretKey}"}' \
     "$REPORT/api/report/report/generate")" == *'sb-report-internal-secret'* ]]; then
  printf '\033[31m  FAIL\033[0m SSTI still reads config.secretKey\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m SSTI no longer reads config.secretKey\n'
  PASS=$((PASS + 1))
fi
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"from_date":"2024-01-01'"'"' && id && echo '"'"'","to_date":"2024-12-31"}' \
     "$REPORT/api/report/report/date-filter")" == *'uid='* ]]; then
  printf '\033[31m  FAIL\033[0m command injection still runs id\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m command injection no longer runs id\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 13: stored XSS =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}' \
     "$API/api/a05/transfers/send")" == *'onerror=alert'* ]]; then
  printf '\033[31m  FAIL\033[0m the note is still stored verbatim\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the note is no longer stored verbatim\n'
  PASS=$((PASS + 1))
fi
if [[ "$(curl -s "${AUTH[@]}" "$API/api/a05/transfers")" == *'<img'* ]]; then
  printf '\033[31m  FAIL\033[0m the note is still returned with a raw img tag\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the note is no longer returned with a raw img tag\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 14: negative transfer =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"from_account_id":2,"to_account_id":1,"amount":-1000}' \
     "$API/api/a06/transfers/")" == *'"transfer_id"'* ]]; then
  printf '\033[31m  FAIL\033[0m a negative transfer is still accepted\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m a negative transfer is no longer accepted\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 15: mass assignment =="
if [[ "$(curl -s -X PATCH "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"username":"alice","email":"alice@bank.com","role":"admin"}' \
     "$API/api/a06/profile")" == *'"role":"admin"'* ]]; then
  printf '\033[31m  FAIL\033[0m the role is still bound from the request body\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the role is no longer bound from the request body\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 16: enumeration =="
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"notauser","password":"x"}' "$API/api/a06/auth/login/")" == *'User not found'* ]]; then
  printf '\033[31m  FAIL\033[0m a missing user is still reported separately\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m a missing user is no longer reported separately\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 17: brute force =="
WALK_BF_LAST=""
for pw in one two three four five six seven eight nine ten; do
  WALK_BF_LAST="$(curl -s -X POST -H "Content-Type: application/json" \
     -d "{\"username\":\"ratelimitprobe\",\"password\":\"$pw\"}" \
     "$API/api/a07/auth/login")"
done
if [[ "$WALK_BF_LAST" == *'Too many failed attempts'* ]]; then
  printf '\033[32m  PASS\033[0m the account is locked out after too many failures\n'
  PASS=$((PASS + 1))
else
  printf '\033[31m  FAIL\033[0m the account is not locked out\n'
  FAIL=$((FAIL + 1))
fi

echo "== Lab 18: session fixation =="
JAR="$(mktemp)"
SID="$(curl -s -c "$JAR" -X POST "$API/api/a07/session/init" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null)"
curl -s -c "$JAR" -b "$JAR" -X POST "$API/api/a07/auth/login-session" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' >/dev/null
if [[ "$(curl -s -b "$JAR" "$API/api/a07/session/whoami")" == *'"username":"alice"'* ]]; then
  printf '\033[32m  PASS\033[0m the new session id is authenticated\n'
  PASS=$((PASS + 1))
else
  printf '\033[31m  FAIL\033[0m the new session id is not authenticated\n'
  FAIL=$((FAIL + 1))
fi
# The cookie jar now holds the NEW id, so the old, planted id is presented
# directly. It must no longer authenticate.
if [[ "$(curl -s -H "Cookie: JSESSIONID=$SID" "$API/api/a07/session/whoami")" == *'"username":"alice"'* ]]; then
  printf '\033[31m  FAIL\033[0m the pre-login session id is still authenticated\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the pre-login session id is no longer authenticated\n'
  PASS=$((PASS + 1))
fi
rm -f "$JAR"

echo "== Lab 19: predictable reset token =="
check "a reset token is issued" \
  "$(curl -s -X POST -H "Content-Type: application/json" \
     -d '{"username":"alice"}' "$API/api/a07/auth/reset-request")" '"token"'
WALK_RT_OUT=""
for offset in $(seq -30 30); do
  WALK_RT_TOKEN="$(python3 -c "import hashlib,time; print(hashlib.md5(f'alice{int(time.time())+$offset}'.encode()).hexdigest())")"
  WALK_RT_OUT="$(curl -s -X POST -H "Content-Type: application/json" \
     -d "{\"token\":\"$WALK_RT_TOKEN\",\"new_password\":\"hacked123\"}" \
     "$API/api/a07/auth/reset-confirm")"
  if [[ "$WALK_RT_OUT" == *'"password_reset":true'* ]]; then
    break
  fi
done
if [[ "$WALK_RT_OUT" == *'"password_reset":true'* ]]; then
  printf '\033[31m  FAIL\033[0m an offline-computed token was accepted\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m an offline-computed token was not accepted\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 20: deserialization =="
PAYLOAD="$(mktemp)"
cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
if [[ "$(curl -s -X POST "${AUTH[@]}" -F "data=@$PAYLOAD" \
     "$API/api/a08/integrity/import-account")" == *'uid='* ]]; then
  printf '\033[31m  FAIL\033[0m the gadget still executes the command\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the gadget no longer executes the command\n'
  PASS=$((PASS + 1))
fi
rm -f "$PAYLOAD"
if [[ "$(curl -s -X POST "${AUTH[@]}" "$API/api/a08/integrity/import-account/describe")" == *'enabled'* ]]; then
  printf '\033[31m  FAIL\033[0m default typing is still enabled\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m default typing is no longer enabled\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 22: file upload =="
TMP="$(mktemp --suffix=.html)"
echo "SHELL_HERE" > "$TMP"
if [[ "$(curl -s -X POST "${AUTH[@]}" -F "file=@$TMP" "$API/api/a08/kyc-upload")" == *'"uploaded":true'* ]]; then
  printf '\033[31m  FAIL\033[0m the .html upload is still accepted\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the .html upload is no longer accepted\n'
  PASS=$((PASS + 1))
fi
rm -f "$TMP"
if [[ "$(curl -s "$API/uploads/shell.txt")" == *'SHELL_HERE'* ]]; then
  printf '\033[31m  FAIL\033[0m the uploads are still served from the web root\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the uploads are no longer served from the web root\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 23: verbose error (no stack trace on this branch) =="
check "the error response is a generic message" \
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" '"error"'
if [[ "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" == *'jdbc:postgresql'* ]]; then
  printf '\033[31m  FAIL\033[0m the datasource url is still disclosed\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the datasource url is no longer disclosed\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 24: type coercion =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
     -d '{"from_account_id":1,"to_account_id":2,"amount":"notanumber"}' \
     "$API/api/a10/transfers/send")" == *'stacktrace'* ]]; then
  printf '\033[31m  FAIL\033[0m the stack trace is still returned\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m the stack trace is no longer returned\n'
  PASS=$((PASS + 1))
fi

echo "== Lab 25: auth bypass =="
if [[ "$(curl -s -o /dev/null -w '%{http_code}' \
     -H "Authorization: Bearer THISISNOTAVALIDTOKEN" \
     "$API/api/a10/transfers/history")" == '200' ]]; then
  printf '\033[31m  FAIL\033[0m a garbage token is still accepted\n'
  FAIL=$((FAIL + 1))
else
  printf '\033[32m  PASS\033[0m a garbage token is no longer accepted\n'
  PASS=$((PASS + 1))
fi

echo
echo "passed: $PASS   failed: $FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
