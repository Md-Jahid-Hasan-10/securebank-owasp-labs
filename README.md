# SecureBank Labs

> OWASP Top 10 (2025) · 25 intentionally vulnerable labs · Spring Boot 3.3 · PostgreSQL · React

---

> [!CAUTION]
> # ⚠️ THIS APPLICATION IS INTENTIONALLY VULNERABLE
>
> Every one of the 25 vulnerabilities is **deliberate**. It exists so that you can
> practise exploiting it, and later practise fixing it.
>
> **Never deploy this anywhere reachable from the internet, and never put real
> credentials, real customer data or real money into it.** The seed data is fake.
>
> The project deliberately depends on packages that scanners flag
> (`commons-collections:3.2.1`, `Runtime.exec`, a hardcoded JWT secret). Those
> findings are the point of the exercise, not accidents.

---

## What this is

A realistic-looking internet banking application — React frontend, Spring Boot API,
a second Spring Boot "report" service, PostgreSQL — with 25 security flaws from
the OWASP Top 10 baked in.

Every flaw is marked in the source with a greppable comment:

```java
// VULN: [A05-Lab10] SQL Injection - user input concatenated into raw SQL
// FIX:  use PreparedStatement with ? placeholders
```

That gives you a checklist for the remediation pass:

```bash
# every intentional vulnerability
grep -rn "VULN:" backend/*/src/main/java | wc -l

# every lab, by tag
grep -rho "\[A[0-9]*-Lab[0-9]*\]" backend/*/src/main/java | sort -u -V
```

## Running it

```bash
docker compose up --build
```

| Service | URL | Health |
|---------|-----|--------|
| React frontend + lab panel | http://localhost | — |
| Core API | http://localhost:8080/api | http://localhost:8080/api/health |
| Report service | http://localhost:8081/api | http://localhost:8081/api/report/health |
| PostgreSQL | localhost:5432 (`securebank` / `securebank`) | — |

Compose waits for Postgres and the core API to report healthy before starting
the report service and the frontend.

Open http://localhost and sign in as `alice / password123`.

| Username | Password | Role |
|----------|----------|------|
| alice | password123 | customer |
| bob | qwerty | customer |
| admin | admin | admin |
| charlie | charlie | customer |

### The lab panel

The left sidebar has an **OWASP LABS** tree, grouped by category. Each lab page has
four tabs:

- **Exploit Steps** — the commands, with copy-pasteable curl
- **Affected Code** — the *live* Java source, extracted from the file on disk
- **Hint** — a nudge, not the answer
- **Fix** — the remediation

The Affected Code tab is generated from the real source files by
`scripts/sync-labs.py`, so it can never drift out of date. The Docker build runs
that script automatically before packaging the jar, so `docker compose up --build`
always ships a current panel. When working outside Docker (or after changing
Java code and wanting to preview the panel locally), run it by hand:

```bash
python3 scripts/sync-labs.py
```

The generated `labs.json` is gitignored — it is a build artefact, not a source
file. It is anchored on each lab's own `// VULN: [Axx-Labyy]` marker, so the
Affected Code tab always shows the vulnerable statement together with the
comment naming it.

## Verifying the labs

```bash
./scripts/verify-labs.sh          # all 25 labs
./scripts/verify-labs.sh 10 11 25 # specific labs
```

This script is the **inverse** of a regression suite: it must **pass** while the
vulnerabilities are present and **fail** once they have been fixed. That makes it
the checklist for the remediation pass — when you start closing holes, this script
is how you know you actually closed them.

`scripts/verify-walkthrough.sh` separately checks that every command shown in
`WALKTHROUGH.md` still works, `scripts/check-labs-json.py` validates the panel
payload the frontend consumes, and `scripts/check-stack.py` smoke-checks that all
four services are up and the Lab 6 file fixtures are still exposed.

## Layout

```
.
├── WALKTHROUGH.md          # the trainer walkthrough - every lab, step by step
├── docker-compose.yml
├── backend/
│   ├── pom.xml             # Maven parent (core + report modules)
│   ├── core/               # the main Spring Boot application
│   │   └── src/main/java/com/securebank/
│   │       ├── core/       # domain: user, account, transfer, security
│   │       └── lab/        # one package per OWASP category, one class per lab
│   └── report/             # the second Spring Boot application (Lab 12)
├── frontend/               # React + Vite
├── labs/
│   └── labs.meta.yaml      # lab content - the source of truth for the panel
└── scripts/
    ├── sync-labs.py        # meta yaml + java source -> labs.json
    ├── verify-labs.sh      # asserts every lab is still exploitable
    ├── verify-walkthrough.sh  # asserts every walkthrough command still works
    ├── check-labs-json.py  # validates the panel payload the frontend consumes
    └── check-stack.py      # smoke-checks every service and the Lab 6 fixtures
```

## Why there is no Spring Security

`spring-boot-starter-security` is **deliberately absent**. Its auto-configuration
would silently remediate Labs 1, 2, 15, 18, 21 and 25 the moment the dependency
landed — you would fix six labs without writing a line of code, and the exercise
would teach you nothing.

All authentication is hand-rolled in `com.securebank.core.security` so that every
flaw is explicit, visible and greppable.

## Development

```bash
# build
mvn -B -f backend/pom.xml package

# run the backend against a local Postgres
DB_HOST=localhost mvn -B -f backend/pom.xml -pl core spring-boot:run

# frontend dev server (proxies /api to localhost:8080)
cd frontend && npm install && npm run dev
```

Note the frontend pins **Vite 4** — Vite 5 requires Node 20.

## The labs

| # | Category | Lab | Severity |
|---|----------|-----|----------|
| 1 | A01 Broken Access Control | IDOR — read another customer's account | Low |
| 2 | A01 | Privilege escalation — customer → admin | Medium |
| 3 | A01 | SSRF — fetch internal URLs | High |
| 4 | A02 Misconfiguration | Debug mode — stack trace leaks config | Low |
| 5 | A02 | Default admin credentials | Low |
| 6 | A02 | Sensitive file exposure (.env, .git, backup.zip) | Medium |
| 7 | A04 Cryptographic Failures | Unsalted MD5 password hashes | Medium |
| 8 | A04 | Hardcoded JWT secret | Medium |
| 9 | A04 | PII in cleartext responses and logs | Low |
| 10 | A05 Injection | SQL injection — login bypass and data dump | High |
| 11 | A05 | SSTI via SpEL — RCE | High |
| 12 | A05 | SSTI + OS command injection (report service) | High |
| 13 | A05 | Stored XSS via transaction notes | Medium |
| 14 | A06 Insecure Design | Negative transfer amount | Medium |
| 15 | A06 | Mass assignment — self-promote to admin | Medium |
| 16 | A06 | Account enumeration via error messages | Low |
| 17 | A07 Authentication Failures | No rate limiting on login | Low |
| 18 | A07 | Session fixation | Medium |
| 19 | A07 | Predictable password reset token | High |
| 20 | A08 Integrity Failures | Insecure deserialization — RCE | High |
| 21 | A08 | JWT algorithm confusion (`alg: none`) | Medium |
| 22 | A08 | Unrestricted file upload | High |
| 23 | A10 Exceptional Conditions | Verbose error with config values | Low |
| 24 | A10 | Error-based info disclosure — type coercion | Medium |
| 25 | A10 | Auth bypass on exception — fail-open | High |

## Notes for the remediation pass

- Lab 10's `UNION` payload must match the query's column arity and order exactly:
  `username, password_hash, email, role, id`. Postgres rejects a mismatch with
  *"UNION types bigint and character varying cannot be matched"*.
- Lab 12's payload is `${config.secretKey}`, **not**
  `${T(...ReportConfig).secretKey}` — `T(...)` yields the `Class`, not the instance.
- Lab 20's type property is `@class` (Jackson's `As.PROPERTY` default), not `@type`.
- Lab 7's MD5 of `password123` is `482c811da5d5b4bc6d497ffa98491e38`. Older
  versions of the walkthrough listed a wrong hash.
- The database dump for Lab 6 is **PostgreSQL** — use `pg_restore`, not `sqlite3`.
