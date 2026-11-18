# Practising and Contributing

Welcome. This repo is a self-contained OWASP Top 10 (2025) training range.

> **⚠️ The app is intentionally vulnerable.** Every flaw is deliberate and marked
> in the source with a `// VULN: [Axx-Labyy]` comment. See [`SECURITY.md`](SECURITY.md).

---

## Branches — read this first

| Branch | State | Use it for |
|--------|-------|------------|
| `main` | 25 vulnerabilities **present** | **Practising.** This is the training target. |
| `fixed` | 25 vulnerabilities **fixed** | **Learning.** The reference solution. |

`main` is the default branch and it **stays vulnerable**. Do not fix a lab on
`main` — that would remove the exercise for everyone who clones it.

---

## 1. Get the vulnerable target running

```bash
git clone https://github.com/<owner>/securebank-owasp-labs.git
cd securebank-owasp-labs
docker compose up --build
```

Open **http://localhost** — the React banking app loads automatically.

| Service | URL |
|---------|-----|
| React frontend + lab panel | http://localhost |
| Core API | http://localhost:8080/api |
| Report service | http://localhost:8081/api |

Sign in as `alice / password123`.

| Username | Password | Role |
|----------|----------|------|
| alice | password123 | customer |
| bob | qwerty | customer |
| admin | admin | admin |
| charlie | charlie | customer |

> **Note:** the Docker build generates the lab panel payload from the live Java
> sources, so a fresh clone works with no extra setup. There is no need to run
> `scripts/sync-labs.py` yourself unless you are changing Java code.

### The lab panel

The left sidebar has an **OWASP LABS** tree grouped by category. Every lab page
has four tabs:

- **Exploit Steps** — the commands, with copy-pasteable curl
- **Affected Code** — the *live* Java source, extracted from the file on disk
- **Hint** — a nudge, not the answer
- **Fix** — the remediation

The Affected Code tab is generated from the real source files, so it can never
drift out of date.

---

## 2. Work through the labs

[`WALKTHROUGH.md`](WALKTHROUGH.md) has every lab step by step, with the exact
commands, the expected output, and a suggested full-day / half-day schedule.

Work in any order you like. If you want a starting path, the half-day route is:

> Lab 1 (IDOR) → Lab 10 (SQLi) → Lab 11 (SSTI) → Lab 13 (XSS) →
> Lab 19 (reset token) → Lab 20 (deserialization RCE) → Lab 25 (auth bypass)

---

## 3. Verify before you change anything

```bash
./scripts/verify-labs.sh          # all 25 labs
./scripts/verify-labs.sh 10 11 25 # specific labs
```

**Read this carefully — it is the opposite of a normal test suite.**

`verify-labs.sh` runs each exploit and asserts that the *vulnerable* outcome
still happens. So:

| State | Expected result |
|-------|-----------------|
| Fresh, unmodified clone | `passed: 55   failed: 0` |
| After you fix Lab 1 | Lab 1's checks now **fail** |

That failing check **is** your evidence the hole is actually closed. If a lab you
have *not* touched starts failing, you have broken something else.

There are two more checks worth running:

```bash
./scripts/verify-walkthrough.sh   # every command in WALKTHROUGH.md still works
python3 scripts/check-stack.py     # all services up, Lab 6 fixtures exposed
```

---

## 4. Fixing the labs

Work on your own branch so `main` stays vulnerable:

```bash
git switch -c my-fixes
```

Fix one lab at a time. After each fix:

```bash
./scripts/verify-labs.sh <lab-number>   # should now fail for that lab
python3 scripts/sync-labs.py             # refresh the panel's Affected Code tab
git commit -am "fix(Axx-Labyy): what you changed"
```

Then compare your work against the reference solution:

```bash
git diff fixed -- backend/core/src/main/java/com/securebank/lab/a01/
```

### Rules

1. **Never fix a lab on `main`.** It must stay vulnerable.
2. **Never delete a `// VULN:` comment.** The greppability is the contract —
   it is how the labs, the panel and the verification script all find each other.
3. **Never add real secrets.** Fake values only.
4. **Never commit `backend/core/src/main/resources/labs/labs.json`** — it is a
   generated build artefact and is gitignored on purpose.
5. Run `python3 scripts/sync-labs.py` before committing any Java change.

---

## 5. See the reference solution

```bash
git switch fixed
docker compose down && docker compose up --build
```

Now every exploit fails. `./scripts/verify-labs.sh` reports `failed: 55` — which
is the proof that the application is secure.

To see every fix as a diff:

```bash
git diff main fixed -- backend/core/src/main/java
```

---

## Adding a new lab

New labs are welcome. The pieces that must line up:

1. **Java source** — put the controller in
   `backend/core/src/main/java/com/securebank/lab/aXX/`, and mark the flaw:

   ```java
   // VULN: [A05-Lab26] SQL Injection - the username is concatenated into raw SQL
   // FIX:  use a PreparedStatement with ? placeholders
   ```

2. **Metadata** — add an entry to `labs/labs.meta.yaml` with `id`, `category`,
   `categoryName`, `title`, `severity`, `objective`, `exploit`, `hint`, `fix`,
   `source` and `anchors`.

3. **Verification** — add an exploit check to `scripts/verify-labs.sh` that
   asserts the *vulnerable* outcome.

4. **Walkthrough** — add a section to `WALKTHROUGH.md` with the exact commands.

5. **Regenerate** — run `python3 scripts/sync-labs.py` and confirm the new lab
   appears in the in-app panel with its Affected Code tab populated.

Then verify the whole thing:

```bash
./scripts/verify-labs.sh
./scripts/verify-walkthrough.sh
python3 scripts/check-labs-json.py
```

---

## Reporting problems with the training infrastructure

If the labs themselves stop working — a documented exploit no longer reproduces,
the panel fails to load, the build breaks on a clean clone — open a normal
issue. For the 25 deliberate flaws, report nothing: see
[`SECURITY.md`](SECURITY.md).
