# Security Policy

## ⚠️ This repository contains intentional vulnerabilities

SecureBank Labs is a **deliberately vulnerable** training application. All 25 flaws
are intentional and marked in the source with a greppable comment:

```bash
# every intentional vulnerability (63 markers across 25 labs)
grep -rn "VULN:" backend/*/src/main/java | wc -l

# every lab, by tag
grep -rho "\[A[0-9]*-Lab[0-9]*\]" backend/*/src/main/java | sort -u -V
```

Every marker is followed by a `// FIX:` comment describing the remediation.

Findings reported by automated scanners — hardcoded secrets, `Runtime.exec`,
`commons-collections:3.2.1`, SQL string concatenation, permissive CORS — are
**the point of the exercise**, not accidents. Please do not report them.

**Never deploy this application on any reachable network. Never put real
credentials, real customer data or real money in it.** The seed data is fake.

## Branches

| Branch | State | Purpose |
|--------|-------|---------|
| `main` | 25 vulnerabilities **present** | The training target — practise here |
| `fixed` | 25 vulnerabilities **fixed** | Reference solution — see how each hole is closed |

## Reporting a real problem with the training infrastructure

If you find a bug in the *training infrastructure* — something that stops the
labs from working, rather than a vulnerability that is supposed to be there —
open a normal issue. It will be treated as a bug report.

Examples of real problems worth reporting:

- a lab that no longer reproduces its documented exploit
- the in-app lab panel failing to load, or showing stale source
- `verify-labs.sh` failing on an unmodified checkout
- the Docker build failing from a clean clone

For the 25 deliberate flaws, report nothing — they are intentional and closing
one of them defeats the exercise.

## Deployment warning

This repository is configured to be as unsafe as a real banking application
would be *if it were built badly*:

- authentication is hand-rolled rather than using Spring Security
- passwords are stored as unsalted MD5
- the JWT signing secret is committed in two places
- SQL is built by string concatenation
- a `backup.zip` of the live database is downloadable over HTTP

That is the lesson. Do not copy any of this pattern into anything real.
