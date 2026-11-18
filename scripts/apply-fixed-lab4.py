#!/usr/bin/env python3
"""Apply the Lab 4 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab4.py

The Java fix itself was written by hand in Lab4DebugController.java and
Lab4ErrorController.java, and the config was changed in application.yml. This
script handles everything around it:

  1. backend/core/src/main/resources/application.yml - the server.error.* keys
     flip from always/always/true to never/never/false, and the marker comment
     is updated to match.
  2. scripts/verify-labs.sh - the Lab 4 expectations are inverted: they now
     assert that the exploit FAILS, not that it succeeds.
  3. scripts/verify-walkthrough.sh - the same inversion for the walkthrough.
  4. labs/labs.meta.yaml - the Lab 4 hint/fix text is replaced with the
     remediation as implemented, so the panel on this branch teaches the fix
     rather than describing a hypothetical one.

Lab 23 shares the global error handler with Lab 4, so its assertions are
inverted at the same time: the handler no longer returns a stack trace, which
means Lab 23's "a stack trace is returned" check has to become "no stack trace
is returned". Lab 23's own remediation - validating the id in
Lab23VerboseErrorController - belongs to the Lab 23 pass and is not done here.

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

YML = ROOT / "backend/core/src/main/resources/application.yml"
VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"

# --- application.yml --------------------------------------------------------

OLD_YML = """  error:
    # VULN: [A02-Lab4] / [A10-Lab23] Verbose stack traces are returned to the client.
    # Django's DEBUG=True analogue. Exposes config values, file paths and library versions.
    # FIX:  set to 'never' in production and configure a dedicated error page.
    include-stacktrace: never
    include-message: never
    include-exception: false
"""

NEW_YML = """  error:
    # FIXED: [A02-Lab4] / [A10-Lab23] Verbose stack traces are no longer returned to
    # the client. Django's DEBUG=True analogue. These exposed config values, file
    # paths and library versions on every unhandled error.
    include-stacktrace: never
    include-message: never
    include-exception: false
"""

# --- verify-labs.sh ---------------------------------------------------------

OLD_VERIFY = """# --- Lab 4: debug / stack trace ---------------------------------------------
if should_run 4; then
  lab 4 "Debug mode exposes config"
  OUT="$(curl -s "$API/api/a02/debug")"
  check "debug endpoint returns the JWT secret" "$OUT" '"jwt.secret":"secret"'
  check "debug endpoint returns the datasource URL" "$OUT" 'jdbc:postgresql'
  OUT2="$(curl -s "$API/api/a02/debug/boom")"
  check "unhandled error returns a stack trace" "$OUT2" 'Exception'
  check "the error response repeats the JWT secret" "$OUT2" '"jwt.secret":"secret"'
fi
"""

NEW_VERIFY = """# --- Lab 4: debug / stack trace (FIXED on this branch) -----------------------
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
"""

# --- verify-walkthrough.sh --------------------------------------------------

OLD_WALKTHROUGH = """echo "== Lab 4: debug =="
check "GET /api/a02/debug leaks jwt.secret" \\
  "$(curl -s "$API/api/a02/debug")" '"jwt.secret":"secret"'
check "GET /api/a02/debug/boom returns a stack trace" \\
  "$(curl -s "$API/api/a02/debug/boom")" 'Exception'
"""

NEW_WALKTHROUGH = """echo "== Lab 4: debug (fixed on this branch) =="
check "GET /api/a02/debug does not leak jwt.secret" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a02/debug")" '"error":"Admin role required"'
check "GET /api/a02/debug/boom returns a generic message" \\
  "$(curl -s "${AUTH[@]}" "$API/api/a02/debug/boom")" '"error":"Internal server error"'
"""

# --- verify-labs.sh, Lab 23 -------------------------------------------------
#
# Lab 23's exploit relies on the global error handler returning a stack trace.
# Lab 4's fix removes that handler's stack trace, so Lab 23's assertion is
# inverted here as well. Lab 23's own remediation - validating the id in
# Lab23VerboseErrorController - is done in the Lab 23 pass.

OLD_LAB23 = """# --- Lab 23: verbose error --------------------------------------------------
if should_run 23; then
  lab 23 "Verbose error with stack trace"
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  check "a stack trace is returned to the client" "$OUT" 'NumberFormatException'
  check "the trace names the internal parameter" "$OUT" 'account-summary'
fi
"""

NEW_LAB23 = """# --- Lab 23: verbose error (the global handler no longer leaks) -------------
if should_run 23; then
  lab 23 "Verbose error with stack trace"
  OUT="$(curl -s "$API/api/a10/transfers/account-summary?id=abc")"
  refute "no stack trace is returned to the client" "$OUT" 'NumberFormatException'
  refute "the internal call chain is not exposed" "$OUT" '"trace"'
  refute "the configuration is not leaked with the error" "$OUT" '"jwt.secret"'
fi
"""

# --- verify-walkthrough.sh, Lab 23 ------------------------------------------

OLD_WALKTHROUGH_23 = """echo "== Lab 23: verbose error =="
check "a stack trace is returned" \\
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" 'NumberFormatException'
check "the trace names the endpoint" \\
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" 'account-summary'
"""

NEW_WALKTHROUGH_23 = """echo "== Lab 23: verbose error (no stack trace on this branch) =="
check "the error response is a generic message" \\
  "$(curl -s "$API/api/a10/transfers/account-summary?id=abc")" '"error"'
"""

# --- labs.meta.yaml ---------------------------------------------------------

OLD_META = """    hint: >-
      Look for the endpoint that prints the Spring `Environment`.
    fix: >-
      Set `server.error.include-stacktrace=never` and `server.error.include-message=never`
      in production. Serve a generic error page and log the detail server-side only.
"""

NEW_META = """    hint: >-
      This lab is FIXED on the `fixed` branch. Compare it with `main` to see the
      original flaw:
      `git diff main fixed -- backend/core/src/main/java/com/securebank/lab/a02/`
    fix: >-
      Three changes, because the secret leaked from two places.

      **1. The debug endpoint requires the admin role.** It used to be reachable
      without authentication at all:

      ```java
      if (caller == null || !caller.isAdmin()) {
          return ResponseEntity.status(HttpStatus.FORBIDDEN)
                  .body(Map.of("error", "Admin role required"));
      }
      ```

      It also has to come off the auth filter's public-path allowlist, otherwise
      an anonymous caller reaches the controller instead of being turned away by
      the filter.

      **2. The endpoint no longer returns secrets.** `jwt.secret` and the
      datasource credentials are gone from the response entirely. No secret
      should ever travel in an HTTP response - not even to an administrator.

      **3. The global error handler returns nothing sensitive.** This was the
      bigger leak: the handler caught every unhandled exception in the whole
      application, so *any* 500 anywhere handed over the JWT signing secret and
      the full stack trace. It now returns a generic message and a correlation
      id, and logs the detail server-side:

      ```java
      String correlationId = UUID.randomUUID().toString();

      log.error("unhandled exception [{}] on {} {}",
              correlationId, request.getMethod(), request.getRequestURI(), e);

      body.put("error", "Internal server error");
      body.put("correlation_id", correlationId);
      ```

      The correlation id lets a user quote the failure to support without the
      response itself carrying anything sensitive.

      And the framework defaults are tightened as a second layer:

      ```yaml
      server:
        error:
          include-stacktrace: never
          include-message: never
          include-exception: false
      ```
"""


changes = 0


def replace(path: Path, old: str, new: str, label: str) -> None:
    global changes
    text = path.read_text(encoding="utf-8")
    if new in text and old not in text:
        print(f"  = {label}: already applied")
        return
    if old not in text:
        print(f"  ! {label}: pattern not found - skipped")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  + {label}: updated")
    changes += 1


print("applying the Lab 4 solution to the fixed branch")
replace(YML, OLD_YML, NEW_YML, "application.yml (server.error.* settings)")
replace(VERIFY, OLD_VERIFY, NEW_VERIFY, "verify-labs.sh (Lab 4 expectations)")
replace(VERIFY, OLD_LAB23, NEW_LAB23, "verify-labs.sh (Lab 23 expectations)")
replace(WALKTHROUGH, OLD_WALKTHROUGH, NEW_WALKTHROUGH, "verify-walkthrough.sh (Lab 4 expectations)")
replace(WALKTHROUGH, OLD_WALKTHROUGH_23, NEW_WALKTHROUGH_23, "verify-walkthrough.sh (Lab 23 expectations)")
replace(META, OLD_META, NEW_META, "labs.meta.yaml (Lab 4 hint/fix)")

print()
if changes:
    print(f"{changes} change(s) applied.")
    print("Now run:")
    print("  python3 scripts/sync-labs.py")
    print("  docker compose up -d --build backend")
    print("  ./scripts/verify-labs.sh")
    print("  ./scripts/verify-walkthrough.sh")
else:
    print("nothing to do - the solution is already applied.")
