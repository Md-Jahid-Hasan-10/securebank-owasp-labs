#!/usr/bin/env python3
"""Apply the Lab 3 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab3.py

The Java fix itself was written by hand in
Lab3SsrfController.java. This script handles everything around it:

  1. labs/labs.meta.yaml - the Lab 3 hint/fix text is replaced with the
     remediation as implemented, so the panel on this branch teaches the fix
     rather than describing a hypothetical one.
  2. scripts/verify-labs.sh - the Lab 3 expectations are inverted: they now
     assert that the exploit FAILS, not that it succeeds.
  3. scripts/verify-walkthrough.sh - the same inversion for the walkthrough.

The controller is NOT touched: the fix is already in the source, complete with
its FIXED: marker and explanatory comment.

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"

# --- verify-labs.sh ---------------------------------------------------------

OLD_VERIFY = """# --- Lab 3: SSRF ------------------------------------------------------------
if should_run 3; then
  lab 3 "SSRF"
  OUT="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://report:8081/"}')"
  check "server fetched the internal report service" "$OUT" '"status"'
  OUT2="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://169.254.169.254/latest/meta-data/"}')"
  check "server attempted the cloud metadata address" "$OUT2" '"sent_to"'
  # The report service is only reachable by name on the Docker network, so a
  # successful fetch of it proves the request came from inside the network.
  OUT3="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://report:8081/api/report/report/generate"}')"
  check "server reached an internal-only service by Docker DNS name" "$OUT3" '"status"'
fi
"""

NEW_VERIFY = """# --- Lab 3: SSRF (FIXED on this branch) -------------------------------------
if should_run 3; then
  lab 3 "SSRF"
  # The internal report service is only reachable by name on the Docker network,
  # so a successful fetch of it would prove the request came from inside.
  OUT="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://report:8081/"}')"
  check "the internal report service is refused" "$OUT" '"error":"Callback URL is not allowed"'
  refute "no internal response body is returned" "$OUT" '"body"'
  refute "the target is not echoed back" "$OUT" '"sent_to"'
  OUT2="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://169.254.169.254/latest/meta-data/"}')"
  check "the cloud metadata address is refused" "$OUT2" '"error":"Callback URL is not allowed"'
  refute "the metadata attempt is not echoed back" "$OUT2" '"sent_to"'
  OUT3="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://report:8081/api/report/report/generate"}')"
  check "the SSTI pivot target is refused too" "$OUT3" '"error":"Callback URL is not allowed"'
  # Layer 1 - only http and https are accepted.
  OUT4="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "file:///etc/passwd"}')"
  check "a non-http scheme is refused" "$OUT4" '"error":"Callback URL is not allowed"'
  # Layer 3 - the host allowlist rejects a public host that is not on it.
  OUT5="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://example.com/"}')"
  check "a host that is not on the allowlist is refused" "$OUT5" '"error":"Callback URL is not allowed"'
  # Layer 3 - loopback is blocked even when the host resolves to it.
  OUT6="$(post "$API/api/a01/accounts/statement-email" \\
    -d '{"account_id": 1, "callback_url": "http://127.0.0.1:8080/api/labs"}')"
  check "a loopback address is refused" "$OUT6" '"error":"Callback URL is not allowed"'
fi
"""

# --- verify-walkthrough.sh --------------------------------------------------

OLD_WALKTHROUGH = """echo "== Lab 3: SSRF =="
check "SSRF to the internal report service" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"account_id":1,"callback_url":"http://report:8081/api/report/report/generate"}' \\
     "$API/api/a01/accounts/statement-email")" '"status"'
check "SSRF to the metadata address reports sent_to" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"account_id":1,"callback_url":"http://169.254.169.254/latest/meta-data/"}' \\
     "$API/api/a01/accounts/statement-email")" '"sent_to"'
"""

NEW_WALKTHROUGH = """echo "== Lab 3: SSRF (fixed on this branch) =="
check "SSRF to the internal report service is refused" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"account_id":1,"callback_url":"http://report:8081/api/report/report/generate"}' \\
     "$API/api/a01/accounts/statement-email")" '"error":"Callback URL is not allowed"'
check "SSRF to the metadata address is refused" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"account_id":1,"callback_url":"http://169.254.169.254/latest/meta-data/"}' \\
     "$API/api/a01/accounts/statement-email")" '"error":"Callback URL is not allowed"'
"""

# --- labs.meta.yaml ---------------------------------------------------------

OLD_META = """    hint: >-
      What happens to the `callback_url` value between it arriving in the JSON body and
      the HTTP request being made?
    fix: >-
      Validate the URL before fetching it: resolve the hostname, reject private,
      loopback, link-local and metadata address ranges, and allow only an explicit
      allowlist of hosts:

      ```java
      URI uri = URI.create(callbackUrl);
      if (!ALLOWED_HOSTS.contains(uri.getHost())) {
          return ResponseEntity.badRequest().body(Map.of("error", "Unsupported callback host"));
      }
      ```
"""

NEW_META = """    hint: >-
      This lab is FIXED on the `fixed` branch. Compare it with `main` to see the
      original flaw:
      `git diff main fixed -- backend/core/src/main/java/com/securebank/lab/a01/`
    fix: >-
      The URL is validated in three layers before any request is made.

      **Layer 1 - scheme allowlist.** Only `http` and `https` are accepted, so
      `file://`, `gopher://` and `jar:` cannot be used to read local files or
      speak other protocols:

      ```java
      String scheme = uri.getScheme();
      if (scheme == null
              || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
          return notAllowed();
      }
      ```

      **Layer 2 - host allowlist.** Only hosts the application actually needs are
      fetchable:

      ```java
      private static final Set<String> ALLOWED_HOSTS = Set.of("report");
      ```

      **Layer 3 - resolved address check.** The allowlist alone is not enough,
      because a hostname can resolve to an address the attacker controls. So the
      host is resolved and *every* address it resolves to is checked - not just
      the first, or the attacker controls the ordering:

      ```java
      for (InetAddress address : InetAddress.getAllByName(host)) {
          if (isBlocked(address)) {
              return notAllowed();
          }
      }
      ```

      with `isBlocked` covering loopback (`127.0.0.0/8`, `::1`), link-local
      (`169.254.0.0/16` - this is the cloud metadata range), site-local
      (`10/8`, `172.16/12`, `192.168/16`), `0.0.0.0` and IPv6 unique-local
      (`fc00::/7`).

      **And redirects are never followed**, or an allowed host could answer with
      a `302` pointing at an internal address and bypass all of the above:

      ```java
      .followRedirects(HttpClient.Redirect.NEVER)
      ```

      Every rejection returns the same generic message, so the response does not
      reveal whether the guess hit something real.
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


print("applying the Lab 3 solution to the fixed branch")
replace(VERIFY, OLD_VERIFY, NEW_VERIFY, "verify-labs.sh (Lab 3 expectations)")
replace(WALKTHROUGH, OLD_WALKTHROUGH, NEW_WALKTHROUGH, "verify-walkthrough.sh (Lab 3 expectations)")
replace(META, OLD_META, NEW_META, "labs.meta.yaml (Lab 3 hint/fix)")

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
