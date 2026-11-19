#!/usr/bin/env python3
"""Apply the Lab 12 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab12.py

The Java fix was written in:
  - report/.../ReportController.java     (fixed templates, no shell)
  - report/src/main/resources/application.yml   (no stack traces)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 12 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 12 fix text)

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"


def replace_once(path: Path, old: str, new: str, label: str, sentinel: str = "") -> None:
    """Replace `old` with `new`, at most once."""
    text = path.read_text()
    if sentinel and sentinel in text:
        print(f"  already applied: {label}")
        return
    if old not in text:
        print(f"  already applied: {label}")
        return
    path.write_text(text.replace(old, new, 1))
    print(f"  applied: {label}")


# --- 1. verify-labs.sh: invert the Lab 12 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 12: SSTI + command injection (report service) ----------------------
if should_run 12; then
  lab 12 "SSTI + OS command injection"
  OUT="$(curl -s -X POST "$REPORT/api/report/report/generate" -H "Content-Type: application/json" \\
    -d '{"account_id": "1001", "template": "Secret: ${config.secretKey}"}')"
  check "internal secret key is extracted from the template" "$OUT" 'sb-report-internal-secret'
  # The date filter is concatenated into `sh -c "echo 'From: <from> To: <to>' && date"`,
  # so a single quote in the date closes the quoted argument and everything after it
  # is executed as a separate command.
  DATE_BODY="$(mktemp)"
  cat > "$DATE_BODY" <<'JSON'
{"from_date": "2024-01-01' && id && echo '", "to_date": "2024-12-31"}
JSON
  OUT="$(curl -s -X POST "$REPORT/api/report/report/date-filter" -H "Content-Type: application/json" \\
    --data-binary "@$DATE_BODY")"
  rm -f "$DATE_BODY"
  check "command injection runs 'id'" "$OUT" 'uid='
fi""",
    """# --- Lab 12: SSTI + command injection (report service) (FIXED on this branch) --
if should_run 12; then
  lab 12 "SSTI + OS command injection"
  OUT="$(curl -s -X POST "$REPORT/api/report/report/generate" -H "Content-Type: application/json" \\
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
  OUT="$(curl -s -X POST "$REPORT/api/report/report/date-filter" -H "Content-Type: application/json" \\
    --data-binary "@$DATE_BODY")"
  rm -f "$DATE_BODY"
  refute "the command injection no longer runs 'id'" "$OUT" 'uid='
  # A valid date range must still work, so the fix did not simply break the endpoint.
  OUT="$(curl -s -X POST "$REPORT/api/report/report/date-filter" -H "Content-Type: application/json" \\
    -d '{"from_date": "2024-01-01", "to_date": "2024-12-31"}')"
  check "a valid date range is still accepted" "$OUT" '2024-01-01'
fi""",
    "verify-labs.sh: Lab 12 expectations inverted",
    sentinel='refute "the internal secret key is no longer extracted"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 12 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 12: report service =="
check "SSTI reads config.secretKey" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     --data-binary '{"account_id":"1001","template":"Secret: ${config.secretKey}"}' \\
     "$REPORT/api/report/report/generate")" 'sb-report-internal-secret'
check "SSTI reads config.dbPath" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     --data-binary '{"account_id":"1001","template":"DB: ${config.dbPath}"}' \\
     "$REPORT/api/report/report/generate")" '/var/lib/securebank'
check "date-filter echoes the command it runs" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"from_date":"2024-01-01","to_date":"2024-12-31"}' \\
     "$REPORT/api/report/report/date-filter")" 'echo'
check "command injection runs id" \\
  "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"from_date":"2024-01-01'"'"' && id && echo '"'"'","to_date":"2024-12-31"}' \\
     "$REPORT/api/report/report/date-filter")" 'uid='""",
    """echo "== Lab 12: report service =="
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \\
     --data-binary '{"account_id":"1001","template":"Secret: ${config.secretKey}"}' \\
     "$REPORT/api/report/report/generate")" == *'sb-report-internal-secret'* ]]; then
  printf '\\033[31m  FAIL\\033[0m SSTI still reads config.secretKey\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m SSTI no longer reads config.secretKey\\n'
  PASS=$((PASS + 1))
fi
if [[ "$(curl -s -X POST -H "Content-Type: application/json" \\
     -d '{"from_date":"2024-01-01'"'"' && id && echo '"'"'","to_date":"2024-12-31"}' \\
     "$REPORT/api/report/report/date-filter")" == *'uid='* ]]; then
  printf '\\033[31m  FAIL\\033[0m command injection still runs id\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m command injection no longer runs id\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 12 expectations inverted",
    sentinel="command injection no longer runs id",
)

# --- 3. labs.meta.yaml: the Lab 12 fix text -----------------------------------

replace_once(
    META,
    """      ```java
      LocalDate from = LocalDate.parse(fromDate, DateTimeFormatter.ISO_LOCAL_DATE);
      ProcessBuilder pb = new ProcessBuilder("date", "--from", from.toString());
      ```
    source: report/src/main/java/com/securebank/lab/a05/report/ReportController.java""",
    """      ```java
      LocalDate from = LocalDate.parse(fromDate, DateTimeFormatter.ISO_LOCAL_DATE);
      ProcessBuilder pb = new ProcessBuilder("date", "--from", from.toString());
      ```

      **What was changed:** the `evaluate()` method and the whole SpEL evaluation
      context are gone. A caller-supplied template is now matched against a fixed
      set of server-side templates and anything else is rejected, and the template
      model no longer carries the configuration object at all - so there is nothing
      in scope to steal. The date filter parses both dates with a strict
      `LocalDate` formatter and runs no shell, and the report service no longer
      renders stack traces (`include-stacktrace: never`).
    source: report/src/main/java/com/securebank/lab/a05/report/ReportController.java""",
    "labs.meta.yaml: Lab 12 fix text",
    sentinel="**What was changed:** the `evaluate()` method and the whole SpEL",
)

print("Lab 12 fix applied.")
