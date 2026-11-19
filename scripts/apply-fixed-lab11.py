#!/usr/bin/env python3
"""Apply the Lab 11 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab11.py

The Java fix was written in:
  - lab/a05/Lab11SstiController.java   (no SpEL evaluation, HTML-escaped output)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 11 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 11 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 11 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 11: SSTI via SpEL --------------------------------------------------
if should_run 11; then
  lab 11 "SSTI (SpEL)"
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "7*7"}')"
  check "arithmetic expression is evaluated" "$OUT" '49'
  OUT="$(post "$API/api/a05/transfers/1/remark" \\
    -d '{"remark": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\\"id\\"})"}')"
  check "Runtime.exec is reachable via SpEL" "$OUT" 'uid='
fi""",
    """# --- Lab 11: SSTI via SpEL (FIXED on this branch) ----------------------------
if should_run 11; then
  lab 11 "SSTI (SpEL)"
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "7*7"}')"
  refute "the arithmetic expression is no longer evaluated" "$OUT" '49'
  OUT="$(post "$API/api/a05/transfers/1/remark" \\
    -d '{"remark": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\\"id\\"})"}')"
  refute "Runtime.exec is no longer reachable via SpEL" "$OUT" 'uid='
  # The remark must be stored and returned as the text it is, not evaluated.
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "7*7"}')"
  check "the remark is stored as plain text" "$OUT" '7*7'
  # The rendered fragment must be HTML-escaped. The raw remark is echoed back as
  # plain text (that is the stored value), so only the rendered fragment is checked.
  OUT="$(post "$API/api/a05/transfers/1/remark" -d '{"remark": "<script>alert(1)</script>"}')"
  RENDERED="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rendered',''))" 2>/dev/null)"
  refute "the rendered remark does not contain a raw script tag" "$RENDERED" '<script>'
  check "the rendered remark is HTML-escaped" "$RENDERED" '&lt;script&gt;'
  # The remark must still be stored verbatim, so the API does not corrupt the data.
  check "the raw remark is still stored as the text it is" "$OUT" '"remark":"<script>alert(1)</script>"'
fi""",
    "verify-labs.sh: Lab 11 expectations inverted",
    sentinel='refute "the arithmetic expression is no longer evaluated"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 11 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 11: SSTI =="
check "7*7 evaluates to 49" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"remark":"7*7"}' "$API/api/a05/transfers/1/remark")" '49'
check "Runtime.exec is reachable" \\
  "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"remark":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\\"id\\"})"}' \\
     "$API/api/a05/transfers/1/remark")" 'uid='""",
    """echo "== Lab 11: SSTI =="
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"remark":"7*7"}' "$API/api/a05/transfers/1/remark")" == *'49'* ]]; then
  printf '\\033[31m  FAIL\\033[0m 7*7 still evaluates to 49\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m 7*7 is no longer evaluated\\n'
  PASS=$((PASS + 1))
fi
if [[ "$(curl -s -X POST "${AUTH[@]}" -H "Content-Type: application/json" \\
     -d '{"remark":"T(java.lang.Runtime).getRuntime().exec(new java.lang.String[]{\\"id\\"})"}' \\
     "$API/api/a05/transfers/1/remark")" == *'uid='* ]]; then
  printf '\\033[31m  FAIL\\033[0m Runtime.exec is still reachable\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m Runtime.exec is no longer reachable\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 11 expectations inverted",
    sentinel="Runtime.exec is no longer reachable",
)

# --- 3. labs.meta.yaml: the Lab 11 fix text -----------------------------------

replace_once(
    META,
    """      ```java
      return ResponseEntity.ok("<p>Remark: " + escapeHtml(remark) + "</p>");
      ```
    source: core/src/main/java/com/securebank/lab/a05/Lab11SstiController.java""",
    """      ```java
      return ResponseEntity.ok("<p>Remark: " + escapeHtml(remark) + "</p>");
      ```

      **What was changed:** the remark is never evaluated. The SpEL parser and the
      `StandardEvaluationContext` are gone, along with the `render()` helper that
      read a spawned process's output stream, so there is no expression language in
      scope at all. The remark is HTML-escaped with `HtmlUtils.htmlEscape` before
      it is embedded in the response fragment, and a failure is reported with a
      generic message instead of `e.toString()`.
    source: core/src/main/java/com/securebank/lab/a05/Lab11SstiController.java""",
    "labs.meta.yaml: Lab 11 fix text",
    sentinel="**What was changed:** the remark is never evaluated",
)

print("Lab 11 fix applied.")
