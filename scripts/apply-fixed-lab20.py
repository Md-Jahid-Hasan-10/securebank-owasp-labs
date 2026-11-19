#!/usr/bin/env python3
"""Apply the Lab 20 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab20.py

The Java fix was written in:
  - lab/a08/Lab20DeserializationController.java   (a fixed target type, no default typing)
  - the gadget class has been deleted
  - core/pom.xml                       (commons-collections removed)
  - core/src/main/resources/application.yml  (default typing disabled)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 20 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 20 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 20 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 20: insecure deserialization ---------------------------------------
if should_run 20; then
  lab 20 "Insecure deserialization"
  PAYLOAD="$(mktemp)"
  cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account" \\
    -H "Authorization: Bearer $TOKEN" -F "data=@$PAYLOAD")"
  check "uploaded payload is deserialised" "$OUT" '"imported"'
  check "the gadget executed the command during deserialisation" "$OUT" 'uid='
  rm -f "$PAYLOAD"
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account/describe" \\
    -H "Authorization: Bearer $TOKEN")"
  check "default typing is enabled on the mapper" "$OUT" 'enabled'
fi""",
    """# --- Lab 20: insecure deserialization (FIXED on this branch) -----------------
if should_run 20; then
  lab 20 "Insecure deserialization"
  PAYLOAD="$(mktemp)"
  cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account" \\
    -H "Authorization: Bearer $TOKEN" -F "data=@$PAYLOAD")"
  refute "the uploaded payload is no longer deserialised" "$OUT" '"imported"'
  refute "the gadget no longer executed the command during deserialisation" "$OUT" 'uid='
  rm -f "$PAYLOAD"
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account/describe" \\
    -H "Authorization: Bearer $TOKEN")"
  refute "default typing is no longer enabled on the mapper" "$OUT" 'enabled'
  # A well-formed document must still be accepted.
  GOOD="$(mktemp)"
  cat > "$GOOD" <<'JSON'
{"username":"alice","account_number":"ACC-1001","currency":"GBP"}
JSON
  OUT="$(curl -s -X POST "$API/api/a08/integrity/import-account" \\
    -H "Authorization: Bearer $TOKEN" -F "data=@$GOOD")"
  check "a well-formed import document is still accepted" "$OUT" '"imported":true'
  rm -f "$GOOD"
  # The gadget class and the vulnerable library must be gone from the source.
  GADGET="backend/core/src/main/java/com/securebank/lab/a08/gadget/AccountImportJob.java"
  if [[ -f "$GADGET" ]]; then
    red "the gadget class is still present"
    FAIL=$((FAIL + 1))
    FAILED_LABS+=("$CURRENT_LAB")
  else
    green "the gadget class has been removed"
    PASS=$((PASS + 1))
  fi
  # The dependency must no longer be declared. The FIXED comment in the pom
  # names the artifact, so the check is for the dependency declaration itself.
  OUT="$(grep -c '<artifactId>commons-collections</artifactId>' backend/core/pom.xml || true)"
  refute "the vulnerable commons-collections dependency is gone" "$OUT" '1'
fi""",
    "verify-labs.sh: Lab 20 expectations inverted",
    sentinel='refute "the uploaded payload is no longer deserialised"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 20 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 20: deserialization =="
PAYLOAD="$(mktemp)"
cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
check "the gadget executes the command" \\
  "$(curl -s -X POST "${AUTH[@]}" -F "data=@$PAYLOAD" \\
     "$API/api/a08/integrity/import-account")" 'uid='
rm -f "$PAYLOAD"
check "default typing is enabled" \\
  "$(curl -s -X POST "${AUTH[@]}" "$API/api/a08/integrity/import-account/describe")" 'enabled'""",
    """echo "== Lab 20: deserialization =="
PAYLOAD="$(mktemp)"
cat > "$PAYLOAD" <<'JSON'
{"@class":"com.securebank.lab.a08.gadget.AccountImportJob","command":"id"}
JSON
if [[ "$(curl -s -X POST "${AUTH[@]}" -F "data=@$PAYLOAD" \\
     "$API/api/a08/integrity/import-account")" == *'uid='* ]]; then
  printf '\\033[31m  FAIL\\033[0m the gadget still executes the command\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the gadget no longer executes the command\\n'
  PASS=$((PASS + 1))
fi
rm -f "$PAYLOAD"
if [[ "$(curl -s -X POST "${AUTH[@]}" "$API/api/a08/integrity/import-account/describe")" == *'enabled'* ]]; then
  printf '\\033[31m  FAIL\\033[0m default typing is still enabled\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m default typing is no longer enabled\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 20 expectations inverted",
    sentinel="the gadget no longer executes the command",
)

# --- 3. labs.meta.yaml: the Lab 20 fix text -----------------------------------

replace_once(
    META,
    """      Never deserialize untrusted data into polymorphic types. Use JSON with a fixed
      schema, or validate against a schema with `jsonschema` before use. Never enable
      Jackson's `activateDefaultTyping` on an ObjectMapper that reads user input.
    source: core/src/main/java/com/securebank/lab/a08/Lab20DeserializationController.java""",
    """      Never deserialize untrusted data into polymorphic types. Use JSON with a fixed
      schema, or validate against a schema with `jsonschema` before use. Never enable
      Jackson's `activateDefaultTyping` on an ObjectMapper that reads user input.

      **What was changed:** the `ObjectMapper` no longer has polymorphic default
      typing - the `@class` property is simply an unknown property and the
      document is rejected. The import file is parsed into a fixed `AccountImport`
      record, so there is no type for the document to choose. The lab's own gadget
      class has been deleted and the `commons-collections` dependency has been
      removed from the POM, so the gadget chain is not on the classpath either.
    source: core/src/main/java/com/securebank/lab/a08/Lab20DeserializationController.java""",
    "labs.meta.yaml: Lab 20 fix text",
    sentinel="**What was changed:** the `ObjectMapper` no longer has polymorphic default",
)

print("Lab 20 fix applied.")
