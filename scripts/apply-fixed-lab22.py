#!/usr/bin/env python3
"""Apply the Lab 22 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab22.py

The Java fix was written in:
  - lab/a08/Lab22UploadController.java   (allowlist, UUID name, download endpoint)
  - core/security/WebConfig.java         (the /uploads/** handler is gone)
  - core/security/AuthFilter.java        (/uploads/ is no longer public)
  - core/src/main/resources/application.yml  (uploads moved out of the web root)
  - core/pom.xml                         (uploads are no longer packaged)

The supporting changes are made here:
  - scripts/verify-labs.sh            (the Lab 22 expectations are inverted)
  - scripts/verify-walkthrough.sh     (the same inversion for the walkthrough)
  - labs/labs.meta.yaml               (the Lab 22 fix text)

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


# --- 1. verify-labs.sh: invert the Lab 22 expectations -------------------------

replace_once(
    VERIFY,
    """# --- Lab 22: unrestricted upload --------------------------------------------
if should_run 22; then
  lab 22 "Unrestricted file upload"
  TMPFILE="$(mktemp)"
  echo "SHELL_HERE" > "$TMPFILE"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPFILE")"
  check "file is accepted and a URL is returned" "$OUT" '"uploaded":true'
  URL="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))" 2>/dev/null)"
  BODY="$(curl -s "$API$URL")"
  check "the uploaded file is served back from the web root" "$BODY" 'SHELL_HERE'
  rm -f "$TMPFILE"
fi""",
    """# --- Lab 22: unrestricted upload (FIXED on this branch) ----------------------
if should_run 22; then
  lab 22 "Unrestricted file upload"
  # A file with no extension at all, and then one with a scripting extension.
  TMPFILE="$(mktemp)"
  echo "SHELL_HERE" > "$TMPFILE"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPFILE")"
  refute "the file with no extension is no longer accepted" "$OUT" '"uploaded":true'
  rm -f "$TMPFILE"
  TMPHTML="$(mktemp --suffix=.html)"
  echo "<script>alert(1)</script>" > "$TMPHTML"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPHTML")"
  refute "the .html file is no longer accepted" "$OUT" '"uploaded":true'
  rm -f "$TMPHTML"
  # A traversal attempt in the filename must not escape the upload directory.
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" \\
    -F 'file=@/dev/null;filename=../../shell.txt')"
  refute "the traversal filename is no longer accepted" "$OUT" '"uploaded":true'
  # The static handler must not serve the uploads any more.
  OUT="$(curl -s "$API/uploads/shell.txt")"
  refute "the uploads are no longer served from the web root" "$OUT" 'SHELL_HERE'
  # An allowed document type must still be accepted, and must be downloaded with
  # a fixed content type rather than rendered.
  TMPPDF="$(mktemp --suffix=.pdf)"
  echo "%PDF-1.4 test" > "$TMPPDF"
  OUT="$(curl -s -X POST "$API/api/a08/kyc-upload" -H "Authorization: Bearer $TOKEN" -F "file=@$TMPPDF")"
  check "an allowed document type is still accepted" "$OUT" '"uploaded":true'
  URL="$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))" 2>/dev/null)"
  # The download endpoint is behind the auth filter, so it is fetched with a token.
  HEADERS="$(curl -s -D - -o /dev/null -H "Authorization: Bearer $TOKEN" "$API$URL")"
  check "the download is sent as an attachment" "$HEADERS" 'attachment'
  check "the download has a fixed content type" "$HEADERS" 'application/octet-stream'
  # And it must not be reachable anonymously.
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$API$URL")"
  check "the download is not reachable without authentication" "$CODE" '401'
  rm -f "$TMPPDF"
fi""",
    "verify-labs.sh: Lab 22 expectations inverted",
    sentinel='refute "the file with no extension is no longer accepted"',
)

# --- 2. verify-walkthrough.sh: invert the Lab 22 expectations ------------------

replace_once(
    WALKTHROUGH,
    """echo "== Lab 22: file upload =="
TMP="$(mktemp)"
echo "SHELL_HERE" > "$TMP"
check "the upload is accepted" \\
  "$(curl -s -X POST "${AUTH[@]}" -F "file=@$TMP" "$API/api/a08/kyc-upload")" '"uploaded":true'
check "the uploaded file is served back" \\
  "$(curl -s "$API/uploads/$(basename "$TMP")")" 'SHELL_HERE'
rm -f "$TMP\"""",
    """echo "== Lab 22: file upload =="
TMP="$(mktemp --suffix=.html)"
echo "SHELL_HERE" > "$TMP"
if [[ "$(curl -s -X POST "${AUTH[@]}" -F "file=@$TMP" "$API/api/a08/kyc-upload")" == *'"uploaded":true'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the .html upload is still accepted\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the .html upload is no longer accepted\\n'
  PASS=$((PASS + 1))
fi
rm -f "$TMP"
if [[ "$(curl -s "$API/uploads/shell.txt")" == *'SHELL_HERE'* ]]; then
  printf '\\033[31m  FAIL\\033[0m the uploads are still served from the web root\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m the uploads are no longer served from the web root\\n'
  PASS=$((PASS + 1))
fi""",
    "verify-walkthrough.sh: Lab 22 expectations inverted",
    sentinel="the uploads are no longer served from the web root",
)

# --- 3. labs.meta.yaml: the Lab 22 fix text -----------------------------------

replace_once(
    META,
    """      Validate the extension and MIME type server-side, generate a UUID filename,
      store uploads outside the web root, and serve them through a handler that sets
      `Content-Disposition: attachment` and a fixed content type.
    source: core/src/main/java/com/securebank/lab/a08/Lab22UploadController.java""",
    """      Validate the extension and MIME type server-side, generate a UUID filename,
      store uploads outside the web root, and serve them through a handler that sets
      `Content-Disposition: attachment` and a fixed content type.

      **What was changed:** the extension is checked against an allowlist
      (`.pdf`, `.png`, `.jpg`, `.jpeg`, `.doc`, `.docx`, `.txt`), the size is
      capped at 5 MB, and the stored name is a UUID - the client's filename never
      reaches the filesystem, so a traversal sequence cannot escape the upload
      directory and a second upload cannot overwrite the first. The upload
      directory has moved out of the static tree (`data/uploads`) and is no longer
      packaged into the artifact, the `/uploads/**` static handler has been
      removed, and `/uploads/` is no longer on the public allowlist. Files are
      now downloaded through an authenticated endpoint that sets
      `Content-Disposition: attachment` and `application/octet-stream`, and the
      absolute server path is no longer returned in the response.
    source: core/src/main/java/com/securebank/lab/a08/Lab22UploadController.java""",
    "labs.meta.yaml: Lab 22 fix text",
    sentinel="**What was changed:** the extension is checked against an allowlist",
)

print("Lab 22 fix applied.")
