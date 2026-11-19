#!/usr/bin/env python3
"""Apply the Lab 6 solution to the `fixed` branch.

Run this from the repo root while the `fixed` branch is checked out:

    git switch fixed
    python3 scripts/apply-fixed-lab6.py

The Java fix was written by hand in:
  - core/security/WebConfig.java                   (assets-only resource handler)
  - core/security/AuthFilter.java                 (secrets no longer public)
  - lab/a02/Lab6StaticExposureController.java     (reports nothing exposed)

The supporting changes are made here:
  - backend/core/Dockerfile            - the fake .git directory is no longer
                                         copied into the image's web root
  - backend/core/docker-entrypoint.sh  - the database backup is written to
                                         /app/backups, outside the web root
  - backend/core/pom.xml               - the .env file is no longer packaged
  - backend/core/src/main/resources/static/.env - deleted from the served tree
  - backend/core/src/main/resources/application.yml - asset-dir replaces web-root
  - .gitignore                         - .env is never committed
  - scripts/verify-labs.sh             - the Lab 6 expectations are inverted, so
                                         the suite asserts the exploit FAILS
  - scripts/verify-walkthrough.sh      - the same inversion for the walkthrough
  - labs/labs.meta.yaml                - the Lab 6 hint/fix text is replaced with
                                         the remediation as implemented

The script is idempotent: running it twice changes nothing the second time.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DOCKERFILE = ROOT / "backend/core/Dockerfile"
ENTRYPOINT = ROOT / "backend/core/docker-entrypoint.sh"
POM = ROOT / "backend/core/pom.xml"
APP_YML = ROOT / "backend/core/src/main/resources/application.yml"
GITIGNORE = ROOT / ".gitignore"
STATIC_ENV = ROOT / "backend/core/src/main/resources/static/.env"
VERIFY = ROOT / "scripts/verify-labs.sh"
WALKTHROUGH = ROOT / "scripts/verify-walkthrough.sh"
META = ROOT / "labs/labs.meta.yaml"


def replace_once(path: Path, old: str, new: str, label: str, sentinel: str = "") -> None:
    """Replace `old` with `new`, at most once.

    The patched form carries a sentinel (a comment that only exists in the
    new text). If the sentinel is already in the file the patch has been
    applied, which keeps the script idempotent even when the new block
    contains the old block as a prefix.
    """
    text = path.read_text()
    if sentinel and sentinel in text:
        print(f"  already applied: {label}")
        return
    if old not in text:
        print(f"  already applied: {label}")
        return
    path.write_text(text.replace(old, new, 1))
    print(f"  applied: {label}")


# --- 1. Dockerfile: do not copy the .git fixture into the web root ----------

OLD_DOCKERFILE = """# VULN: [A02-Lab6] Sensitive File Exposure - the fake .git directory is copied into
# the image's web root, so that /.git/config is downloadable over HTTP. This mirrors
# what happens when an application is deployed straight out of a repository checkout.
# FIX:  never ship a .git directory (or a .env file) inside the document root.
#
# The fixture is stored in the repository as lab-fixtures/git-config rather than as
# static/.git/config, because git refuses to track any path containing a ".git"
# component - not even with "git add -f". The Dockerfile renames it into place, so
# the served path is still /.git/config.
COPY backend/core/src/main/resources/lab-fixtures/git-config /app/static/.git/config
RUN chmod +x /app/docker-entrypoint.sh \\
    && mkdir -p /app/static/uploads"""

NEW_DOCKERFILE = """# FIXED: [A02-Lab6] Sensitive File Exposure - the fake .git directory is no longer
# copied into the image's web root, so /.git/config is not downloadable over HTTP.
# Shipping VCS metadata inside the document root is what made this possible in the
# first place: the image used to be built straight out of a repository checkout.
#
# The fixture is still tracked in the repository as lab-fixtures/git-config rather
# than as static/.git/config, because git refuses to track any path containing a
# ".git" component - not even with "git add -f". It is simply not copied into the
# image any more.
#
# The image also no longer contains a .env file in a served directory. The
# environment file is a training fixture for the vulnerable branch; see
# scripts/apply-fixed-lab6.py for the details.
RUN chmod +x /app/docker-entrypoint.sh \\
    && mkdir -p /app/static/uploads \\
    && mkdir -p /app/static/assets"""


def patch_dockerfile() -> None:
    print("backend/core/Dockerfile")
    replace_once(DOCKERFILE, OLD_DOCKERFILE, NEW_DOCKERFILE, "no .git fixture in the web root",
                 sentinel="FIXED: [A02-Lab6] Sensitive File Exposure - the fake .git directory is no longer")


# --- 2. Entrypoint: keep the database backup out of the web root ------------

OLD_ENTRYPOINT = """# VULN: [A02-Lab6] Sensitive File Exposure - a full database backup is written into the
# static web root so that it can be downloaded at /backup.zip without authentication.
# FIX:  never write database dumps into a directory served by the web server.
#"""

NEW_ENTRYPOINT = """# FIXED: [A02-Lab6] Sensitive File Exposure - the database backup is no longer
# written into the static web root. It used to be copied to
# /app/static/backup.zip, where anyone could download the entire database -
# every user, balance and password hash - without authentication.
#
# The dump is still taken (it is useful for a genuine off-host backup), but it
# now stays in /app/backups, which is outside every directory the web server
# serves, and it is never reachable over HTTP.
#"""

OLD_ENTRYPOINT_COPY = """        ( cd /tmp && rm -f backup.zip && zip -q backup.zip securebank.dump )
        cp /tmp/backup.zip /app/static/backup.zip
        echo "[entrypoint] backup.zip written to /app/static/backup.zip\""""

NEW_ENTRYPOINT_COPY = """        ( cd /tmp && rm -f backup.zip && zip -q backup.zip securebank.dump )
        mkdir -p /app/backups
        cp /tmp/backup.zip /app/backups/backup.zip
        chmod 600 /app/backups/backup.zip
        echo "[entrypoint] backup.zip written to /app/backups/backup.zip (outside the web root)\""""


def patch_entrypoint() -> None:
    print("backend/core/docker-entrypoint.sh")
    replace_once(ENTRYPOINT, OLD_ENTRYPOINT, NEW_ENTRYPOINT, "backup comment",
                 sentinel="FIXED: [A02-Lab6] Sensitive File Exposure - the database backup is no longer")
    replace_once(ENTRYPOINT, OLD_ENTRYPOINT_COPY, NEW_ENTRYPOINT_COPY, "backup destination",
                 sentinel="/app/backups/backup.zip")


# --- 3. pom.xml: do not package the .env file -------------------------------

OLD_POM = """      <!--
        VULN: [A02-Lab6] Sensitive File Exposure - the static resource directory is
        packaged into the artifact as-is, including the .env file, so that it is
        served over HTTP by the static resource handler.
        FIX:  never package secrets or VCS metadata into a deployable artifact.

        The fake .git directory is NOT packaged here - Maven's resource scanner skips
        dot-directories. The Dockerfile copies it into the image's web root instead,
        which is exactly how a real repository checkout ends up serving its own
        .git directory over HTTP.
      -->
      <resource>
        <directory>src/main/resources</directory>
        <filtering>false</filtering>
      </resource>"""

NEW_POM = """      <!--
        FIXED: [A02-Lab6] Sensitive File Exposure - the static resource directory is
        no longer packaged into the artifact as-is. It used to include the .env
        file, so the environment file shipped inside the deployable jar and was
        served over HTTP by the static resource handler.

        The static tree now only contains the uploads directory (Lab 22) and the
        assets directory. Secrets and VCS metadata are never packaged into an
        artifact.
      -->
      <resource>
        <directory>src/main/resources</directory>
        <filtering>false</filtering>
        <excludes>
          <exclude>static/**</exclude>
          <exclude>lab-fixtures/**</exclude>
        </excludes>
      </resource>
      <!--
        The static tree is packaged separately so that the asset and upload
        directories are still present in the artifact, but without any secret
        file that may have been dropped into them.
      -->
      <resource>
        <directory>src/main/resources/static</directory>
        <targetPath>static</targetPath>
        <filtering>false</filtering>
        <includes>
          <include>assets/**</include>
          <include>uploads/**</include>
        </includes>
      </resource>"""

OLD_POM_PLUGIN = """          <!--
            VULN: [A02-Lab6] the .git directory is deliberately kept in the artifact so
            that it can be downloaded over HTTP.
            FIX:  exclude VCS metadata from the packaged artifact.
          -->"""

NEW_POM_PLUGIN = """          <!--
            FIXED: [A02-Lab6] the .git directory is no longer kept in the artifact,
            so it can no longer be downloaded over HTTP.
          -->"""


def patch_pom() -> None:
    print("backend/core/pom.xml")
    replace_once(POM, OLD_POM, NEW_POM, "resource excludes",
                 sentinel="FIXED: [A02-Lab6] Sensitive File Exposure - the static resource directory is")
    replace_once(POM, OLD_POM_PLUGIN, NEW_POM_PLUGIN, "plugin comment",
                 sentinel="FIXED: [A02-Lab6] the .git directory is no longer kept in the artifact")


# --- 4. application.yml: asset-dir replaces web-root ------------------------

OLD_APP = """# VULN: [A02-Lab6] The static resource directory is the web root, so files placed there
# are served verbatim. Lab 6 ships .env and .git/config here; Lab 22 writes uploads here.
# FIX:  serve static assets from a dedicated directory outside the web root.
app:
  # The filesystem directory that is exposed as the web root.
  web-root: ${APP_WEB_ROOT:static}
  # Where Lab 22 writes uploaded files. Inside the web root - on purpose.
  upload-dir: ${APP_UPLOAD_DIR:static/uploads}"""

NEW_APP = """# FIXED: [A02-Lab6] The static resource directory is no longer the web root. Assets
# are served from a dedicated directory that contains no secrets, the dot-prefixed
# resource handlers are gone and the database backup is written outside the web
# root. Lab 22 still writes uploads into the upload directory on purpose.
app:
  # The filesystem directory that holds static assets. Contains no secrets.
  asset-dir: ${APP_ASSET_DIR:static/assets}
  # Where Lab 22 writes uploaded files. Served by its own handler - on purpose.
  upload-dir: ${APP_UPLOAD_DIR:static/uploads}"""


def patch_app_yml() -> None:
    print("application.yml")
    replace_once(APP_YML, OLD_APP, NEW_APP, "asset-dir replaces web-root",
                 sentinel="FIXED: [A02-Lab6] The static resource directory is no longer the web root")


# --- 5. .gitignore: never commit an environment file ------------------------

OLD_GITIGNORE = """# Lab 6: the database dump is generated at container start, never committed.
backend/core/src/main/resources/static/backup.zip
*.dump"""

NEW_GITIGNORE = """# Lab 6: the database dump is generated at container start, never committed.
backend/core/src/main/resources/static/backup.zip
*.dump

# Lab 6: an environment file is never committed and never shipped inside the
# document root. On the vulnerable branch the fake .env is a training fixture
# that is tracked explicitly; on the fixed branch it is not tracked at all.
.env
backend/core/src/main/resources/static/.env"""


def patch_gitignore() -> None:
    print(".gitignore")
    replace_once(GITIGNORE, OLD_GITIGNORE, NEW_GITIGNORE, "ignore .env",
                 sentinel="backend/core/src/main/resources/static/.env")


# --- 6. Delete the .env from the served tree --------------------------------

def remove_static_env() -> None:
    print("static/.env")
    if STATIC_ENV.exists():
        STATIC_ENV.unlink()
        print("  removed: static/.env")
    else:
        print("  already applied: static/.env")


# --- 7. verify-labs.sh: invert the Lab 6 assertions -------------------------

OLD_LAB6 = """# --- Lab 6: exposed files ----------------------------------------------------
if should_run 6; then
  lab 6 "Sensitive file exposure"
  OUT="$(curl -s "$API/.env")"
  check "/.env is served" "$OUT" 'JWT_SECRET'
  OUT="$(curl -s "$API/.git/config")"
  check "/.git/config is served" "$OUT" 'securebank-internet-banking.git'
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")"
  check "/backup.zip is served" "$HTTP" '200'
fi"""

NEW_LAB6 = """# --- Lab 6: exposed files (FIXED on this branch) ----------------------------
if should_run 6; then
  lab 6 "Sensitive file exposure"
  # The environment file must not be reachable by an anonymous client. The
  # resource handler for it has been removed, so the request falls through to
  # the SPA / 404 rather than returning the file.
  OUT="$(curl -s "$API/.env")"
  refute "/.env is not served" "$OUT" 'JWT_SECRET'
  refute "/.env does not leak the AWS key" "$OUT" 'AKIAIOSFODNN7EXAMPLE'
  refute "/.env does not leak the Stripe secret" "$OUT" 'sk_test_4eC39HqLyjWDarjtT1zdp7dc'
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/.env")"
  refute "/.env is not downloadable" "$HTTP" '200'
  # The same for the repository's git configuration.
  OUT="$(curl -s "$API/.git/config")"
  refute "/.git/config is not served" "$OUT" 'securebank-internet-banking.git'
  refute "/.git/config does not leak the remote URL" "$OUT" '[remote "origin"]'
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/.git/config")"
  refute "/.git/config is not downloadable" "$HTTP" '200'
  # And for the database backup, which used to hand over every user, balance
  # and password hash.
  HTTP="$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")"
  refute "/backup.zip is not served" "$HTTP" '200'
  OUT="$(curl -s "$API/backup.zip")"
  refute "/backup.zip is not the database dump" "$OUT" 'PGDMP'
  # The panel endpoint must no longer advertise where the secrets were.
  OUT="$(curl -s "$API/api/a02/exposed-files")"
  refute "the panel does not advertise /.env" "$OUT" '"url":"/.env"'
  refute "the panel does not advertise /.git/config" "$OUT" '"url":"/.git/config"'
  refute "the panel does not advertise /backup.zip" "$OUT" '"url":"/backup.zip"'
fi"""


def patch_verify() -> None:
    print("verify-labs.sh")
    replace_once(VERIFY, OLD_LAB6, NEW_LAB6, "inverted Lab 6 assertions",
                 sentinel="# --- Lab 6: exposed files (FIXED on this branch) ----------------------------")


# --- 8. verify-walkthrough.sh: invert the Lab 6 assertions -------------------

# The walkthrough script has no refute helper, so the negative assertions are
# written out explicitly, in the same style the Lab 5 block uses.
OLD_WALK = """echo "== Lab 6: file exposure =="
check "/.env is served" "$(curl -s "$API/.env")" 'JWT_SECRET'
check "/.git/config is served" "$(curl -s "$API/.git/config")" 'securebank-internet-banking.git'
check "/backup.zip is served" \\
  "$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")" '200'"""

NEW_WALK = """echo "== Lab 6: file exposure (fixed on this branch) =="
WALK_ENV_OUT="$(curl -s "$API/.env")"
if [[ "$WALK_ENV_OUT" == *'JWT_SECRET'* ]]; then
  printf '\\033[31m  FAIL\\033[0m /.env is not served\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m /.env is not served\\n'
  PASS=$((PASS + 1))
fi
WALK_GIT_OUT="$(curl -s "$API/.git/config")"
if [[ "$WALK_GIT_OUT" == *'securebank-internet-banking.git'* ]]; then
  printf '\\033[31m  FAIL\\033[0m /.git/config is not served\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m /.git/config is not served\\n'
  PASS=$((PASS + 1))
fi
WALK_BACKUP_CODE="$(curl -s -o /dev/null -w '%{http_code}' "$API/backup.zip")"
if [[ "$WALK_BACKUP_CODE" == '200' ]]; then
  printf '\\033[31m  FAIL\\033[0m /backup.zip is not served\\n'
  FAIL=$((FAIL + 1))
else
  printf '\\033[32m  PASS\\033[0m /backup.zip is not served\\n'
  PASS=$((PASS + 1))
fi"""


def patch_walkthrough() -> None:
    print("verify-walkthrough.sh")
    replace_once(WALKTHROUGH, OLD_WALK, NEW_WALK, "inverted Lab 6 assertions",
                 sentinel="echo \"== Lab 6: file exposure (fixed on this branch) ==\"")


# --- 9. labs.meta.yaml: the hint and fix text -------------------------------

OLD_META = """    hint: >-
      The static resource directory is the web root. What was placed in it?
    fix: >-
      Isolate static files in a dedicated directory outside the web root. Never serve
      `.env` or `.git` from a web server. Use `.gitignore` and point `STATIC_ROOT` at a
      path that contains no sensitive files. Add a build step that fails if a secret
      file is detected in the static tree."""

NEW_META = """    hint: >-
      The static resource directory is the web root. What was placed in it?
      Now that the web root is gone, try the same paths again - none of them
      resolves to a file any more.
    fix: >-
      Static assets are served from a dedicated directory that contains nothing
      but assets, and nothing is mapped at `/**` any more, so a file dropped into
      the asset directory is not reachable by default. The explicit `/.env` and
      `/.git/**` resource handlers have been removed, which restores Spring
      Boot's built-in refusal to serve dot-prefixed paths, and the three secret
      paths are no longer on the AuthFilter's public list. The `.env` file is not
      packaged into the artifact at all and is gitignored, the image no longer
      contains a `.git` directory, and the database backup is written to
      `/app/backups` instead of into a served directory."""


def patch_meta() -> None:
    print("labs.meta.yaml")
    replace_once(META, OLD_META, NEW_META, "Lab 6 fix text",
                 sentinel="Static assets are served from a dedicated directory that contains nothing")


def main() -> None:
    patch_dockerfile()
    patch_entrypoint()
    patch_pom()
    patch_app_yml()
    patch_gitignore()
    remove_static_env()
    patch_verify()
    patch_walkthrough()
    patch_meta()
    print("\nLab 6 remediation applied.")


if __name__ == "__main__":
    main()
