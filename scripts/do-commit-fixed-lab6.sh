#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(A02-Lab6): stop serving secrets and the database backup

The static resource directory was the web root, so three files were handed to
any anonymous client: the environment file, the repository's git config and a
full PostgreSQL backup. The backup alone gave away every user, balance and
password hash in the system.

The fix works from the outside in:

  - The resource handler no longer maps /** at the web root. Static assets are
    served from a dedicated directory that contains nothing but assets, and
    because nothing is mapped at the root, a secret file dropped into that
    directory is not reachable by default either.
  - The explicit /.env and /.git/** handlers are gone. Spring Boot's default
    static resource handling deliberately refuses to serve dot-prefixed paths;
    those handlers undid that protection, so removing them restores it.
  - The three secret paths are no longer on the auth filter's public list.
    Even if one of them were reintroduced into a served directory, it would
    now require a valid principal rather than being world-readable.
  - The .env file is no longer packaged into the artifact and is gitignored.
  - The image no longer contains a .git directory: the Dockerfile used to copy
    the fixture straight into the web root, which is how a repository checkout
    ends up serving its own git config.
  - The database backup is still taken, but it now lands in /app/backups,
    outside every directory the web server serves, with mode 600.

The verification scripts now assert the opposite of what they used to: none of
the three paths may resolve to a file, and the panel endpoint must no longer
advertise where the secrets were.

While regenerating the lab panel, a latent bug in scripts/sync-labs.py turned
up: the marker pattern only allowed uppercase letters, so the tag A01-Lab1
never matched and every lab had reported an empty tag list since the panel was
introduced. The pattern now accepts the lowercase in 'Lab'."

git add backend/core/src/main/java/com/securebank/core/security/WebConfig.java
git add backend/core/src/main/java/com/securebank/core/security/AuthFilter.java
git add backend/core/src/main/java/com/securebank/lab/a02/Lab6StaticExposureController.java
git add backend/core/src/main/resources/application.yml
git add backend/core/Dockerfile
git add backend/core/docker-entrypoint.sh
git add backend/core/pom.xml
git add .gitignore
git add -A backend/core/src/main/resources/static
git add labs/labs.meta.yaml
git add scripts/verify-labs.sh
git add scripts/verify-walkthrough.sh
git add scripts/sync-labs.py
git add scripts/apply-fixed-lab6.py
git add scripts/do-commit-fixed-lab6.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
