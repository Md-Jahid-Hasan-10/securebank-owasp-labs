#!/usr/bin/env bash
set -euo pipefail

# The upload directory has to exist before the app starts, otherwise the first
# upload in Lab 22 fails.
mkdir -p /app/static/uploads

# VULN: [A02-Lab6] Sensitive File Exposure - a full database backup is written into the
# static web root so that it can be downloaded at /backup.zip without authentication.
# FIX:  never write database dumps into a directory served by the web server.
#
# The dump has to wait for Flyway to have created the schema, so it runs in the
# background once the database answers.
(
  echo "[entrypoint] waiting for the database before taking the Lab 6 backup ..."
  for _ in $(seq 1 60); do
    if PGPASSWORD="${DB_PASSWORD:-securebank}" \
        psql -h "${DB_HOST:-postgres}" -p "${DB_PORT:-5432}" \
             -U "${DB_USER:-securebank}" -d "${DB_NAME:-securebank}" \
             -c "SELECT 1 FROM users LIMIT 1" >/dev/null 2>&1; then
      if PGPASSWORD="${DB_PASSWORD:-securebank}" \
          pg_dump -h "${DB_HOST:-postgres}" -p "${DB_PORT:-5432}" \
                  -U "${DB_USER:-securebank}" -d "${DB_NAME:-securebank}" -Fc \
                  > /tmp/securebank.dump 2>/dev/null; then
        ( cd /tmp && rm -f backup.zip && zip -q backup.zip securebank.dump )
        cp /tmp/backup.zip /app/static/backup.zip
        echo "[entrypoint] backup.zip written to /app/static/backup.zip"
      else
        echo "[entrypoint] pg_dump failed"
      fi
      exit 0
    fi
    sleep 2
  done
  echo "[entrypoint] database never became ready - skipping the Lab 6 backup"
) &

exec java -jar /app/app.jar
