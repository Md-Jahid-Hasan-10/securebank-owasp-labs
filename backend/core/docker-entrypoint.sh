#!/usr/bin/env bash
set -euo pipefail

# The upload directory has to exist before the app starts, otherwise the first
# upload in Lab 22 fails.
mkdir -p /app/static/uploads

# FIXED: [A02-Lab6] Sensitive File Exposure - the database backup is no longer
# written into the static web root. It used to be copied to
# /app/static/backup.zip, where anyone could download the entire database -
# every user, balance and password hash - without authentication.
#
# The dump is still taken (it is useful for a genuine off-host backup), but it
# now stays in /app/backups, which is outside every directory the web server
# serves, and it is never reachable over HTTP.
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
        mkdir -p /app/backups
        cp /tmp/backup.zip /app/backups/backup.zip
        chmod 600 /app/backups/backup.zip
        echo "[entrypoint] backup.zip written to /app/backups/backup.zip (outside the web root)"
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
