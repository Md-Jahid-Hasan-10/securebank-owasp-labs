# Build context is the repository root so that the lab content pipeline
# (labs/labs.meta.yaml + scripts/sync-labs.py) is available to the build.
#
#   docker build -f backend/core/Dockerfile -t securebank-core .

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build

# The stage mirrors the repository layout (backend/, labs/, scripts/) because
# scripts/sync-labs.py resolves the Java sources relative to its own location.

# Dependency layer: resolve artifacts before copying sources so code edits
# do not invalidate the dependency cache.
COPY backend/pom.xml ./backend/pom.xml
COPY backend/core/pom.xml ./backend/core/pom.xml
COPY backend/report/pom.xml ./backend/report/pom.xml
RUN cd backend && mvn -q -B -pl core -am dependency:go-offline || true

COPY backend/core ./backend/core
COPY backend/report ./backend/report

# The lab panel payload is generated from the live Java sources so it can never
# drift out of date. It is not committed (see .gitignore), so it has to be
# produced here, before the jar is packaged.
COPY labs ./labs
COPY scripts/sync-labs.py ./scripts/sync-labs.py
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --quiet --break-system-packages pyyaml \
    && python3 scripts/sync-labs.py

RUN cd backend && mvn -q -B -pl core -am package -DskipTests

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# postgresql-client-16 provides pg_dump (Lab 6 backup), zip provides the archiver.
# The client version has to match the server version, otherwise pg_dump refuses to
# run ("server version: 16.16; pg_dump version: 14.24").
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gnupg zip \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
         -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt jammy-pgdg main" \
         > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-16 \
    && ln -sf /usr/lib/postgresql/16/bin/pg_dump /usr/local/bin/pg_dump \
    && ln -sf /usr/lib/postgresql/16/bin/psql /usr/local/bin/psql \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/backend/core/target/*.jar app.jar
COPY backend/core/docker-entrypoint.sh /app/docker-entrypoint.sh
# VULN: [A02-Lab6] Sensitive File Exposure - the fake .git directory is copied into
# the image's web root, so that /.git/config is downloadable over HTTP. This mirrors
# what happens when an application is deployed straight out of a repository checkout.
# FIX:  never ship a .git directory (or a .env file) inside the document root.
COPY backend/core/src/main/resources/static/.git /app/static/.git
RUN chmod +x /app/docker-entrypoint.sh \
    && mkdir -p /app/static/uploads

EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
