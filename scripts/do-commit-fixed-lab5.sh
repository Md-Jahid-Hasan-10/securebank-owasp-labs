#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(A02-Lab5): make the seeded admin password a dead end

The admin console shipped with admin/admin. Anyone who had read the seed
script or the public repository could sign in as the administrator of a
freshly deployed instance and mint further administrator accounts from
there.

The flag lives on the account, not in the console:

  - users.must_change_password marks an account whose password is still the
    factory default. The seeded administrator carries it, and so does every
    account created through the admin API.
  - Both login paths - /api/a02/admin/login and /api/auth/login - refuse an
    account that still carries the flag, with 403 and must_change_password.
    Blocking only the admin console would have left the default credential
    working on the main login path.
  - The password-change endpoint proves identity with the username plus the
    current password rather than with a session. The account has no session
    yet - that is the whole point of the flag - so requiring one would have
    locked the account out of its own fix. It sits on the auth filter's
    public-path allowlist for the same reason.
  - Creating an administrator now requires the admin role, taken from the
    verified JWT and never from the request body. A customer account could
    previously mint itself an administrator and take over the back office.

The admin console gains the change-password flow, so there is a way in, and
the seeded account can be unlocked from the browser.

The verification scripts now assert the opposite of what they used to: the
factory password must not yield a session on either path, a customer must not
be able to create an administrator, and a newly created administrator must be
flagged for a change too. Lab 2 and Lab 4 need an admin token, so they unlock
the seeded account first through the password endpoint. The Lab 10 row-count
assertion now checks the seeded usernames instead of a fixed number, because
the admin accounts the Lab 5 checks create make that count grow."

git add backend/core/src/main/java/com/securebank/lab/a02/Lab5DefaultAdminController.java
git add backend/core/src/main/java/com/securebank/core/security/AuthController.java
git add backend/core/src/main/java/com/securebank/core/security/AuthFilter.java
git add backend/core/src/main/java/com/securebank/core/user/User.java
git add backend/core/src/main/java/com/securebank/core/user/UserRepository.java
git add backend/core/src/main/resources/db/migration/V1__schema.sql
git add backend/core/src/main/resources/db/migration/V2__seed.sql
git add backend/core/src/main/resources/db/migration/V3__must_change_password.sql
git add frontend/src/features/admin/AdminConsolePage.jsx
git add frontend/src/api/client.js
git add frontend/src/components/Layout.jsx
git add frontend/src/styles.css
git add frontend/vite.config.js
git add frontend/nginx.conf
git add frontend/Dockerfile
git add docker-compose.yml
git add labs/labs.meta.yaml
git add scripts/verify-labs.sh
git add scripts/verify-walkthrough.sh
git add scripts/apply-fixed-lab5.py
git add scripts/do-commit-fixed-lab5.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
