#!/usr/bin/env bash
set -euo pipefail

cd "/home/bs01092/Projects/CyberSecurity Test/Practice"

MSG="fix(A02-Lab4): stop leaking configuration and stack traces to the client

The debug endpoint dumped the entire resolved application configuration to any
caller, including the JWT signing secret and the database credentials. The
global error handler did the same on every unhandled exception in the whole
application - it caught Exception, so any 500 anywhere handed over the signing
secret, the datasource URL, the request URI and the full stack trace.

Three changes:

  - The debug endpoint now requires the admin role, and it has come off the
    auth filter's public-path allowlist so an anonymous caller is turned away
    by the filter itself.
  - The debug endpoint no longer returns jwt.secret or the datasource
    credentials. No secret should travel in an HTTP response, not even to an
    administrator.
  - The global error handler returns only a generic message and a correlation
    id, and logs the detail server-side. The correlation id lets a user quote
    the failure to support without the response carrying anything sensitive.

The framework defaults are tightened as a second layer:
server.error.include-stacktrace/include-message are now 'never' and
include-exception is 'false'.

Lab 23 shares the global error handler, so its assertions are inverted at the
same time - the handler no longer returns a stack trace. Lab 23's own
remediation, validating the id in Lab23VerboseErrorController, belongs to the
Lab 23 pass and is not done here."

git add backend/core/src/main/java/com/securebank/lab/a02/Lab4DebugController.java
git add backend/core/src/main/java/com/securebank/lab/a02/Lab4ErrorController.java
git add backend/core/src/main/java/com/securebank/core/security/AuthFilter.java
git add backend/core/src/main/resources/application.yml
git add labs/labs.meta.yaml
git add scripts/verify-labs.sh
git add scripts/verify-walkthrough.sh
git add scripts/apply-fixed-lab4.py
git add scripts/do-push-fixed-lab3.sh

git commit -m "$MSG"
git log --oneline -3
git status --short
