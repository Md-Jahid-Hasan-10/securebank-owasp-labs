#!/usr/bin/env python3
"""Smoke-check every service and the Lab 6 static file fixtures."""
import json
import urllib.error
import urllib.request


def probe(name, url, expect=None):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        print(f"{name}: HTTP {exc.code}  FAIL")
        return False
    except Exception as exc:
        print(f"{name}: ERROR {exc}  FAIL")
        return False

    ok = True
    if expect is not None:
        ok = expect in body
    status = "OK" if ok else "FAIL"
    print(f"{name}: {resp.status} ({len(body)} bytes)  {status}")
    return ok


def probe_report(name, url, payload, expect):
    """POST a JSON body and look for a marker in the response."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        print(f"{name}: HTTP {exc.code}  FAIL")
        return False
    except Exception as exc:
        print(f"{name}: ERROR {exc}  FAIL")
        return False

    ok = expect in body
    status = "OK" if ok else "FAIL"
    print(f"{name}: {resp.status} ({len(body)} bytes)  {status}")
    return ok


results = [
    probe("frontend index      ", "http://localhost/"),
    probe("labs API (nginx)    ", "http://localhost/api/labs"),
    probe("core API (labs)     ", "http://localhost:8080/api/labs"),
    probe("core health         ", "http://localhost:8080/api/health", b'"status":"UP"'),
    probe("report health       ", "http://localhost:8081/api/report/health", b'"status":"UP"'),
    probe_report(
        "report API (SSTI)    ",
        "http://localhost:8081/api/report/report/generate",
        {"account_id": "1001", "template": "Secret: ${config.secretKey}"},
        b"sb-report-internal-secret",
    ),
    probe("Lab 6 /.env         ", "http://localhost/.env", b"JWT_SECRET"),
    probe("Lab 6 /.git/config  ", "http://localhost/.git/config", b"securebank-internet-banking.git"),
    probe("Lab 6 /backup.zip   ", "http://localhost/backup.zip", b"PK"),
]

print()
if all(results):
    print("OK - every service is up and the Lab 6 fixtures are exposed.")
else:
    print("FAIL - see above.")
    raise SystemExit(1)
