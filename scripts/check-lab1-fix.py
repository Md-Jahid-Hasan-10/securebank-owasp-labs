#!/usr/bin/env python3
"""Check that the Lab 1 fix blocks the exploit without breaking legitimate access."""
import json
import urllib.error
import urllib.request

API = "http://localhost:8080"


def login(username, password):
    req = urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)["token"]


def get(path, token):
    req = urllib.request.Request(
        f"{API}{path}", headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


alice = login("alice", "password123")

status, body = get("/api/a01/accounts/1", alice)
print(f"alice -> own account (id=1)   : HTTP {status}  {body[:110]}")
own_ok = status == 200 and "ACC-1001" in body

status, body = get("/api/a01/accounts/2", alice)
print(f"alice -> bob's account (id=2)  : HTTP {status}  {body[:110]}")
bob_blocked = status == 404 and "ACC-1002" not in body

status, body = get("/api/a01/accounts/9999", alice)
print(f"alice -> nonexistent (id=9999) : HTTP {status}  {body[:110]}")
missing = status == 404

print()
# The two rejection responses must be indistinguishable - no enumeration oracle.
_, bob_body = get("/api/a01/accounts/2", alice)
_, missing_body = get("/api/a01/accounts/9999", alice)
indistinguishable = bob_body == missing_body
print(f"rejection bodies identical      : {indistinguishable}")
if not indistinguishable:
    print(f"   bob's     : {bob_body}")
    print(f"   missing   : {missing_body}")

print()
checks = [
    ("alice can still read her own account", own_ok),
    ("alice CANNOT read bob's account", bob_blocked),
    ("a nonexistent account is 404", missing),
    ("no enumeration oracle (identical errors)", indistinguishable),
]

for name, ok in checks:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")

print()
if all(ok for _, ok in checks):
    print("OK - Lab 1 is fixed and enumeration is closed.")
else:
    print("FAIL - see above.")
    raise SystemExit(1)
