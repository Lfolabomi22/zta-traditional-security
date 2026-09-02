"""
zta_pep_test.py — end-to-end enforcement tests.

Drives real HTTP requests through the PEP middleware with the FastAPI test
client. Verifies the four behaviours the enforcement layer must guarantee:
deny-by-default, legitimate allow, recoverable step-up, and attack denial.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient

from zta_pep import app

client = TestClient(app)
TOKENS = app.state.tokens
DEVICES = app.state.devices
REVOCATION = app.state.revocation


def login(**data) -> str:
    r = client.post("/login", json=data)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(token: str, **headers) -> dict:
    h = {"authorization": f"Bearer {token}"}
    h.update({k.replace("_", "-"): str(v) for k, v in headers.items()})
    return h


results = []


def check(name: str, got: int, expected: int, extra: str = "") -> None:
    ok = got == expected
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<52} {got} (want {expected}) {extra}")


print("Deny by default")
# unmapped route -> 403 even with a strong token
tok = login(subject="alice", roles=["admin"], amr=["passkey"], mfa=True, device_id="dev-001")
r = client.get("/api/secret-backdoor", headers=auth(tok))
check("unmapped route refused", r.status_code, 403)

print("\nLegitimate access")
r = client.get("/health")
check("anonymous health check", r.status_code, 200)

tok = login(subject="alice", roles=["user"], amr=["passkey"], mfa=True, device_id="dev-001")
r = client.get("/api/dashboard", headers=auth(tok, x_zta_source_zone="app"))
check("user dashboard with passkey+MFA", r.status_code, 200,
      f"trust={r.headers.get('x-zta-trust')}")

tok = login(subject="bola", roles=["analyst"], amr=["passkey", "fingerprint"],
            mfa=True, device_id="dev-001")
r = client.get("/api/records", headers=auth(tok, x_zta_source_zone="app"))
check("analyst reads records, compliant device", r.status_code, 200,
      f"trust={r.headers.get('x-zta-trust')}")

print("\nStep-up required")
tok = login(subject="alice", roles=["user"], amr=["password"], mfa=False, device_id="dev-001")
r = client.post("/api/profile", headers=auth(tok, x_zta_source_zone="app"))
check("profile write without MFA -> step-up", r.status_code, 401,
      f"challenge={r.json().get('challenge')}")

print("\nAttack denial")
# 1. stolen credential replayed from an unknown attacker device
tok = login(subject="alice", roles=["user"], amr=["password"], mfa=False,
            device_id="dev-attacker")
r = client.get("/api/dashboard", headers=auth(
    tok, x_zta_source_zone="public", x_zta_ip_reputation=0.4,
    x_zta_off_hours=1, x_zta_anomaly=0.8, x_zta_failed_attempts=3))
check("stolen credential, attacker device", r.status_code, 403,
      f"rule={r.json().get('rule')}")

# 2. token replay after revocation
tok = login(subject="bola", roles=["analyst"], amr=["passkey"], mfa=True,
            device_id="dev-001")
claims = TOKENS.decode(tok)
REVOCATION.revoke(claims["jti"])
r = client.get("/api/records", headers=auth(tok, x_zta_source_zone="app"))
check("replayed token after revocation", r.status_code, 403,
      f"rule={r.json().get('rule')}")

# 3. impossible-travel session hijack
tok = login(subject="alice", roles=["user"], amr=["passkey"], mfa=True,
            device_id="dev-001")
r = client.get("/api/dashboard", headers=auth(
    tok, x_zta_source_zone="app", x_zta_impossible_travel=1, x_zta_geo="RU"))
check("impossible-travel hijack", r.status_code, 403, f"rule={r.json().get('rule')}")

# 4. lateral movement to data zone from an unenrolled host
tok = login(subject="carl", roles=["admin"], amr=["passkey"], mfa=True,
            device_id="dev-unenrolled")
r = client.get("/api/records", headers=auth(tok, x_zta_source_zone="app"))
check("lateral movement, unenrolled device", r.status_code, 403,
      f"rule={r.json().get('rule')}")

# 5. brute-force / credential stuffing burst
tok = login(subject="mallory", roles=["user"], amr=["password"], mfa=False,
            device_id="dev-bot")
r = client.get("/api/dashboard", headers=auth(
    tok, x_zta_source_zone="public", x_zta_rate=300, x_zta_ip_reputation=0.2,
    x_zta_anomaly=0.95, x_zta_failed_attempts=14))
check("credential-stuffing burst", r.status_code, 403, f"rule={r.json().get('rule')}")

print("\nStep-up recovery flow")
# a genuine user hits step-up, then re-auths with biometric -> reissued token allows
tok = login(subject="alice", roles=["user"], amr=["password"], mfa=False, device_id="dev-001")
r = client.post("/api/profile", headers=auth(tok, x_zta_source_zone="app"))
assert r.status_code == 401
stepped = login(subject="alice", roles=["user"], amr=["password", "iris"],
                mfa=True, device_id="dev-001")
r = client.post("/api/profile", headers=auth(stepped, x_zta_source_zone="app"))
check("re-auth with biometric clears step-up", r.status_code, 200,
      f"trust={r.headers.get('x-zta-trust')}")

print("\n" + "=" * 62)
print(f"{sum(results)}/{len(results)} enforcement tests passed")
