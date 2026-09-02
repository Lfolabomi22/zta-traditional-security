# Cordon — Zero Trust Architecture Demo Application

A self-contained, runnable implementation of a Zero Trust control plane
(NIST SP 800-207) protecting a small FastAPI application, with an interactive
web console for driving and observing live policy decisions.

## What's in the box

| File | Role |
|---|---|
| `zta_pdp.py` | Policy Decision Point — hard constraints, weighted trust algorithm, policy engine |
| `zta_pep.py` | Policy Enforcement Point — FastAPI middleware, token service, device registry, protected routes, console API |
| `static/index.html` | Interactive console: persona login, live trust gauge, resource actions, attack simulator, audit stream |
| `zta_pep_test.py` | End-to-end enforcement tests (11 scenarios: deny-by-default, allow, step-up, 5 attack vectors) |
| `requirements.txt` / `run.sh` | Dependencies and one-command launch |

## Run it

```bash
./run.sh
# or manually:
pip install -r requirements.txt --break-system-packages
uvicorn zta_pep:app --reload
```

Then open **http://localhost:8000/console/**.

Run the automated test suite:

```bash
python zta_pep_test.py
```

## Using the console

1. **Pick a persona** (or set subject/roles/auth methods/device manually) and click **Sign in** — this calls `/login` on the demo token service and issues a JWT.
2. **Choose a protected resource** on the right of the middle panel. Each request goes through the real PEP middleware and PDP; the response headers and body drive the trust gauge, sub-score bars, and decision explanation shown live.
3. **Attack simulator** buttons pre-fill the persona and request-context fields to reproduce five attack vectors from the thesis evaluation (stolen credential, impossible-travel hijack, credential stuffing, etc.) so you can watch the PDP deny them in real time.
4. **Kill current session** revokes the live token via `/revoke`, demonstrating that a subsequent request with the same token is denied by hard constraint `HC-01` even though nothing else about the request changed — the point being that trust alone does not matter once revocation fires.
5. The **audit stream** polls `/api/audit-log`, which mirrors exactly what `PolicyDecisionPoint.audit_sink` writes to stdout/CloudWatch in production — the console is reading the same evidence an auditor would.

## Architecture in one paragraph

Every business route (`/health`, `/api/dashboard`, `/api/profile`, `/api/records`, `/api/records/export`) is mapped to a `ResourcePolicy` in `RESOURCE_CATALOGUE`. The PEP middleware intercepts every request, assembles `IdentityContext` (from the JWT), `DeviceContext` (from the server-side device registry, never trusting client-asserted posture), and `RequestContext` (from simulated signal headers standing in for a UEBA/geo-IP service), then calls `PolicyDecisionPoint.evaluate()`. The PDP first checks non-negotiable hard constraints (revoked token, jailbroken device, impossible travel, zone/role mismatches), then computes a weighted 0–100 trust score across identity/device/context, then compares it against the resource's `min_trust` to return ALLOW, STEP_UP, or DENY with a full explanation and a set of obligations the PEP enforces (session shortening, field masking, enhanced logging, device quarantine). Routes with no mapped policy are denied by default — the absence of a rule is itself a rule.

## Endpoints reference

**Business (protected by the PEP):**
`GET /health` · `GET /api/dashboard` · `POST /api/profile` · `GET /api/records` · `GET /api/records/export`

**Control plane (bypass the PEP by design — not business resources):**
`POST /login` · `POST /enroll-demo` · `POST /revoke` · `GET /api/audit-log` · `GET /api/catalogue`

## Deploying to AWS

See `deploy/AWS_DEPLOYMENT.md` for the full step-by-step process. Short version:
```bash
cd deploy
./deploy.sh <your-key-pair-name> <your-ip>/32
```
This provisions the EC2 instance, security group, and IAM role via CloudFormation (`deploy/cloudformation.yaml`), ships the app code, starts it as a systemd service, and wires the audit log into CloudWatch Logs (`/cordon/pdp-decisions`). Tear down with `./destroy.sh` when you're done.

## Known simplifications (documented, not hidden)

In-memory storage (device registry, revocation list, audit log reset on restart); simulated sensors for biometrics and device posture; context signals (IP reputation, anomaly score, geo) supplied via headers rather than a real UEBA/geo-IP pipeline; HS256 JWT signing for demo simplicity (swap to RS256 for production); single-process deployment (no real service mesh). Each is a stated scope boundary for the prototype, not an oversight — see the thesis appendix for the full simplification list and production-path notes (WebAuthn/FIDO2 for biometrics, OPA/Rego for policy externalization, SPIFFE/SPIRE for workload identity).
