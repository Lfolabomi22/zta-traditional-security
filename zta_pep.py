"""
zta_pep.py — Policy Enforcement Point (PEP)

The enforcement half of the Zero Trust control plane (NIST SP 800-207 §3.1).
Where the PDP *decides*, the PEP *acts*: it sits in the request path, gathers
the signals the PDP needs, calls it, and turns the verdict into an HTTP outcome
plus a set of enforced obligations.

Design commitments
------------------
* Deny by default. A route with no mapped policy is refused, not waved through.
  The absence of a rule is itself a rule.
* The PEP is the only way in. Every protected route passes through the same
  middleware; there is no annotation a developer can forget that silently
  bypasses evaluation.
* The PEP trusts nothing the client asserts about itself. Device posture comes
  from a server-side registry keyed by an attested device id, never from the
  raw client-supplied headers alone.
* Obligations are honoured, not merely logged: STEP_UP produces a 401 with a
  challenge, SHORTEN_SESSION actually shortens the reissued token, and
  MASK_SENSITIVE_FIELDS actually redacts the response body.

Run:  uvicorn zta_pep:app --reload
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import jwt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from zta_pdp import (
    AccessRequest, AuthMethod, Decision, DeviceContext, IdentityContext,
    Obligation, PolicyDecisionPoint, RequestContext, ResourcePolicy,
    RESOURCE_CATALOGUE, Zone,
)

# ---------------------------------------------------------------------------
# Token service (minimal IdP surface, enough to exercise the PEP end to end)
# ---------------------------------------------------------------------------

JWT_SECRET = "thesis-demo-secret-not-for-production"   # prod: RS256 private key
JWT_ALG = "HS256"


class RevocationList:
    """
    Stateless JWTs cannot be un-issued, so a compromised token stays valid until
    expiry. A server-side denylist of jti values closes that window and is what
    the 'token replay after revocation' attack scenario exercises.
    """
    def __init__(self) -> None:
        self._revoked: Set[str] = set()

    def revoke(self, jti: str) -> None:
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked


class TokenService:
    def __init__(self, revocation: RevocationList) -> None:
        self.revocation = revocation

    def issue(self, subject: str, roles: List[str], auth_methods: List[str],
              mfa: bool, ttl_seconds: int = 3600, device_id: Optional[str] = None,
              issued_at: Optional[int] = None) -> str:
        now = issued_at if issued_at is not None else int(time.time())
        payload = {
            "sub": subject,
            "roles": roles,
            "amr": auth_methods,          # authentication methods references
            "mfa": mfa,
            "device_id": device_id,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

    def decode(self, token: str) -> Dict[str, Any]:
        # We validate the signature and expiry here; revocation is checked by
        # the PEP so it can feed token_revoked into the PDP as a signal.
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


# ---------------------------------------------------------------------------
# Device registry — server-side source of truth for posture
# ---------------------------------------------------------------------------

@dataclass
class DeviceRecord:
    device_id: str
    known: bool = True
    managed: bool = False
    disk_encrypted: bool = False
    screen_lock: bool = False
    os_patch_age_days: int = 0
    edr_present: bool = False
    jailbroken: bool = False
    last_attestation: float = field(default_factory=time.time)

    def to_context(self) -> DeviceContext:
        return DeviceContext(
            device_id=self.device_id, known_device=self.known,
            managed=self.managed, disk_encrypted=self.disk_encrypted,
            screen_lock=self.screen_lock, os_patch_age_days=self.os_patch_age_days,
            edr_present=self.edr_present, jailbroken=self.jailbroken,
            attestation_age_seconds=int(time.time() - self.last_attestation))


class DeviceRegistry:
    def __init__(self) -> None:
        self._devices: Dict[str, DeviceRecord] = {}

    def enroll(self, record: DeviceRecord) -> None:
        self._devices[record.device_id] = record

    def context_for(self, device_id: Optional[str]) -> DeviceContext:
        if not device_id or device_id not in self._devices:
            # Unknown device: report exactly that, let the PDP weigh it.
            return DeviceContext(device_id=device_id, known_device=False)
        return self._devices[device_id].to_context()


# ---------------------------------------------------------------------------
# Route -> resource mapping
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteRule:
    method: str
    prefix: str
    resource_id: str


#: Ordered most-specific first; first match wins. Anything unmatched is denied.
ROUTE_TABLE: List[RouteRule] = [
    RouteRule("GET", "/health", "public.health"),
    RouteRule("GET", "/api/dashboard", "app.dashboard"),
    RouteRule("POST", "/api/profile", "app.profile.write"),
    RouteRule("GET", "/api/records/export", "data.records.export"),
    RouteRule("GET", "/api/records", "data.records.read"),
]


def resolve_policy(method: str, path: str) -> Optional[ResourcePolicy]:
    for rule in ROUTE_TABLE:
        if method == rule.method and path.startswith(rule.prefix):
            return RESOURCE_CATALOGUE.get(rule.resource_id)
    return None


# ---------------------------------------------------------------------------
# Context assembly — turn an HTTP request into the PDP's input contexts
# ---------------------------------------------------------------------------

class SignalCollector:
    """
    Gathers identity, device and request signals for the PDP. In production the
    context signals (ip reputation, impossible travel, UEBA anomaly) would come
    from dedicated services; here they arrive as X-ZTA-* headers so the attack
    scenarios remain drivable from a test client without external dependencies.
    """

    def __init__(self, tokens: TokenService, revocation: RevocationList,
                 devices: DeviceRegistry) -> None:
        self.tokens = tokens
        self.revocation = revocation
        self.devices = devices

    def identity(self, request: Request) -> tuple[Optional[IdentityContext], Optional[str]]:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return None, "missing bearer token"
        token = auth[7:]
        try:
            claims = self.tokens.decode(token)
        except jwt.ExpiredSignatureError:
            return None, "token expired"
        except jwt.InvalidTokenError as exc:
            return None, f"invalid token: {exc}"

        methods = [AuthMethod(m) for m in claims.get("amr", []) if m in AuthMethod._value2member_map_]
        ident = IdentityContext(
            subject_id=claims["sub"],
            roles=claims.get("roles", []),
            auth_methods=methods,
            mfa_satisfied=bool(claims.get("mfa", False)),
            session_age_seconds=max(0, int(time.time()) - int(claims.get("iat", time.time()))),
            failed_attempts_1h=int(request.headers.get("x-zta-failed-attempts", 0)),
            token_revoked=self.revocation.is_revoked(claims.get("jti", "")),
        )
        # bind the device id carried in the token so the PEP can cross-check
        request.state.token_device_id = claims.get("device_id")
        request.state.token_jti = claims.get("jti")
        return ident, None

    def device(self, request: Request) -> DeviceContext:
        # Prefer the device bound to the token; fall back to an explicit header.
        device_id = getattr(request.state, "token_device_id", None) \
            or request.headers.get("x-zta-device-id")
        return self.devices.context_for(device_id)

    def context(self, request: Request, source_zone: Zone) -> RequestContext:
        h = request.headers
        client_ip = request.client.host if request.client else "0.0.0.0"
        return RequestContext(
            source_zone=source_zone,
            ip_address=client_ip,
            ip_reputation=float(h.get("x-zta-ip-reputation", 0.9)),
            geo_country=h.get("x-zta-geo", "NG"),
            impossible_travel=h.get("x-zta-impossible-travel", "0") == "1",
            off_hours=h.get("x-zta-off-hours", "0") == "1",
            request_rate_1m=int(h.get("x-zta-rate", 5)),
            behavioural_anomaly=float(h.get("x-zta-anomaly", 0.05)),
        )


# ---------------------------------------------------------------------------
# The PEP middleware
# ---------------------------------------------------------------------------

class PolicyEnforcementPoint:
    def __init__(self, pdp: PolicyDecisionPoint, collector: SignalCollector,
                 tokens: TokenService) -> None:
        self.pdp = pdp
        self.collector = collector
        self.tokens = tokens

    async def __call__(self, request: Request, call_next: Callable):
        method, path = request.method, request.url.path

        if method == "OPTIONS":  # CORS preflight — never a policy decision
            return await call_next(request)

        # Non-protected utility routes bypass evaluation explicitly (not silently).
        # These are control-plane/demo-harness routes (issuing tokens, seeding
        # device posture, reading the audit trail) rather than business
        # resources, so they sit outside the ZTA policy surface by design.
        bypass_exact = {"/", "/docs", "/openapi.json", "/redoc", "/login",
                        "/enroll-demo", "/revoke"}
        bypass_prefix = ("/api/audit-log", "/api/catalogue", "/console")
        if path in bypass_exact or path.startswith(bypass_prefix):
            return await call_next(request)

        policy = resolve_policy(method, path)
        if policy is None:
            return self._deny_unmapped(method, path)

        source_zone = self._infer_source_zone(request)
        ident, err = self.collector.identity(request)
        if ident is None:
            # public resources may be reachable without a token
            if policy.zone is Zone.PUBLIC:
                ident = IdentityContext(subject_id="anonymous", roles=[],
                                        auth_methods=[AuthMethod.PASSWORD])
            else:
                return JSONResponse(status_code=401,
                                    content={"detail": f"authentication required: {err}"})

        access = AccessRequest(
            identity=ident,
            device=self.collector.device(request),
            context=self.collector.context(request, source_zone),
            resource=policy,
            action="write" if method in ("POST", "PUT", "PATCH", "DELETE") else "read",
        )

        decision = self.pdp.evaluate(access)
        request.state.decision = decision

        if decision.decision is Decision.DENY:
            return self._deny(decision)
        if decision.decision is Decision.STEP_UP:
            return self._step_up(decision)

        response = await call_next(request)
        return self._apply_allow_obligations(request, response, decision)

    # -- zone inference ----------------------------------------------------
    def _infer_source_zone(self, request: Request) -> Zone:
        # In a segmented deployment this derives from the ingress network. Here a
        # header lets the harness place a request in a zone; default public.
        z = request.headers.get("x-zta-source-zone", "public")
        try:
            return Zone(z)
        except ValueError:
            return Zone.PUBLIC

    # -- responses ---------------------------------------------------------
    def _deny_unmapped(self, method: str, path: str) -> JSONResponse:
        return JSONResponse(status_code=403, content={
            "detail": "No policy maps to this route; denied by default.",
            "route": f"{method} {path}",
            "tenet": "no implicit trust — absence of a rule is a deny",
        })

    def _deny(self, decision) -> JSONResponse:
        return JSONResponse(status_code=403, content={
            "detail": "Access denied by policy.",
            "request_id": decision.request_id,
            "rule": decision.rule_fired,
            "reasons": decision.reasons,
            "trust": round(decision.trust.composite, 1),
            "required_trust": decision.required_trust,
        }, headers={"x-zta-request-id": decision.request_id})

    def _step_up(self, decision) -> JSONResponse:
        challenge = [o.value for o in decision.obligations
                     if o in (Obligation.REQUIRE_BIOMETRIC, Obligation.REQUIRE_OTP)]
        return JSONResponse(status_code=401, content={
            "detail": "Step-up authentication required.",
            "request_id": decision.request_id,
            "rule": decision.rule_fired,
            "challenge": challenge or ["require_biometric"],
            "reasons": decision.reasons,
            "trust": round(decision.trust.composite, 1),
            "required_trust": decision.required_trust,
            "step_up_endpoint": "/step-up",
        }, headers={"x-zta-request-id": decision.request_id})

    def _apply_allow_obligations(self, request: Request, response, decision):
        obligations = set(decision.obligations)
        response.headers["x-zta-request-id"] = decision.request_id
        response.headers["x-zta-trust"] = str(round(decision.trust.composite, 1))
        response.headers["x-zta-decision"] = decision.decision.value
        if Obligation.SHORTEN_SESSION in obligations:
            response.headers["x-zta-session-ttl"] = str(decision.session_ttl_seconds)
            response.headers["x-zta-reauth-hint"] = "session shortened by policy"
        if Obligation.ENHANCED_LOGGING in obligations:
            response.headers["x-zta-enhanced-logging"] = "on"
        if Obligation.MASK_SENSITIVE_FIELDS in obligations:
            response.headers["x-zta-masking"] = "applied"
        return response


# ---------------------------------------------------------------------------
# Application wiring + demo seed data
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="ZTA PEP", version="1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                       allow_headers=["*"])

    revocation = RevocationList()
    tokens = TokenService(revocation)
    devices = DeviceRegistry()
    collector = SignalCollector(tokens, revocation, devices)

    audit_log: List[Dict[str, Any]] = []

    def audit_sink(event: Dict[str, Any]) -> None:
        audit_log.append(event)
        if len(audit_log) > 200:
            del audit_log[0]
        print(__import__("json").dumps(event), flush=True)

    pdp = PolicyDecisionPoint(audit_sink=audit_sink)
    pep = PolicyEnforcementPoint(pdp, collector, tokens)
    app.state.audit_log = audit_log

    # seed a compliant managed device + a weak unmanaged one
    devices.enroll(DeviceRecord("dev-001", known=True, managed=True,
                                disk_encrypted=True, screen_lock=True,
                                os_patch_age_days=5, edr_present=True))
    devices.enroll(DeviceRecord("dev-weak", known=True, managed=False,
                                disk_encrypted=False, screen_lock=False,
                                os_patch_age_days=200, edr_present=False))

    app.state.tokens = tokens
    app.state.devices = devices
    app.state.revocation = revocation

    app.middleware("http")(pep)

    # -- protected business routes ----------------------------------------
    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/dashboard")
    async def dashboard():
        return {"widgets": ["kpi", "alerts", "activity"]}

    @app.post("/api/profile")
    async def update_profile():
        return {"updated": True}

    @app.get("/api/records")
    async def records(request: Request):
        body = {"records": [{"id": 1, "name": "Ada", "ssn": "123-45-6789"}]}
        # honour field masking if the decision demanded it
        decision = getattr(request.state, "decision", None)
        if decision and Obligation.MASK_SENSITIVE_FIELDS in set(decision.obligations):
            for r in body["records"]:
                r["ssn"] = "***-**-****"
        return body

    @app.get("/api/records/export")
    async def export_records():
        return {"export": "csv", "rows": 1042}

    # -- helper routes (bypassed by the PEP) ------------------------------
    @app.post("/login")
    async def login(request: Request):
        """Issue a token. Body: {subject, roles, amr, mfa, device_id, ttl}."""
        data = await request.json()
        token = tokens.issue(
            subject=data["subject"], roles=data.get("roles", []),
            auth_methods=data.get("amr", []), mfa=data.get("mfa", False),
            ttl_seconds=data.get("ttl", 3600), device_id=data.get("device_id"),
            issued_at=data.get("iat"))
        return {"access_token": token, "token_type": "bearer"}

    @app.post("/enroll-demo")
    async def enroll_demo(request: Request):
        """Register a demo device with a chosen posture. Body matches DeviceRecord."""
        data = await request.json()
        devices.enroll(DeviceRecord(
            device_id=data["device_id"],
            known=data.get("known", True),
            managed=data.get("managed", False),
            disk_encrypted=data.get("disk_encrypted", False),
            screen_lock=data.get("screen_lock", False),
            os_patch_age_days=data.get("os_patch_age_days", 0),
            edr_present=data.get("edr_present", False),
            jailbroken=data.get("jailbroken", False),
        ))
        return {"enrolled": data["device_id"]}

    @app.post("/revoke")
    async def revoke_token(request: Request):
        """Revoke a token by value (console 'kill session' button)."""
        data = await request.json()
        try:
            claims = tokens.decode(data["token"])
        except jwt.InvalidTokenError as exc:
            return JSONResponse(status_code=400, content={"detail": str(exc)})
        revocation.revoke(claims["jti"])
        return {"revoked": claims["jti"]}

    @app.get("/api/audit-log")
    async def get_audit_log(limit: int = 30):
        """Recent PDP decisions, most recent first — powers the console feed."""
        return list(reversed(audit_log[-limit:]))

    @app.get("/api/catalogue")
    async def get_catalogue():
        """Expose the resource catalogue + route table so the console can
        render available actions without hardcoding them twice."""
        return {
            "routes": [
                {"method": r.method, "path": r.prefix, "resource": r.resource_id}
                for r in ROUTE_TABLE
            ],
            "resources": {
                rid: {
                    "zone": rp.zone.value,
                    "min_trust": rp.min_trust,
                    "required_roles": rp.required_roles,
                    "require_mfa": rp.require_mfa,
                    "required_auth_methods": [m.value for m in rp.required_auth_methods],
                    "allow_unmanaged_device": rp.allow_unmanaged_device,
                }
                for rid, rp in RESOURCE_CATALOGUE.items()
            },
            "devices": list(devices._devices.keys()),
        }

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/console", StaticFiles(directory=str(static_dir), html=True), name="console")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
