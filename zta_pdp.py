"""
zta_pdp.py — Policy Decision Point (PDP)

Implements the decision component of a Zero Trust Architecture as described in
NIST SP 800-207 §3.1. The PDP is deliberately free of any web-framework
dependency so that it can be unit-tested in isolation and reused by any
Policy Enforcement Point (PEP).

Decision pipeline
-----------------
    AccessRequest
        -> HardConstraintEvaluator   (non-negotiable deny rules)
        -> TrustAlgorithm            (weighted, explainable 0-100 score)
        -> PolicyEngine              (resource requirements vs. trust)
        -> PolicyDecision            (ALLOW | STEP_UP | DENY + obligations)

Every decision carries a full explanation: the per-signal contributions, the
rule that fired, and the obligations the PEP must enforce. Explainability is a
requirement, not a nicety — an unexplainable deny cannot be defended in an
audit and cannot be evaluated in a thesis.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

class Decision(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    DENY = "DENY"


class Zone(str, Enum):
    """Micro-segmentation zones. Ordered from least to most sensitive."""
    PUBLIC = "public"
    APP = "app"
    DATA = "data"


class AuthMethod(str, Enum):
    PASSWORD = "password"
    OTP = "otp"
    FINGERPRINT = "fingerprint"
    IRIS = "iris"
    PALM = "palm"
    PASSKEY = "passkey"          # WebAuthn/FIDO2 — production target


#: Authenticator assurance weights. Loosely tracks NIST SP 800-63B AAL tiers:
#: a knowledge factor alone is weak, a phishing-resistant bound credential is
#: strong. Values are relative, not absolute probabilities.
AUTH_STRENGTH: Dict[AuthMethod, float] = {
    AuthMethod.PASSWORD: 0.30,
    AuthMethod.OTP: 0.55,
    AuthMethod.FINGERPRINT: 0.70,
    AuthMethod.PALM: 0.75,
    AuthMethod.IRIS: 0.85,
    AuthMethod.PASSKEY: 1.00,
}


class Obligation(str, Enum):
    """Actions the PEP must perform when honouring a decision."""
    REQUIRE_BIOMETRIC = "require_biometric"
    REQUIRE_OTP = "require_otp"
    SHORTEN_SESSION = "shorten_session"
    ENHANCED_LOGGING = "enhanced_logging"
    MASK_SENSITIVE_FIELDS = "mask_sensitive_fields"
    NOTIFY_USER = "notify_user"
    QUARANTINE_DEVICE = "quarantine_device"


# ---------------------------------------------------------------------------
# Input contexts — the three signal families the trust algorithm consumes
# ---------------------------------------------------------------------------

@dataclass
class IdentityContext:
    subject_id: str
    roles: List[str] = field(default_factory=list)
    auth_methods: List[AuthMethod] = field(default_factory=list)
    mfa_satisfied: bool = False
    session_age_seconds: int = 0
    account_age_days: int = 365
    failed_attempts_1h: int = 0
    credential_age_days: int = 30
    token_revoked: bool = False


@dataclass
class DeviceContext:
    device_id: Optional[str] = None
    known_device: bool = False
    managed: bool = False
    disk_encrypted: bool = False
    screen_lock: bool = False
    os_patch_age_days: int = 0
    edr_present: bool = False
    jailbroken: bool = False
    attestation_age_seconds: int = 0


@dataclass
class RequestContext:
    source_zone: Zone = Zone.PUBLIC
    ip_address: str = "0.0.0.0"
    ip_reputation: float = 1.0        # 0.0 = known-malicious, 1.0 = clean
    geo_country: str = "NG"
    impossible_travel: bool = False
    off_hours: bool = False
    request_rate_1m: int = 1
    behavioural_anomaly: float = 0.0  # 0.0 = typical, 1.0 = highly anomalous


@dataclass
class ResourcePolicy:
    """What a protected resource demands before it will be reached."""
    resource_id: str
    zone: Zone
    min_trust: float                              # 0-100
    required_roles: List[str] = field(default_factory=list)
    require_mfa: bool = False
    required_auth_methods: List[AuthMethod] = field(default_factory=list)
    max_session_age_seconds: Optional[int] = None
    allow_unmanaged_device: bool = True
    step_up_band: float = 20.0    # how far below min_trust step-up may recover


@dataclass
class AccessRequest:
    identity: IdentityContext
    device: DeviceContext
    context: RequestContext
    resource: ResourcePolicy
    action: str = "read"
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

@dataclass
class SignalContribution:
    name: str
    raw: Any
    weight: float
    points: float       # signed contribution to the subscore, already weighted
    note: str = ""


@dataclass
class TrustScore:
    identity: float
    device: float
    context: float
    composite: float
    contributions: List[SignalContribution] = field(default_factory=list)

    def explain(self) -> List[str]:
        return [
            f"{c.name}: {c.raw} -> {c.points:+.1f} pts ({c.note})"
            for c in self.contributions
        ]


@dataclass
class PolicyDecision:
    request_id: str
    decision: Decision
    trust: TrustScore
    required_trust: float
    reasons: List[str]
    obligations: List[Obligation]
    rule_fired: str
    session_ttl_seconds: int
    evaluated_at: float = field(default_factory=time.time)
    latency_ms: float = 0.0

    def to_audit_event(self, request: AccessRequest) -> Dict[str, Any]:
        """Single structured line for stdout -> CloudWatch Logs Insights."""
        return {
            "event": "pdp.decision",
            "request_id": self.request_id,
            "ts": self.evaluated_at,
            "subject": request.identity.subject_id,
            "device": request.device.device_id,
            "resource": request.resource.resource_id,
            "action": request.action,
            "source_zone": request.context.source_zone.value,
            "target_zone": request.resource.zone.value,
            "decision": self.decision.value,
            "rule": self.rule_fired,
            "trust_composite": round(self.trust.composite, 2),
            "trust_identity": round(self.trust.identity, 2),
            "trust_device": round(self.trust.device, 2),
            "trust_context": round(self.trust.context, 2),
            "required_trust": self.required_trust,
            "obligations": [o.value for o in self.obligations],
            "reasons": self.reasons,
            "latency_ms": round(self.latency_ms, 3),
        }


# ---------------------------------------------------------------------------
# Stage 1 — hard constraints
# ---------------------------------------------------------------------------

class HardConstraintEvaluator:
    """
    Conditions that deny regardless of accumulated trust. Kept separate from the
    scoring model on purpose: a compromised device must not be able to buy its
    way back in by scoring well elsewhere. This is the "no implicit trust"
    tenet expressed as code.
    """

    def evaluate(self, req: AccessRequest) -> Optional[tuple[str, str]]:
        i, d, c, r = req.identity, req.device, req.context, req.resource

        if i.token_revoked:
            return ("HC-01", "Presented token appears in the revocation list")
        if d.jailbroken:
            return ("HC-02", "Device reports a compromised OS integrity state")
        if c.ip_reputation <= 0.1:
            return ("HC-03", f"Source address {c.ip_address} has a hostile reputation score")
        if c.impossible_travel:
            return ("HC-04", "Geo-velocity between consecutive requests is physically impossible")
        if r.required_roles and not set(r.required_roles) & set(i.roles):
            return ("HC-05", f"Subject holds none of the roles required by {r.resource_id}")
        if r.zone is Zone.DATA and not d.known_device:
            return ("HC-06", "Unenrolled device requesting a data-zone resource")
        if not r.allow_unmanaged_device and not d.managed:
            return ("HC-07", "Resource is restricted to managed devices")
        if i.failed_attempts_1h >= 10:
            return ("HC-08", "Authentication failure threshold exceeded within the hour")
        if r.max_session_age_seconds and i.session_age_seconds > r.max_session_age_seconds:
            return ("HC-09", "Session exceeds the maximum age permitted for this resource")
        return None


# ---------------------------------------------------------------------------
# Stage 2 — trust algorithm
# ---------------------------------------------------------------------------

@dataclass
class TrustWeights:
    """
    Family weights must sum to 1.0. Identity carries the most weight because the
    threat model centres on identity theft; device and context act as the
    corroborating evidence that makes a stolen credential insufficient on its own.
    """
    identity: float = 0.45
    device: float = 0.35
    context: float = 0.20

    def validate(self) -> None:
        total = self.identity + self.device + self.context
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Trust family weights must sum to 1.0, got {total}")


class TrustAlgorithm:
    """
    Produces an explainable 0-100 composite score.

    Each subscore starts at a baseline and moves on weighted evidence, then is
    clamped to [0, 100]. A baseline above zero reflects that an authenticated
    session is not worthless — but it is capped well below the level any
    sensitive resource demands, so corroboration is always required.
    """

    def __init__(self, weights: Optional[TrustWeights] = None):
        self.weights = weights or TrustWeights()
        self.weights.validate()

    # -- identity ----------------------------------------------------------
    def _identity_subscore(self, i: IdentityContext) -> tuple[float, List[SignalContribution]]:
        contribs: List[SignalContribution] = []
        score = 25.0
        contribs.append(SignalContribution("identity.baseline", "authenticated", 1.0, 25.0,
                                           "session exists but is uncorroborated"))

        strongest = max((AUTH_STRENGTH[m] for m in i.auth_methods), default=0.0)
        pts = strongest * 35.0
        score += pts
        contribs.append(SignalContribution(
            "identity.auth_strength",
            [m.value for m in i.auth_methods] or "none",
            35.0, pts, "strongest authenticator presented"))

        pts = 15.0 if i.mfa_satisfied else -5.0
        score += pts
        contribs.append(SignalContribution("identity.mfa", i.mfa_satisfied, 15.0, pts,
                                           "multi-factor satisfied" if i.mfa_satisfied
                                           else "single factor only"))

        # Fresh sessions are more trustworthy; decay 5 pts per hour, floor -15.
        decay = max(-15.0, -(i.session_age_seconds / 3600.0) * 5.0)
        score += decay
        contribs.append(SignalContribution("identity.session_age", f"{i.session_age_seconds}s",
                                           15.0, decay, "temporal decay of session assurance"))

        pts = -min(20.0, i.failed_attempts_1h * 4.0)
        score += pts
        contribs.append(SignalContribution("identity.failed_attempts", i.failed_attempts_1h,
                                           20.0, pts, "recent authentication failures"))

        pts = 5.0 if i.account_age_days > 30 else -10.0
        score += pts
        contribs.append(SignalContribution("identity.account_age", f"{i.account_age_days}d",
                                           10.0, pts, "established account"
                                           if i.account_age_days > 30 else "newly created account"))

        pts = -8.0 if i.credential_age_days > 180 else 0.0
        score += pts
        contribs.append(SignalContribution("identity.credential_age", f"{i.credential_age_days}d",
                                           8.0, pts, "credential past rotation window"
                                           if pts else "credential within rotation window"))

        return max(0.0, min(100.0, score)), contribs

    # -- device ------------------------------------------------------------
    def _device_subscore(self, d: DeviceContext) -> tuple[float, List[SignalContribution]]:
        contribs: List[SignalContribution] = []
        score = 10.0
        contribs.append(SignalContribution("device.baseline", "present", 1.0, 10.0,
                                           "device asserted but unverified"))

        for name, ok, up, down, note in [
            ("device.known", d.known_device, 25.0, -15.0, "enrolled in the device registry"),
            ("device.managed", d.managed, 20.0, -5.0, "under mobile device management"),
            ("device.encrypted", d.disk_encrypted, 12.0, -8.0, "full-disk encryption active"),
            ("device.screen_lock", d.screen_lock, 6.0, -4.0, "screen lock enforced"),
            ("device.edr", d.edr_present, 12.0, -3.0, "endpoint detection agent reporting"),
        ]:
            pts = up if ok else down
            score += pts
            contribs.append(SignalContribution(name, ok, max(up, abs(down)), pts, note))

        if d.os_patch_age_days <= 14:
            pts = 15.0
            note = "patch level current"
        elif d.os_patch_age_days <= 45:
            pts = 0.0
            note = "patch level acceptable"
        else:
            pts = -20.0
            note = "patch level stale — known-vulnerable window"
        score += pts
        contribs.append(SignalContribution("device.patch_age", f"{d.os_patch_age_days}d",
                                           20.0, pts, note))

        # Posture attestation is perishable evidence.
        if d.attestation_age_seconds > 3600:
            pts = -12.0
            note = "posture attestation stale (>1h)"
        else:
            pts = 5.0
            note = "posture attestation fresh"
        score += pts
        contribs.append(SignalContribution("device.attestation_age",
                                           f"{d.attestation_age_seconds}s", 12.0, pts, note))

        return max(0.0, min(100.0, score)), contribs

    # -- context -----------------------------------------------------------
    def _context_subscore(self, c: RequestContext) -> tuple[float, List[SignalContribution]]:
        contribs: List[SignalContribution] = []
        score = 50.0
        contribs.append(SignalContribution("context.baseline", "neutral", 1.0, 50.0,
                                           "no contextual evidence either way"))

        zone_pts = {Zone.PUBLIC: 0.0, Zone.APP: 8.0, Zone.DATA: 12.0}[c.source_zone]
        score += zone_pts
        contribs.append(SignalContribution("context.source_zone", c.source_zone.value,
                                           12.0, zone_pts, "origin segment of the request"))

        pts = (c.ip_reputation - 0.5) * 30.0
        score += pts
        contribs.append(SignalContribution("context.ip_reputation", round(c.ip_reputation, 2),
                                           15.0, pts, "network reputation of source address"))

        pts = -10.0 if c.off_hours else 3.0
        score += pts
        contribs.append(SignalContribution("context.time_of_day",
                                           "off-hours" if c.off_hours else "business-hours",
                                           10.0, pts, "temporal access pattern"))

        pts = -c.behavioural_anomaly * 25.0
        score += pts
        contribs.append(SignalContribution("context.behaviour", round(c.behavioural_anomaly, 2),
                                           25.0, pts, "UEBA deviation from the subject's profile"))

        if c.request_rate_1m > 120:
            pts = -20.0
            note = "request rate consistent with automation"
        elif c.request_rate_1m > 40:
            pts = -8.0
            note = "elevated request rate"
        else:
            pts = 2.0
            note = "request rate within human range"
        score += pts
        contribs.append(SignalContribution("context.request_rate", c.request_rate_1m,
                                           20.0, pts, note))

        return max(0.0, min(100.0, score)), contribs

    def score(self, req: AccessRequest) -> TrustScore:
        ident, c1 = self._identity_subscore(req.identity)
        dev, c2 = self._device_subscore(req.device)
        ctx, c3 = self._context_subscore(req.context)
        composite = (ident * self.weights.identity
                     + dev * self.weights.device
                     + ctx * self.weights.context)
        return TrustScore(identity=ident, device=dev, context=ctx,
                          composite=composite, contributions=c1 + c2 + c3)


# ---------------------------------------------------------------------------
# Stage 3 — policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Compares the trust score against what the resource demands and selects one
    of three outcomes. Step-up is offered only when an additional authenticator
    could realistically close the gap — otherwise the prompt is theatre.
    """

    def decide(self, req: AccessRequest, trust: TrustScore) -> tuple[Decision, str, List[str], List[Obligation]]:
        r, i = req.resource, req.identity
        reasons: List[str] = []
        obligations: List[Obligation] = []

        missing_methods = [m for m in r.required_auth_methods if m not in i.auth_methods]
        mfa_gap = r.require_mfa and not i.mfa_satisfied
        gap = r.min_trust - trust.composite

        if mfa_gap:
            reasons.append(f"{r.resource_id} requires multi-factor authentication")
        if missing_methods:
            reasons.append("Missing required authenticators: "
                           + ", ".join(m.value for m in missing_methods))

        # -- recoverable shortfalls -> step up
        if mfa_gap or missing_methods:
            obligations.append(Obligation.REQUIRE_BIOMETRIC if missing_methods
                               else Obligation.REQUIRE_OTP)
            if gap > r.step_up_band + 15.0:
                reasons.append(f"Trust deficit of {gap:.1f} exceeds what step-up can recover")
                return Decision.DENY, "PR-03", reasons, [Obligation.NOTIFY_USER]
            return Decision.STEP_UP, "PR-01", reasons, obligations

        if gap <= 0:
            reasons.append(f"Trust {trust.composite:.1f} meets the {r.min_trust:.0f} "
                           f"threshold for {r.resource_id}")
            if trust.device < 50:
                obligations.append(Obligation.ENHANCED_LOGGING)
            if trust.composite < r.min_trust + 10:
                obligations.append(Obligation.SHORTEN_SESSION)
            return Decision.ALLOW, "PR-00", reasons, obligations

        if gap <= r.step_up_band:
            reasons.append(f"Trust {trust.composite:.1f} falls {gap:.1f} short of "
                           f"{r.min_trust:.0f}; recoverable by step-up")
            obligations += [Obligation.REQUIRE_BIOMETRIC, Obligation.SHORTEN_SESSION]
            return Decision.STEP_UP, "PR-02", reasons, obligations

        reasons.append(f"Trust {trust.composite:.1f} falls {gap:.1f} short of "
                       f"{r.min_trust:.0f}; outside the step-up band")
        weakest = min([("identity", trust.identity), ("device", trust.device),
                       ("context", trust.context)], key=lambda p: p[1])
        reasons.append(f"Weakest signal family: {weakest[0]} at {weakest[1]:.1f}")
        if trust.device < 30:
            obligations.append(Obligation.QUARANTINE_DEVICE)
        return Decision.DENY, "PR-04", reasons, obligations


# ---------------------------------------------------------------------------
# The PDP itself
# ---------------------------------------------------------------------------

class PolicyDecisionPoint:
    """Entry point the PEP calls. One method, one decision, one audit line."""

    BASE_TTL = 3600
    SHORT_TTL = 600

    def __init__(self,
                 trust_algorithm: Optional[TrustAlgorithm] = None,
                 policy_engine: Optional[PolicyEngine] = None,
                 hard_constraints: Optional[HardConstraintEvaluator] = None,
                 audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.trust_algorithm = trust_algorithm or TrustAlgorithm()
        self.policy_engine = policy_engine or PolicyEngine()
        self.hard_constraints = hard_constraints or HardConstraintEvaluator()
        self.audit_sink = audit_sink or (lambda e: print(json.dumps(e), flush=True))

    def evaluate(self, req: AccessRequest) -> PolicyDecision:
        started = time.perf_counter()
        trust = self.trust_algorithm.score(req)

        violation = self.hard_constraints.evaluate(req)
        if violation:
            rule, reason = violation
            obligations = [Obligation.ENHANCED_LOGGING, Obligation.NOTIFY_USER]
            if rule == "HC-02":
                obligations.append(Obligation.QUARANTINE_DEVICE)
            decision = PolicyDecision(
                request_id=req.request_id,
                decision=Decision.DENY,
                trust=trust,
                required_trust=req.resource.min_trust,
                reasons=[reason],
                obligations=obligations,
                rule_fired=rule,
                session_ttl_seconds=0,
            )
        else:
            verdict, rule, reasons, obligations = self.policy_engine.decide(req, trust)
            ttl = 0 if verdict is Decision.DENY else (
                self.SHORT_TTL if Obligation.SHORTEN_SESSION in obligations else self.BASE_TTL)
            decision = PolicyDecision(
                request_id=req.request_id,
                decision=verdict,
                trust=trust,
                required_trust=req.resource.min_trust,
                reasons=reasons,
                obligations=obligations,
                rule_fired=rule,
                session_ttl_seconds=ttl,
            )

        decision.latency_ms = (time.perf_counter() - started) * 1000.0
        self.audit_sink(decision.to_audit_event(req))
        return decision


# ---------------------------------------------------------------------------
# Resource catalogue — the policies your PEP will look up by route
# ---------------------------------------------------------------------------

RESOURCE_CATALOGUE: Dict[str, ResourcePolicy] = {
    "public.health": ResourcePolicy(
        resource_id="public.health", zone=Zone.PUBLIC, min_trust=20.0),
    "app.dashboard": ResourcePolicy(
        resource_id="app.dashboard", zone=Zone.APP, min_trust=55.0,
        required_roles=["user", "admin"], max_session_age_seconds=28800),
    "app.profile.write": ResourcePolicy(
        resource_id="app.profile.write", zone=Zone.APP, min_trust=65.0,
        required_roles=["user", "admin"], require_mfa=True),
    "data.records.read": ResourcePolicy(
        resource_id="data.records.read", zone=Zone.DATA, min_trust=75.0,
        required_roles=["analyst", "admin"], require_mfa=True,
        allow_unmanaged_device=False, max_session_age_seconds=3600),
    "data.records.export": ResourcePolicy(
        resource_id="data.records.export", zone=Zone.DATA, min_trust=88.0,
        required_roles=["admin"], require_mfa=True,
        required_auth_methods=[AuthMethod.IRIS],
        allow_unmanaged_device=False, max_session_age_seconds=900,
        step_up_band=12.0),
}
