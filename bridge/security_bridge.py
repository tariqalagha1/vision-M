"""
vision-M Bridge: Security
==========================
Connects Atlas SecurityWorker → H-Scraper security modules.

Architecture:
  Layer 1 (orchestration): SecurityWorker dispatches assessment
  Bridge: SecurityBridge routes to H-Scraper security engines
  Layer 2 (execution): PII detection, taint tracking, classification propagation,
                       secret rotation validation
"""

from __future__ import annotations

import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── H-Scraper paths ──────────────────────────────────────────────
_HSCRAPER_BACKEND = Path("/data/workspace/H-scraper-/backend")
_HSCRAPER_ROOT = Path("/data/workspace/H-scraper-")
for p in [_HSCRAPER_BACKEND, _HSCRAPER_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


class SecurityBridge:
    """Bridges Atlas orchestration to H-Scraper security engines."""

    # ── PII patterns for detection ──────────────────────────────────
    PII_PATTERNS = {
        "EMAIL": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "PHONE": re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'),
        "SSN": re.compile(r'\d{3}-\d{2}-\d{4}'),
        "CREDIT_CARD": re.compile(r'\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}'),
        "IP_ADDRESS": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "API_KEY": re.compile(r'(?:api[_-]?key|apikey|token|secret|password)["\s:=]+(["\']?)([A-Za-z0-9_\-+=/]{20,})\1', re.IGNORECASE),
    }

    SENSITIVE_FIELDS = {
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "private_key", "privatekey", "cert", "certificate", "credential",
        "ssn", "social_security", "credit_card", "cc_number",
    }

    def __init__(self):
        self._pii_detector = None
        self._taint_tracker = None
        self._classification_engine = None
        self._available = None

    @property
    def available(self) -> bool:
        if self._available is None:
            try:
                from app.security.pii.pii_detector import PIIDetector
                self._available = True
            except ImportError:
                self._available = False
        return self._available

    @property
    def pii_detector(self):
        if self._pii_detector is None and self.available:
            from app.security.pii.pii_detector import PIIDetector
            self._pii_detector = PIIDetector()
        return self._pii_detector

    @property
    def taint_tracker(self):
        if self._taint_tracker is None:
            try:
                from app.security.taint.taint_tracker import TaintTracker
                self._taint_tracker = TaintTracker()
            except ImportError:
                self._taint_tracker = None
        return self._taint_tracker

    @property
    def classification_engine(self):
        if self._classification_engine is None:
            try:
                from app.security.classification.classification_propagation import ClassificationPropagation
                self._classification_engine = ClassificationPropagation()
            except ImportError:
                self._classification_engine = None
        return self._classification_engine

    # ── Scope Verification ────────────────────────────────────────

    def verify_scope(self, target: str, authorization_ref: str) -> Dict[str, Any]:
        """Verify that the target is within authorized scope."""
        # Check for common out-of-scope patterns
        warnings = []
        blocked = False

        blocked_domains = [".gov", ".mil", ".edu"]
        internal_ips = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.",
                       "172.24.", "172.25.", "172.26.", "172.27.",
                       "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]

        for domain in blocked_domains:
            if domain in target:
                warnings.append(f"Target matches restricted domain pattern: {domain}")
                blocked = True

        for ip_prefix in internal_ips:
            if target.startswith(ip_prefix) or ip_prefix in target:
                warnings.append("Target appears to be internal/private IP")
                blocked = True

        return {
            "status": "BLOCKED" if blocked else "IN_SCOPE",
            "target": target,
            "authorization_ref": authorization_ref,
            "warnings": warnings,
            "blocked": blocked,
        }

    # ── Passive Observation ────────────────────────────────────────

    def observe_passively(self, target: str, content: str = "") -> Dict[str, Any]:
        """Passive information gathering — no active probing."""
        observations = []
        safe_content = content or ""

        # Detect exposed technologies from content
        if "nginx" in safe_content.lower():
            observations.append("nginx server detected in response")
        if "apache" in safe_content.lower():
            observations.append("Apache server detected in response")
        if "iis" in safe_content.lower():
            observations.append("IIS server detected in response")
        if "cloudfront" in safe_content.lower() or "cloudflare" in safe_content.lower():
            observations.append("CDN/WAF detected — CloudFront/Cloudflare")

        # Detect frameworks
        if "react" in safe_content.lower():
            observations.append("React frontend detected")
        if "angular" in safe_content.lower():
            observations.append("Angular frontend detected")
        if "vue" in safe_content.lower():
            observations.append("Vue.js frontend detected")

        # Headers analysis (simulated — real would inspect HTTP headers)
        security_observations = []
        if "access-control-allow-origin" in safe_content.lower():
            if "*" in safe_content:
                security_observations.append("CORS wildcard '*' detected — potential misconfiguration")

        return {
            "status": "observed",
            "observations": observations,
            "security_observations": security_observations,
            "observation_count": len(observations) + len(security_observations),
            "method": "PASSIVE_ONLY",
        }

    # ── Authorization Audit ────────────────────────────────────────

    def audit_authorization(self, target: str, content: str = "") -> Dict[str, Any]:
        """Audit authorization controls in scraped content."""
        findings = []
        safe_content = content or ""

        # Check for exposed credentials/secrets in content
        for pattern_name, pattern in self.PII_PATTERNS.items():
            matches = pattern.findall(safe_content) if safe_content else []
            if matches:
                findings.append({
                    "type": "EXPOSED_DATA",
                    "pattern": pattern_name,
                    "count": len(matches),
                    "severity": "HIGH" if pattern_name in ("API_KEY", "CREDIT_CARD", "SSN") else "MEDIUM",
                    "sample_masked": str(matches[0])[:3] + "***" if matches else "",
                })

        # Check for sensitive field names in JSON-like content
        sensitive_hits = []
        for field in self.SENSITIVE_FIELDS:
            if field in safe_content.lower():
                sensitive_hits.append(field)

        if sensitive_hits:
            findings.append({
                "type": "SENSITIVE_FIELDS_EXPOSED",
                "fields": sensitive_hits,
                "count": len(sensitive_hits),
                "severity": "HIGH" if any(f in sensitive_hits for f in
                    ["password", "secret", "private_key"]) else "MEDIUM",
            })

        return {
            "status": "audited",
            "findings_count": len(findings),
            "findings": findings,
            "critical_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        }

    # ── Exposure Analysis ──────────────────────────────────────────

    def analyze_exposure(self, auth_audit: Dict[str, Any],
                         passive_obs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall exposure surface."""
        exposure_level = "LOW"
        exposure_items = []

        findings = auth_audit.get("findings", [])
        if any(f["severity"] == "HIGH" for f in findings):
            exposure_level = "HIGH"
            exposure_items.append("High-severity data exposure detected")
        elif any(f["severity"] == "MEDIUM" for f in findings):
            exposure_level = "MEDIUM"
            exposure_items.append("Medium-severity data exposure detected")

        sec_obs = passive_obs.get("security_observations", [])
        if sec_obs:
            exposure_items.extend(sec_obs)

        return {
            "status": "analyzed",
            "exposure_level": exposure_level,
            "exposure_items": exposure_items,
            "surface_area": {
                "data_exposure": len(findings),
                "config_issues": len(sec_obs),
                "total_risk_factors": len(findings) + len(sec_obs),
            },
        }

    # ── Risk Classification ────────────────────────────────────────

    def classify_risk(self, exposure: Dict[str, Any],
                      auth_audit: Dict[str, Any]) -> Dict[str, Any]:
        """Classify risk level based on findings."""
        level = exposure.get("exposure_level", "LOW")
        critical = auth_audit.get("critical_count", 0)
        total = auth_audit.get("findings_count", 0)

        # Risk matrix
        if critical > 0:
            risk = "CRITICAL"
            action = "IMMEDIATE_REMEDIATION_REQUIRED"
        elif level == "HIGH":
            risk = "HIGH"
            action = "Remediate within 24 hours"
        elif level == "MEDIUM":
            risk = "MEDIUM"
            action = "Remediate within 7 days"
        else:
            risk = "LOW"
            action = "Monitor and review quarterly"

        return {
            "status": "classified",
            "risk_level": risk,
            "recommended_action": action,
            "finding_counts": {
                "total": total,
                "critical": critical,
                "high": sum(1 for f in auth_audit.get("findings", [])
                          if f["severity"] == "HIGH" and f["type"] != "EXPOSED_DATA" or critical > 0),
            },
        }

    # ── Recommendation Synthesis ───────────────────────────────────

    def synthesize_recommendations(self, risk: Dict[str, Any],
                                   exposure: Dict[str, Any]) -> Dict[str, Any]:
        """Produce actionable security recommendations."""
        recs = []

        if risk["risk_level"] in ("CRITICAL", "HIGH"):
            recs.append({
                "priority": 1,
                "action": "Remove exposed credentials/secrets immediately",
                "rationale": "Credentials found in response data — rotate all affected secrets",
            })

        if exposure.get("exposure_level") in ("HIGH", "MEDIUM"):
            recs.append({
                "priority": 2,
                "action": "Implement data classification review",
                "rationale": "Sensitive fields exposed in API responses — classify and redact",
            })

        recs.append({
            "priority": 3,
            "action": "Conduct full security assessment with authorized testing",
            "rationale": "Passive observation complete — active testing requires separate authorization",
        })

        return {
            "status": "synthesized",
            "recommendations": recs,
            "total_recommendations": len(recs),
            "requires_authorization": True,
        }


# ── Singleton ─────────────────────────────────────────────────────
_security_bridge: Optional[SecurityBridge] = None


def get_security_bridge() -> SecurityBridge:
    global _security_bridge
    if _security_bridge is None:
        _security_bridge = SecurityBridge()
    return _security_bridge
