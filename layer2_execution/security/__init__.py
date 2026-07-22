"""Security Contract — ABC interface for security execution engines.

Defines the contract that all Layer 2 security implementations must fulfill.
Mirrors the SecurityBridge API surface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class SecurityContract(ABC):
    """Abstract interface for security execution engines.

    Implementations must provide: scope verification, passive observation,
    authorization audit, exposure analysis, risk classification, and
    recommendation synthesis.
    """

    @abstractmethod
    def verify_scope(self, target: str,
                     authorization_ref: str) -> Dict[str, Any]:
        """Verify that the target is within authorized scope.

        Args:
            target: The target URL or identifier.
            authorization_ref: Reference to the authorization context.

        Returns:
            Dict with status (IN_SCOPE/BLOCKED), warnings, and blocked flag.
        """
        ...

    @abstractmethod
    def observe_passively(self, target: str,
                          content: str = "") -> Dict[str, Any]:
        """Passive information gathering — no active probing.

        Args:
            target: The target to observe.
            content: Optional content to inspect.

        Returns:
            Dict with status, observations, security_observations, and method.
        """
        ...

    @abstractmethod
    def audit_authorization(self, target: str,
                            content: str = "") -> Dict[str, Any]:
        """Audit authorization controls in content.

        Args:
            target: The target URL or identifier.
            content: Content to audit for exposed data.

        Returns:
            Dict with status, findings_count, findings, and critical_count.
        """
        ...

    @abstractmethod
    def analyze_exposure(self, auth_audit: Dict[str, Any],
                         passive_obs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall exposure surface.

        Args:
            auth_audit: Results from audit_authorization().
            passive_obs: Results from observe_passively().

        Returns:
            Dict with status, exposure_level, exposure_items, and surface_area.
        """
        ...

    @abstractmethod
    def classify_risk(self, exposure: Dict[str, Any],
                      auth_audit: Dict[str, Any]) -> Dict[str, Any]:
        """Classify risk level based on findings.

        Args:
            exposure: Results from analyze_exposure().
            auth_audit: Results from audit_authorization().

        Returns:
            Dict with status, risk_level, recommended_action, and finding_counts.
        """
        ...

    @abstractmethod
    def synthesize_recommendations(self, risk: Dict[str, Any],
                                   exposure: Dict[str, Any]) -> Dict[str, Any]:
        """Produce actionable security recommendations.

        Args:
            risk: Results from classify_risk().
            exposure: Results from analyze_exposure().

        Returns:
            Dict with status, recommendations, total_recommendations, and requires_authorization.
        """
        ...


__all__ = ["SecurityContract"]
