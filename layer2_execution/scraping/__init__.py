"""Scraping Contract — ABC interface for scraping execution engines.

Defines the contract that all Layer 2 scraping implementations must fulfill.
Mirrors the ScrapingBridge API surface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class ScrapingContract(ABC):
    """Abstract interface for scraping execution engines.

    Implementations must provide: source validation, content acquisition,
    evidence collection, and verification.
    """

    @abstractmethod
    def acquire(self, target: str, html: str = "",
                selectors: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Execute content acquisition from the target.

        Args:
            target: URL or identifier of the scraping target.
            html: Optional pre-fetched HTML content.
            selectors: Optional CSS selectors for targeted extraction.

        Returns:
            Dict with status, output, bytes, and engine metadata.
        """
        ...

    @abstractmethod
    def validate_source(self, target: str) -> Dict[str, Any]:
        """Validate a scraping target for reachability, scope, and protocol.

        Args:
            target: URL or identifier to validate.

        Returns:
            Dict with status, in_scope, reachable, protocol, and warnings.
        """
        ...

    @abstractmethod
    def collect_evidence(self, target: str,
                         acquisition_result: Dict[str, Any]) -> Dict[str, Any]:
        """Collect evidence from an acquisition result.

        Args:
            target: The original scraping target.
            acquisition_result: Result dict from acquire().

        Returns:
            Dict with status, items, hashes, engine, bytes, and timestamp.
        """
        ...

    @abstractmethod
    def verify(self, evidence: list,
               acquisition_result: Dict[str, Any]) -> Dict[str, Any]:
        """Verify scraped evidence quality.

        Args:
            evidence: List of collected evidence items.
            acquisition_result: Result dict from acquire().

        Returns:
            Dict with status, passed/failed counts, and checks.
        """
        ...


__all__ = ["ScrapingContract"]
