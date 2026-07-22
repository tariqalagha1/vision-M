"""Mining Contract — ABC interface for mining execution engines.

Defines the contract that all Layer 2 mining implementations must fulfill.
Mirrors the MiningBridge API surface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class MiningContract(ABC):
    """Abstract interface for mining execution engines.

    Implementations must provide: baseline establishment, pattern discovery,
    trend analysis, and insight synthesis.
    """

    @abstractmethod
    def establish_baseline(self, data: list) -> Dict[str, Any]:
        """Establish statistical baseline from data sample.

        Args:
            data: List of records to baseline against.

        Returns:
            Dict with status, metrics, and confidence.
        """
        ...

    @abstractmethod
    def discover_patterns(self, data: list,
                          fields: Optional[list] = None) -> Dict[str, Any]:
        """Discover patterns in the data.

        Args:
            data: List of records to mine.
            fields: Optional list of field names to focus on.

        Returns:
            Dict with status, patterns_detected, and patterns list.
        """
        ...

    @abstractmethod
    def analyze_trends(self, data: list) -> Dict[str, Any]:
        """Analyze temporal trends in the data.

        Args:
            data: List of records to analyze.

        Returns:
            Dict with status, engine, and trend data.
        """
        ...

    @abstractmethod
    def synthesize_insights(self, patterns: list, trends: dict,
                            source: str) -> Dict[str, Any]:
        """Synthesize commercial intelligence from mining results.

        Args:
            patterns: List of discovered patterns.
            trends: Trend analysis results.
            source: Source identifier for context.

        Returns:
            Dict with status, insight_count, insights, and commercial_value.
        """
        ...


__all__ = ["MiningContract"]
