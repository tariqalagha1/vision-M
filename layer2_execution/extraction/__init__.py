"""Extraction Contract — ABC interface for extraction/parsing engines.

Defines the contract that all Layer 2 extraction implementations must fulfill.
Handles content extraction, metadata extraction, and relationship extraction.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class ExtractionContract(ABC):
    """Abstract interface for extraction/parsing engines.

    Implementations must provide: content extraction, metadata extraction,
    and relationship extraction from raw data sources.
    """

    @abstractmethod
    def extract_content(self, raw_data: str,
                        source: str = "") -> Dict[str, Any]:
        """Extract structured content from raw data.

        Args:
            raw_data: Raw HTML, JSON, or text content.
            source: Source identifier for context.

        Returns:
            Dict with extracted content fields.
        """
        ...

    @abstractmethod
    def extract_metadata(self, raw_data: str,
                         source: str = "") -> Dict[str, Any]:
        """Extract metadata from raw data.

        Args:
            raw_data: Raw content to extract metadata from.
            source: Source identifier for context.

        Returns:
            Dict with metadata fields (title, author, dates, etc.).
        """
        ...

    @abstractmethod
    def extract_relationships(self, content: Dict[str, Any],
                              metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relationships between extracted entities.

        Args:
            content: Extracted content from extract_content().
            metadata: Extracted metadata from extract_metadata().

        Returns:
            Dict with relationship data (links, references, entity connections).
        """
        ...


__all__ = ["ExtractionContract"]
