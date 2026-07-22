"""vision-M Bridge Package.

Connects Layer 1 (orchestration) to Layer 2 (execution) via bridge modules
that route Atlas worker jobs to H-Scraper engines.
"""

from bridge.scraping_bridge import ScrapingBridge, get_scraping_bridge
from bridge.mining_bridge import MiningBridge, get_mining_bridge
from bridge.security_bridge import SecurityBridge, get_security_bridge

__all__ = [
    "ScrapingBridge",
    "get_scraping_bridge",
    "MiningBridge",
    "get_mining_bridge",
    "SecurityBridge",
    "get_security_bridge",
]
