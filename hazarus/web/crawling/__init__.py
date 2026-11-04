"""
HAZARUS Web Crawling Module
Content discovery and endpoint enumeration.
"""

from hazarus.web.crawling.feroxbuster import FeroxbusterScanner
from hazarus.web.crawling.ffuf import FFUFScanner

__all__ = [
    "FeroxbusterScanner",
    "FFUFScanner",
]
