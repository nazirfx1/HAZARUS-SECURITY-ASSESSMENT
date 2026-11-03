"""
HAZARUS Web Crawling Module
Content discovery and endpoint enumeration.
"""

from .feroxbuster import FeroxbusterScanner
from .ffuf import FFUFScanner

__all__ = [
    "FeroxbusterScanner",
    "FFUFScanner",
]
