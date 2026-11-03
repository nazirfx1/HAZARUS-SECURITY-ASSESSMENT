"""
HAZARUS Post-Assessment Module
Privilege escalation and security auditing.
"""

from .linpeas import LinPEASScanner
from .lynis import LynisScanner

__all__ = [
    "LinPEASScanner",
    "LynisScanner",
]
