"""
HAZARUS Authentication Module
Password and authentication security testing.
"""

from .hashcat import HashcatAuditor
from .hydra import HydraTester
from .kerbrute import KerbruteAuditor

__all__ = [
    "HashcatAuditor",
    "HydraTester",
    "KerbruteAuditor",
]
