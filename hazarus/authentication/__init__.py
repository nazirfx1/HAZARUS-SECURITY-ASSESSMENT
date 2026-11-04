"""
HAZARUS Authentication Module
Password and authentication security testing.
"""

from hazarus.authentication.hashcat import HashcatAuditor
from hazarus.authentication.hydra import HydraTester
from hazarus.authentication.kerbrute import KerbruteAuditor
from hazarus.authentication.john import JohnAuditor

__all__ = [
    "HashcatAuditor",
    "HydraTester",
    "KerbruteAuditor",
    "JohnAuditor",
]
