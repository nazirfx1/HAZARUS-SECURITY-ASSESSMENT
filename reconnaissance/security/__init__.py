"""
HAZARUS Security Features
Subdomain takeover detection, virtual host enumeration, and DNSSEC validation.
"""

from .subdomain_takeover import SubdomainTakeoverDetector
from .virtual_host import VirtualHostEnumerator

__all__ = [
    "SubdomainTakeoverDetector",
    "VirtualHostEnumerator",
]
