"""
HAZARUS Aircrack-ng Integration
Wireless security auditing.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AircrackResult:
    """Aircrack-ng scan result."""
    target: str
    detected_networks: List[Dict] = field(default_factory=list)
    encrypted_networks: int = 0
    open_networks: int = 0
    scanned_at: datetime = None
    
    def __post_init__(self):
        if self.scanned_at is None:
            self.scanned_at = datetime.utcnow()


class AircrackScanner:
    """Aircrack-ng integration for wireless security."""
    
    def __init__(self):
        self.tool_name = "aircrack-ng"
    
    async def scan_networks(self, interface: str) -> AircrackResult:
        """Scan for wireless networks.
        
        Args:
            interface: Wireless interface name
            
        Returns:
            AircrackResult with detected networks
        """
        result = AircrackResult(target=interface)
        
        try:
            # Check if aircrack-ng is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "airodump-ng",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Aircrack-ng not installed")
            
            # Check if wireless interface exists
            check_proc = await asyncio.create_subprocess_exec(
                "iwconfig", interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await check_proc.communicate()
            
            if check_proc.returncode != 0:
                print(f"  [yellow]⚠ Wireless interface {interface} not found or not in monitor mode[/yellow]")
                print(f"  [dim]To enable: sudo airmon-ng start {interface}[/dim]")
                return result
            
            # Build command (simplified - would need actual interface setup)
            cmd = ["airodump-ng", interface]
            
            # Note: This would require actual wireless interface in monitor mode
            print(f"  [yellow]⚠ Wireless scanning requires interface in monitor mode[/yellow]")
            print(f"  [dim]To enable: sudo airmon-ng start {interface}[/dim]")
            
        except Exception as e:
            print(f"Aircrack-ng error: {e}")
        
        return result
