"""
HAZARUS Wireshark Integration
Network packet analysis.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class WiresharkResult:
    """Wireshark/TShark analysis result."""
    target: str
    captured_packets: int = 0
    protocols: Dict[str, int] = field(default_factory=dict)
    top_hosts: List[str] = field(default_factory=list)
    analyzed_at: datetime = None
    
    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class WiresharkAnalyzer:
    """Wireshark/TShark integration for packet analysis."""
    
    def __init__(self):
        self.tool_name = "tshark"
    
    async def analyze_capture(self, capture_file: str) -> WiresharkResult:
        """Analyze packet capture file.
        
        Args:
            capture_file: Path to pcap file
            
        Returns:
            WiresharkResult with analysis data
        """
        result = WiresharkResult(target=capture_file)
        
        try:
            # Check if tshark is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "tshark",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("TShark not installed")
            
            # Get timeout from config
            from core.config import get_config
            config = get_config()
            timeout = config.get('timeouts.wireless', 300)
            
            # Build command
            cmd = ["tshark", "-r", capture_file, "-q", "-z", "io,phs"]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, capture_file)
            
        except Exception as e:
            print(f"TShark error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> WiresharkResult:
        """Parse TShark output."""
        result = WiresharkResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'packets' in line.lower():
                import re
                match = re.search(r'(\d+)\s+packets', line)
                if match:
                    result.captured_packets = int(match.group(1))
        
        return result
