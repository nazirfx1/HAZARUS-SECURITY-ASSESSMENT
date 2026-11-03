"""
HAZARUS BloodHound Integration
Active Directory relationship and privilege analysis.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BloodHoundResult:
    """BloodHound analysis result."""
    target: str
    shortest_paths: int = 0
    admin_paths: int = 0
    high_value_targets: List[str] = field(default_factory=list)
    analyzed_at: datetime = None
    
    def __post_init__(self):
        if self.analyzed_at is None:
            self.analyzed_at = datetime.utcnow()


class BloodHoundAnalyzer:
    """BloodHound integration for AD assessment."""
    
    def __init__(self):
        self.tool_name = "bloodhound"
    
    async def analyze_ad(self, target: str, username: Optional[str] = None, password: Optional[str] = None) -> BloodHoundResult:
        """Analyze Active Directory with BloodHound.
        
        Args:
            target: Target domain controller
            username: AD username (if None, skips execution)
            password: AD password (if None, skips execution)
            
        Returns:
            BloodHoundResult with AD analysis
        """
        result = BloodHoundResult(target=target)
        
        try:
            # Check if bloodhound-python is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "bloodhound-python",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("BloodHound not installed")
            
            # Check if credentials are provided
            if not username or not password:
                print(f"  [yellow]⚠ BloodHound requires AD credentials[/yellow]")
                print(f"  [dim]Usage: Provide username and password for domain {target}[/dim]")
                return result
            
            # Build command
            cmd = [
                "bloodhound-python",
                "-d", target,
                "-u", username,
                "-p", password,
                "--collection", "All"
            ]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600
            )
            
            # Parse output
            output = stdout.decode()
            result = self._parse_output(output, target)
            
        except Exception as e:
            print(f"BloodHound error: {e}")
        
        return result
            
        except Exception as e:
            print(f"BloodHound error: {e}")
        
        return result
    
    def _parse_output(self, output: str, target: str) -> BloodHoundResult:
        """Parse BloodHound output."""
        result = BloodHoundResult(target=target)
        
        # Simple parsing
        lines = output.split('\n')
        for line in lines:
            if 'path' in line.lower():
                result.shortest_paths += 1
            if 'admin' in line.lower():
                result.admin_paths += 1
        
        return result
