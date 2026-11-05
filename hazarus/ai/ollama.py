"""
HAZARUS Ollama Integration
Local model execution.
"""

import asyncio
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from hazarus.core.config import get_config
config = get_config()


@dataclass
class OllamaResult:
    """Ollama inference result."""
    model: str
    response: str = ""
    executed_at: datetime = None
    
    def __post_init__(self):
        if self.executed_at is None:
            self.executed_at = datetime.utcnow()


class OllamaClient:
    """Ollama client for local AI models."""
    
    def __init__(self):
        self.tool_name = "ollama"
    
    async def query(self, model: str, prompt: str) -> OllamaResult:
        """Query Ollama model.
        
        Args:
            model: Model name
            prompt: Query prompt
            
        Returns:
            OllamaResult with response
        """
        result = OllamaResult(model=model)
        
        try:
            # Check if ollama is installed
            proc = await asyncio.create_subprocess_exec(
                "which", "ollama",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode != 0:
                raise RuntimeError("Ollama not installed")
            
            # Build command
            cmd = ["ollama", "run", model, prompt]
            
            # Execute
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.get('timeouts.ai', 300)
            )
            
            result.response = stdout.decode()
            
        except Exception as e:
            print(f"Ollama error: {e}")
        
        return result
