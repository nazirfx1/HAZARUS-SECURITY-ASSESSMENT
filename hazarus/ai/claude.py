"""
HAZARUS Claude API Integration
AI-assisted analysis and reporting.
"""

import asyncio
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ClaudeResult:
    """Claude API result."""
    prompt: str
    response: str = ""
    executed_at: datetime = None
    
    def __post_init__(self):
        if self.executed_at is None:
            self.executed_at = datetime.utcnow()


class ClaudeClient:
    """Claude API client for AI-assisted analysis."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.tool_name = "claude"
        self.api_key = api_key
    
    async def query(self, prompt: str) -> ClaudeResult:
        """Query Claude API.
        
        Args:
            prompt: Query prompt
            
        Returns:
            ClaudeResult with response
        """
        result = ClaudeResult(prompt=prompt)
        
        try:
            # Check if anthropic is installed
            import anthropic
            
            if not self.api_key:
                raise RuntimeError("Claude API key not set")
            
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )
            
            result.response = response.content[0].text
            
        except Exception as e:
            print(f"Claude API error: {e}")
        
        return result
