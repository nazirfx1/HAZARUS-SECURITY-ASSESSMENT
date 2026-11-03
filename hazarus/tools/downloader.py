"""
HAZARUS GitHub Release Downloader
Downloads and extracts tool releases from GitHub.
"""

import asyncio
import httpx
import re
import os
import zipfile
import tarfile
from typing import Optional
from pathlib import Path


class GitHubDownloader:
    """Downloads and extracts tools from GitHub releases."""
    
    def __init__(self):
        """Initialize GitHub downloader."""
        self.api_base = "https://api.github.com"
        self.download_dir = Path.home() / ".hazarus" / "downloads"
        self.download_dir.mkdir(parents=True, exist_ok=True)
    
    async def download_latest_release(
        self,
        repo: str,
        asset_pattern: str,
        timeout: int = 300
    ) -> Optional[Path]:
        """Download the latest release asset matching a pattern.
        
        Args:
            repo: Repository in format "owner/repo"
            asset_pattern: Regex pattern to match asset name
            timeout: Download timeout in seconds
            
        Returns:
            Path to downloaded file or None if failed
        """
        try:
            # Get latest release info
            release_info = await self._get_latest_release(repo)
            if not release_info:
                return None
            
            # Find matching asset
            asset_url = self._find_matching_asset(
                release_info.get('assets', []),
                asset_pattern
            )
            
            if not asset_url:
                return None
            
            # Download asset with redirect following
            return await self._download_file(asset_url, timeout, follow_redirects=True)
            
        except Exception as e:
            print(f"GitHub download failed: {e}")
            return None
    
    async def _get_latest_release(self, repo: str) -> Optional[dict]:
        """Get latest release information from GitHub API.
        
        Args:
            repo: Repository in format "owner/repo"
            
        Returns:
            Release information dict or None
        """
        url = f"{self.api_base}/repos/{repo}/releases/latest"
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url)
            
            if response.status_code == 200:
                return response.json()
            
            return None
    
    def _find_matching_asset(self, assets: list, pattern: str) -> Optional[str]:
        """Find asset URL matching pattern.
        
        Args:
            assets: List of asset dicts from GitHub API
            pattern: Regex pattern to match
            
        Returns:
            Browser download URL or None
        """
        for asset in assets:
            name = asset.get('name', '')
            if re.search(pattern, name):
                return asset.get('browser_download_url')
        return None
    
    async def _download_file(self, url: str, timeout: int, follow_redirects: bool = True) -> Optional[Path]:
        """Download file from URL.
        
        Args:
            url: URL to download from
            timeout: Timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
            
        Returns:
            Path to downloaded file or None
        """
        try:
            filename = url.split('/')[-1].split('?')[0]  # Handle URLs with query params
            filepath = self.download_dir / filename
            
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=follow_redirects) as client:
                async with client.stream('GET', url) as response:
                    response.raise_for_status()
                    
                    with open(filepath, 'wb') as f:
                        async for chunk in response.aiter_bytes():
                            f.write(chunk)
            
            return filepath
            
        except Exception as e:
            print(f"Download failed: {e}")
            return None
    
    async def extract_archive(self, archive_path: Path) -> Optional[Path]:
        """Extract archive to temporary directory.
        
        Args:
            archive_path: Path to archive file
            
        Returns:
            Path to extracted directory or None
        """
        try:
            extract_dir = self.download_dir / f"{archive_path.stem}_extracted"
            extract_dir.mkdir(exist_ok=True)
            
            if archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            elif archive_path.suffix in ['.tar', '.gz', '.tgz', '.bz2']:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
            else:
                return None
            
            return extract_dir
            
        except Exception as e:
            print(f"Extraction failed: {e}")
            return None
