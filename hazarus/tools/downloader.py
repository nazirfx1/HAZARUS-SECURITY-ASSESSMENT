"""
HAZARUS GitHub Release Downloader
Downloads and extracts tool releases from GitHub.
"""

import asyncio
import httpx
import re
import os
import shutil
import zipfile
import tarfile
import time
import logging
import traceback
from typing import Optional, Callable, Type, Tuple, Set, Any
from pathlib import Path
from datetime import datetime


def setup_debug_logger() -> logging.Logger:
    """Setup debug logger for download operations.
    
    Returns:
        Configured logger instance
    """
    log_dir = Path.home() / ".hazarus" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / "installation_debug.log"
    
    logger = logging.getLogger("hazarus.downloader")
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler with detailed formatting
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


# Network errors that should trigger retry
RETRYABLE_NETWORK_ERRORS = (
    httpx.TimeoutException,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.ConnectError,
    httpx.RemoteProtocolError,
    httpx.NetworkError,
    ConnectionError,
    TimeoutError,
)

# HTTP status codes that should trigger retry
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

# HTTP status codes that should NOT trigger retry (permanent errors)
PERMANENT_ERROR_CODES = {400, 401, 403, 404, 410}


async def retry_with_backoff(
    func: Callable,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retryable_errors: Tuple[Type[Exception], ...] = RETRYABLE_NETWORK_ERRORS,
    debug: bool = False,
    **kwargs
) -> Any:
    """Execute function with exponential backoff retry logic.
    
    Args:
        func: Async function to execute
        *args: Positional arguments for func
        max_retries: Maximum number of retry attempts (default 3)
        base_delay: Base delay in seconds (default 1.0)
        max_delay: Maximum delay in seconds (default 60.0)
        retryable_errors: Tuple of exception types to retry on
        debug: Enable debug logging (default False)
        **kwargs: Keyword arguments for func
        
    Returns:
        Function result
        
    Raises:
        Last exception if all retries exhausted
    """
    debug_logger = setup_debug_logger() if debug else None
    last_exception = None
    
    if debug and debug_logger:
        debug_logger.info(f"Starting retry operation: {func.__name__}")
        debug_logger.info(f"Max retries: {max_retries}, Base delay: {base_delay}s")
    
    for attempt in range(max_retries + 1):
        try:
            if debug and debug_logger:
                debug_logger.info(f"Attempt {attempt + 1}/{max_retries + 1}")
            
            result = await func(*args, **kwargs)
            
            if debug and debug_logger:
                debug_logger.info(f"Attempt {attempt + 1} succeeded")
            
            return result
        except httpx.HTTPStatusError as e:
            # Check if status code is retryable
            if e.response.status_code in PERMANENT_ERROR_CODES:
                # Permanent error, don't retry
                if debug and debug_logger:
                    debug_logger.error(f"Permanent HTTP error: {e.response.status_code}")
                raise
            if e.response.status_code in RETRYABLE_STATUS_CODES:
                last_exception = e
                if attempt < max_retries:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    print(f"  Retry {attempt + 1}/{max_retries} after {delay:.1f}s (HTTP {e.response.status_code})")
                    
                    if debug and debug_logger:
                        debug_logger.warning(f"Attempt {attempt + 1} failed with HTTP {e.response.status_code}")
                        debug_logger.info(f"Retrying after {delay:.1f}s delay")
                    
                    await asyncio.sleep(delay)
                else:
                    if debug and debug_logger:
                        debug_logger.error(f"All {max_retries + 1} attempts failed with HTTP {e.response.status_code}")
                continue
            # Non-retryable status code
            if debug and debug_logger:
                debug_logger.error(f"Non-retryable HTTP status code: {e.response.status_code}")
            raise
        except retryable_errors as e:
            last_exception = e
            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt), max_delay)
                print(f"  Retry {attempt + 1}/{max_retries} after {delay:.1f}s ({type(e).__name__})")
                
                if debug and debug_logger:
                    debug_logger.warning(f"Attempt {attempt + 1} failed with {type(e).__name__}: {str(e)}")
                    debug_logger.info(f"Retrying after {delay:.1f}s delay")
                
                await asyncio.sleep(delay)
            else:
                if debug and debug_logger:
                    debug_logger.error(f"All {max_retries + 1} attempts failed with {type(e).__name__}: {str(e)}")
                    debug_logger.debug(traceback.format_exc())
            continue
        except Exception as e:
            # Non-retryable exception
            if debug and debug_logger:
                debug_logger.error(f"Non-retryable exception: {type(e).__name__}: {str(e)}")
                debug_logger.debug(traceback.format_exc())
            raise
    
    # All retries exhausted
    if last_exception:
        if debug and debug_logger:
            debug_logger.error("All retries exhausted, raising last exception")
        raise last_exception
    raise RuntimeError("All retries exhausted")


class DownloadProgress:
    """Track and report download progress."""
    
    def __init__(self, total_bytes: int):
        """Initialize progress tracker.
        
        Args:
            total_bytes: Total file size in bytes
        """
        self.total_bytes = total_bytes
        self.downloaded_bytes = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.last_bytes = 0
    
    def update(self, chunk_size: int) -> Optional[dict]:
        """Update progress with new chunk.
        
        Args:
            chunk_size: Size of downloaded chunk in bytes
            
        Returns:
            Progress dict with stats or None if no update needed
        """
        self.downloaded_bytes += chunk_size
        current_time = time.time()
        
        # Update every 0.5 seconds
        if current_time - self.last_update < 0.5:
            return None
        
        self.last_update = current_time
        time_elapsed = current_time - self.start_time
        
        # Calculate download speed
        bytes_since_last = self.downloaded_bytes - self.last_bytes
        time_since_last = current_time - (self.last_update if self.last_update != self.start_time else current_time - 0.5)
        speed = bytes_since_last / time_since_last if time_since_last > 0 else 0
        self.last_bytes = self.downloaded_bytes
        
        # Calculate percentage
        percentage = (self.downloaded_bytes / self.total_bytes) * 100 if self.total_bytes > 0 else 0
        
        # Calculate ETA
        if speed > 0:
            remaining_bytes = self.total_bytes - self.downloaded_bytes
            eta_seconds = remaining_bytes / speed
        else:
            eta_seconds = 0
        
        return {
            'downloaded': self.downloaded_bytes,
            'total': self.total_bytes,
            'percentage': percentage,
            'speed': speed,
            'eta': eta_seconds,
            'elapsed': time_elapsed
        }
    
    def format_progress(self, progress: dict) -> str:
        """Format progress dict for display.
        
        Args:
            progress: Progress dict from update()
            
        Returns:
            Formatted progress string
        """
        downloaded = self._format_bytes(progress['downloaded'])
        total = self._format_bytes(progress['total'])
        percentage = progress['percentage']
        speed = self._format_bytes(progress['speed']) + '/s'
        eta = self._format_time(progress['eta'])
        
        return f"  Downloaded: {downloaded}/{total} ({percentage:.1f}%) | Speed: {speed} | ETA: {eta}"
    
    @staticmethod
    def _format_bytes(bytes_val: float) -> str:
        """Format bytes to human-readable string.
        
        Args:
            bytes_val: Bytes value
            
        Returns:
            Formatted string (e.g., "1.5 MB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} PB"
    
    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format seconds to human-readable string.
        
        Args:
            seconds: Seconds value
            
        Returns:
            Formatted string (e.g., "2m 30s")
        """
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"


class GitHubDownloader:
    """Downloads and extracts tools from GitHub releases."""
    
    def __init__(self, debug: bool = False):
        """Initialize GitHub downloader.
        
        Args:
            debug: Enable debug logging (default False)
        """
        self.api_base = "https://api.github.com"
        self.download_dir = Path.home() / ".hazarus" / "downloads"
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.debug = debug
        self.debug_logger = setup_debug_logger() if debug else None
        
        if self.debug and self.debug_logger:
            self.debug_logger.info("=" * 80)
            self.debug_logger.info("GitHubDownloader initialized")
            self.debug_logger.info(f"Download directory: {self.download_dir}")
            self.debug_logger.info(f"Debug mode: {self.debug}")
            self.debug_logger.info("=" * 80)
    
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
        if self.debug and self.debug_logger:
            self.debug_logger.info(f"Starting download for repo: {repo}")
            self.debug_logger.info(f"Asset pattern: {asset_pattern}")
            self.debug_logger.info(f"Timeout: {timeout}s")
        
        try:
            # Get latest release info
            release_info = await self._get_latest_release(repo)
            if not release_info:
                if self.debug and self.debug_logger:
                    self.debug_logger.error("Failed to get latest release info")
                return None
            
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Release info retrieved: {release_info.get('tag_name', 'unknown')}")
            
            # Find matching asset
            asset_url = self._find_matching_asset(
                release_info.get('assets', []),
                asset_pattern
            )
            
            if not asset_url:
                if self.debug and self.debug_logger:
                    self.debug_logger.error(f"No asset found matching pattern: {asset_pattern}")
                return None
            
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Matching asset URL: {asset_url}")
            
            # Download asset with redirect following
            return await self._download_file(asset_url, timeout, follow_redirects=True)
            
        except Exception as e:
            print(f"GitHub download failed: {e}")
            if self.debug and self.debug_logger:
                self.debug_logger.error(f"GitHub download failed: {e}")
                self.debug_logger.debug(traceback.format_exc())
            return None
    
    async def _get_latest_release(self, repo: str) -> Optional[dict]:
        """Get latest release information from GitHub API.
        
        Args:
            repo: Repository in format "owner/repo"
            
        Returns:
            Release information dict or None
        """
        url = f"{self.api_base}/repos/{repo}/releases/latest"
        
        if self.debug and self.debug_logger:
            self.debug_logger.info(f"Fetching release info from: {url}")
        
        async def _fetch_release():
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(url)
                response.raise_for_status()
                return response.json()
        
        try:
            result = await retry_with_backoff(_fetch_release, max_retries=3, debug=self.debug)
            
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Successfully fetched release info")
            
            return result
        except httpx.HTTPStatusError as e:
            if e.response.status_code in PERMANENT_ERROR_CODES:
                print(f"  Permanent error fetching release info: HTTP {e.response.status_code}")
                if self.debug and self.debug_logger:
                    self.debug_logger.error(f"Permanent error fetching release info: HTTP {e.response.status_code}")
            return None
        except Exception as e:
            print(f"  Failed to fetch release info: {e}")
            if self.debug and self.debug_logger:
                self.debug_logger.error(f"Failed to fetch release info: {e}")
                self.debug_logger.debug(traceback.format_exc())
            return None
    
    def _find_matching_asset(self, assets: list, pattern: str) -> Optional[str]:
        """Find asset URL matching pattern.
        
        Args:
            assets: List of asset dicts from GitHub API
            pattern: Regex pattern to match
            
        Returns:
            Browser download URL or None
        """
        if self.debug and self.debug_logger:
            self.debug_logger.info(f"Searching for asset matching pattern: {pattern}")
            self.debug_logger.info(f"Available assets: {[a.get('name', 'unknown') for a in assets]}")
        
        for asset in assets:
            name = asset.get('name', '')
            if re.search(pattern, name):
                url = asset.get('browser_download_url')
                if self.debug and self.debug_logger:
                    self.debug_logger.info(f"Found matching asset: {name}")
                    self.debug_logger.info(f"Download URL: {url}")
                return url
        
        if self.debug and self.debug_logger:
            self.debug_logger.warning(f"No asset found matching pattern: {pattern}")
        
        return None
    
    async def _download_file(self, url: str, timeout: int, follow_redirects: bool = True) -> Optional[Path]:
        """Download file from URL with progress reporting and retry logic.
        
        Args:
            url: URL to download from
            timeout: Timeout in seconds
            follow_redirects: Whether to follow HTTP redirects
            
        Returns:
            Path to downloaded file or None
        """
        filename = url.split('/')[-1].split('?')[0]  # Handle URLs with query params
        filepath = self.download_dir / filename
        
        if self.debug and self.debug_logger:
            self.debug_logger.info(f"Starting download: {filename}")
            self.debug_logger.info(f"URL: {url}")
            self.debug_logger.info(f"Destination: {filepath}")
            self.debug_logger.info(f"Timeout: {timeout}s")
        
        async def _fetch_with_progress():
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Starting HTTP request to {url}")
            
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=follow_redirects) as client:
                async with client.stream('GET', url) as response:
                    response.raise_for_status()
                    
                    if self.debug and self.debug_logger:
                        self.debug_logger.info(f"HTTP response status: {response.status_code}")
                    
                    # Get total file size for progress tracking
                    total_bytes = int(response.headers.get('content-length', 0))
                    
                    if self.debug and self.debug_logger:
                        self.debug_logger.info(f"Total file size: {total_bytes} bytes")
                    
                    # Initialize progress tracker
                    progress = DownloadProgress(total_bytes)
                    
                    # Show progress for large files (> 1MB)
                    show_progress = total_bytes > 1024 * 1024
                    
                    if self.debug and self.debug_logger:
                        self.debug_logger.info(f"Writing to file: {filepath}")
                    
                    with open(filepath, 'wb') as f:
                        bytes_downloaded = 0
                        async for chunk in response.aiter_bytes():
                            f.write(chunk)
                            bytes_downloaded += len(chunk)
                            
                            if show_progress:
                                chunk_size = len(chunk)
                                progress_data = progress.update(chunk_size)
                                if progress_data:
                                    # Print progress with carriage return to overwrite line
                                    print(f"\r{progress.format_progress(progress_data)}", end='', flush=True)
                    
                    if show_progress:
                        print()  # New line after progress
                    
                    if self.debug and self.debug_logger:
                        self.debug_logger.info(f"Download complete: {bytes_downloaded} bytes")
            
            return filepath
        
        try:
            result = await retry_with_backoff(_fetch_with_progress, max_retries=3, debug=self.debug)
            print(f"  Download complete: {filename}")
            
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Download successful: {result}")
            
            return result
        except httpx.HTTPStatusError as e:
            if e.response.status_code in PERMANENT_ERROR_CODES:
                print(f"  Permanent download error: HTTP {e.response.status_code}")
                if self.debug and self.debug_logger:
                    self.debug_logger.error(f"Permanent download error: HTTP {e.response.status_code}")
            else:
                print(f"  Download failed after retries: HTTP {e.response.status_code}")
                if self.debug and self.debug_logger:
                    self.debug_logger.error(f"Download failed after retries: HTTP {e.response.status_code}")
            return None
        except Exception as e:
            print(f"  Download failed after retries: {e}")
            if self.debug and self.debug_logger:
                self.debug_logger.error(f"Download failed after retries: {e}")
                self.debug_logger.debug(traceback.format_exc())
            return None
    
    async def extract_archive(self, archive_path: Path) -> Optional[Path]:
        """Extract archive to temporary directory.
        
        Args:
            archive_path: Path to archive file
            
        Returns:
            Path to extracted directory or None
        """
        if self.debug and self.debug_logger:
            self.debug_logger.info(f"Starting extraction: {archive_path}")
            self.debug_logger.info(f"Archive suffix: {archive_path.suffix}")
        
        try:
            extract_dir = self.download_dir / f"{archive_path.stem}_extracted"
            extract_dir.mkdir(exist_ok=True)
            
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Extract directory: {extract_dir}")
            
            if archive_path.suffix == '.zip':
                if self.debug and self.debug_logger:
                    self.debug_logger.info("Extracting ZIP archive")
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                if self.debug and self.debug_logger:
                    self.debug_logger.info(f"ZIP extraction complete. Files extracted: {len(list(extract_dir.iterdir()))}")
            elif archive_path.suffix in ['.tar', '.gz', '.tgz', '.bz2']:
                if self.debug and self.debug_logger:
                    self.debug_logger.info("Extracting TAR archive")
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
                if self.debug and self.debug_logger:
                    self.debug_logger.info(f"TAR extraction complete. Files extracted: {len(list(extract_dir.iterdir()))}")
            else:
                if self.debug and self.debug_logger:
                    self.debug_logger.error(f"Unsupported archive format: {archive_path.suffix}")
                return None
            
            # Find the actual extracted directory (might be nested)
            extracted_files = list(extract_dir.iterdir())
            if not extracted_files:
                # Check for single nested directory
                if self.debug and self.debug_logger:
                    self.debug_logger.warning("Extract directory is empty, checking for nested directory")
                for item in self.download_dir.iterdir():
                    if item.is_dir() and item.name.startswith(archive_path.stem):
                        if self.debug and self.debug_logger:
                            self.debug_logger.info(f"Found nested directory: {item}")
                        shutil.rmtree(extract_dir)
                        return item
            
            if self.debug and self.debug_logger:
                self.debug_logger.info(f"Extraction successful: {extract_dir}")
                self.debug_logger.info(f"Files extracted: {len(extracted_files)}")
            
            return extract_dir
            
        except Exception as e:
            print(f"Extraction failed: {e}")
            if self.debug and self.debug_logger:
                self.debug_logger.error(f"Extraction failed: {e}")
                self.debug_logger.debug(traceback.format_exc())
            return None
