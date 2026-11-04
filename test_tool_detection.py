#!/usr/bin/env python3
"""
Test script for tool detection improvements.
Tests the enhanced detector with alternative commands and system path searching.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from hazarus.tools.detector import ToolDetector
from hazarus.tools.registry import ToolRegistry


async def test_tool_detection():
    """Test tool detection with debug logging enabled."""
    print("=" * 80)
    print("Testing Enhanced Tool Detection")
    print("=" * 80)
    
    # Initialize detector with debug mode
    registry = ToolRegistry()
    detector = ToolDetector(registry=registry, debug=True)
    
    # Test specific tools that are commonly pre-installed in Parrot OS
    test_tools = [
        "nmap",
        "nikto",
        "masscan",
        "sqlmap",
        "hydra",
        "whois",
        "theharvester",
        "whatweb",
        "wpscan",
        "metasploit",
        "aircrack",
        "wireshark",
        "hashcat",
        "john",
        "gobuster",
        "zap",
        "burp",
    ]
    
    print("\nChecking tools...")
    print("-" * 80)
    
    results = {}
    for tool_name in test_tools:
        print(f"\nChecking: {tool_name}")
        status = await detector.check_tool(tool_name)
        results[tool_name] = status
        
        if status.installed:
            print(f"  ✓ INSTALLED")
            print(f"    Version: {status.version or 'Unknown'}")
            print(f"    Path: {status.path}")
            print(f"    Detection Command: {status.detection_command}")
            print(f"    Compatible: {status.compatible}")
            if status.compatible_reason:
                print(f"    Reason: {status.compatible_reason}")
        else:
            print(f"  ✗ NOT INSTALLED")
            print(f"    Reason: {status.compatible_reason}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    installed_count = sum(1 for s in results.values() if s.installed)
    total_count = len(results)
    print(f"Installed: {installed_count}/{total_count}")
    
    print("\nInstalled Tools:")
    for tool_name, status in results.items():
        if status.installed:
            print(f"  - {tool_name}: {status.version or 'Unknown version'}")
    
    print("\nMissing Tools:")
    for tool_name, status in results.items():
        if not status.installed:
            print(f"  - {tool_name}")
    
    return results


async def test_alternative_commands():
    """Test the alternative command mapping."""
    print("\n" + "=" * 80)
    print("Testing Alternative Command Mapping")
    print("=" * 80)
    
    from hazarus.tools.detector import ALTERNATIVE_COMMANDS
    
    print("\nAlternative Commands Mapping:")
    for tool, alts in sorted(ALTERNATIVE_COMMANDS.items()):
        print(f"  {tool}: {', '.join(alts)}")


async def test_gui_tool_detection():
    """Test GUI tool detection via package manager."""
    print("\n" + "=" * 80)
    print("Testing GUI Tool Detection")
    print("=" * 80)
    
    detector = ToolDetector(debug=True)
    
    gui_tools = ["burp", "zap", "wireshark", "ghidra"]
    
    for tool_name in gui_tools:
        print(f"\nChecking GUI tool: {tool_name}")
        status = await detector.check_tool(tool_name)
        
        if status.installed:
            print(f"  ✓ INSTALLED")
            print(f"    Path: {status.path}")
            print(f"    Detection Command: {status.detection_command}")
        else:
            print(f"  ✗ NOT INSTALLED")


async def test_system_path_search():
    """Test system path searching."""
    print("\n" + "=" * 80)
    print("Testing System Path Search")
    print("=" * 80)
    
    detector = ToolDetector(debug=True)
    
    # Try to find a common tool
    test_commands = ["python3", "bash", "ls"]
    
    for cmd in test_commands:
        print(f"\nSearching for: {cmd}")
        path = await detector._search_in_system_paths(cmd)
        if path:
            print(f"  ✓ Found at: {path}")
        else:
            print(f"  ✗ Not found in system paths")


async def main():
    """Run all tests."""
    try:
        # Test tool detection
        await test_tool_detection()
        
        # Test alternative commands
        await test_alternative_commands()
        
        # Test GUI tool detection
        await test_gui_tool_detection()
        
        # Test system path search
        await test_system_path_search()
        
        print("\n" + "=" * 80)
        print("All tests completed!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
