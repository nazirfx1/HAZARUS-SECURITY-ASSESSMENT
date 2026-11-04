#!/usr/bin/env python3
"""
Demonstration of enhanced tool detection capabilities.
Shows the improvements made for Parrot OS tool detection.
"""

import asyncio
from hazarus.tools.detector import ToolDetector, ALTERNATIVE_COMMANDS, GUI_TOOLS


def show_alternative_commands():
    """Display the alternative command names mapping."""
    print("=" * 80)
    print("ALTERNATIVE COMMAND NAMES MAPPING")
    print("=" * 80)
    print(f"\nTotal tools with alternative commands: {len(ALTERNATIVE_COMMANDS)}\n")
    
    for tool, alts in sorted(ALTERNATIVE_COMMANDS.items()):
        print(f"{tool:20} -> {', '.join(alts)}")


def show_gui_tools():
    """Display the GUI tools mapping."""
    print("\n" + "=" * 80)
    print("GUI TOOLS (detected via package manager)")
    print("=" * 80)
    print(f"\nTotal GUI tools: {len(GUI_TOOLS)}\n")
    
    for tool, package in sorted(GUI_TOOLS.items()):
        print(f"{tool:20} -> package: {package}")


async def demo_detection():
    """Demonstrate tool detection on a few common tools."""
    print("\n" + "=" * 80)
    print("DEMONSTRATING TOOL DETECTION")
    print("=" * 80)
    
    detector = ToolDetector(debug=False)
    
    # Test a few tools
    test_tools = ["nmap", "python3", "zap", "burp"]
    
    print("\nChecking common tools...\n")
    for tool_name in test_tools:
        status = await detector.check_tool(tool_name)
        
        if status.installed:
            print(f"[+] {tool_name:15} INSTALLED")
            print(f"  Version: {status.version or 'Unknown'}")
            print(f"  Path: {status.path}")
            print(f"  Detected via: {status.detection_command}")
        else:
            print(f"[-] {tool_name:15} NOT INSTALLED")
            print(f"  Reason: {status.compatible_reason}")
        print()


def main():
    """Run the demonstration."""
    print("\n" + "=" * 80)
    print("HAZARUS TOOL DETECTION IMPROVEMENTS DEMONSTRATION")
    print("=" * 80)
    
    # Show alternative commands
    show_alternative_commands()
    
    # Show GUI tools
    show_gui_tools()
    
    # Demonstrate detection
    asyncio.run(demo_detection())
    
    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE")
    print("=" * 80)
    print("\nKey Improvements:")
    print("  1. Alternative command names for 42+ tools")
    print("  2. GUI tool detection via package manager")
    print("  3. System path searching")
    print("  4. Debug logging for troubleshooting")
    print("  5. Proper fallback command support")
    print("\nSee TOOL_DETECTION_IMPROVEMENTS.md for details.")
    print()


if __name__ == "__main__":
    main()
