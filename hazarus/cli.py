"""
HAZARUS CLI (Interactive Mode Only)
Entry point for the HAZARUS Security Assessment Framework.
"""

import asyncio
import typer
from rich.console import Console

app = typer.Typer(
    name="hazarus",
    help="HAZARUS Security Assessment Framework - Interactive Mode Only",
    add_completion=False,
)
console = Console()


@app.callback()
def main():
    """HAZARUS Security Assessment Framework - Interactive Mode Only."""
    pass


@app.command()
def start():
    """Launch HAZARUS interactive mode (DEFAULT)."""
    from hazarus.interactive import InteractiveMode
    
    console.print("[green]Launching HAZARUS Interactive Mode...[/green]\n")
    
    interactive = InteractiveMode()
    asyncio.run(interactive.run())


def main_entry():
    """Main entry point."""
    start()


if __name__ == "__main__":
    main_entry()
