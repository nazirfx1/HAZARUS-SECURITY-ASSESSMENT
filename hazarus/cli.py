"""
HAZARUS CLI
Command-line interface for the HAZARUS Security Assessment Framework.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

try:
    from core import HazarusEngine, AssessmentConfig
    from security import ScopeManager, AuthorizationManager, AuditLogger
    from anonymity import AnonsurfManager
except ImportError:
    from ..core import HazarusEngine, AssessmentConfig
    from ..security import ScopeManager, AuthorizationManager, AuditLogger
    from ..anonymity import AnonsurfManager

app = typer.Typer(
    name="hazarus",
    help="HAZARUS Security Assessment Framework - Professional-grade modular security assessment platform",
    add_completion=False,
)
console = Console()


@app.command()
def init(
    output_dir: Path = typer.Option(
        Path.cwd(),
        "--output-dir",
        "-o",
        help="Output directory for configuration files"
    )
) -> None:
    """Initialize a new HAZARUS assessment project."""
    console.print(Panel.fit("[bold blue]HAZARUS Initialization[/bold blue]"))

    # Create directories
    dirs = [
        output_dir / "config",
        output_dir / "reports",
        output_dir / "evidence",
        output_dir / "logs"
    ]

    for dir_path in dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
        console.print(f"✓ Created directory: {dir_path}")

    # Create scope template
    scope_manager = ScopeManager(str(output_dir / "config" / "scope.yaml"))
    scope_manager.create_scope_template(output_dir / "config" / "scope.yaml")

    console.print(f"✓ Created scope template: {output_dir / 'config' / 'scope.yaml'}")

    # Create default config
    config_content = """# HAZARUS Configuration
assessment:
  intensity: normal
  privacy_mode: strict
  max_threads: 10
  timeout: 300

logging:
  level: INFO
  file: logs/hazarus.log

privacy:
  require_anonsurf: true
  block_on_dns_leak: true
  block_on_ipv6_exposure: true
"""

    config_file = output_dir / "config" / "hazarus.yaml"
    config_file.write_text(config_content)
    console.print(f"✓ Created configuration: {config_file}")

    console.print(Panel.fit("[green]Initialization complete![/green]"))
    console.print("\nNext steps:")
    console.print("1. Edit config/scope.yaml to define your assessment scope")
    console.print("2. Run 'hazarus scope validate' to verify your scope")
    console.print("3. Run 'hazarus privacy check' to verify anonymity")
    console.print("4. Run 'hazarus recon' to start reconnaissance")


@app.command()
def scope_validate(
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    )
) -> None:
    """Validate scope configuration."""
    console.print(Panel.fit("[bold blue]Scope Validation[/bold blue]"))

    async def _validate():
        scope_manager = ScopeManager(str(scope_file))

        if not await scope_manager.load_scope():
            console.print("[red]✗ Failed to load scope file[/red]")
            sys.exit(1)

        summary = scope_manager.get_scope_summary()

        table = Table(title="Scope Summary")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        for key, value in summary.items():
            table.add_row(key, str(value))

        console.print(table)

        if summary:
            console.print("[green]✓ Scope configuration is valid[/green]")
        else:
            console.print("[yellow]⚠ Scope is empty[/yellow]")

    asyncio.run(_validate())


@app.command()
def privacy_check() -> None:
    """Check privacy and anonymity configuration."""
    console.print(Panel.fit("[bold blue]Privacy Check[/bold blue]"))

    async def _check():
        anonsurf = AnonsurfManager()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Checking privacy configuration...", total=None)

            installed = await anonsurf.check_installed()
            progress.update(task, description="Checking Anonsurf status...")

            running = await anonsurf.check_running()
            progress.update(task, description="Checking Tor connectivity...")

            tor_available = await anonsurf.check_tor_connectivity()
            progress.update(task, description="Checking for DNS leaks...")

            dns_leak = await anonsurf.check_dns_leak()
            progress.update(task, description="Checking IPv6 exposure...")

            ipv6_exposed = await anonsurf.check_ipv6_exposure()

        table = Table(title="Privacy Status")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="green")

        table.add_row("Anonsurf Installed", "✓" if installed else "✗")
        table.add_row("Anonsurf Running", "✓" if running else "✗")
        table.add_row("Tor Available", "✓" if tor_available else "✗")
        table.add_row("DNS Leak Detected", "✗" if not dns_leak else "⚠")
        table.add_row("IPv6 Exposed", "✗" if not ipv6_exposed else "⚠")

        console.print(table)

        # Overall status
        if running and tor_available and not dns_leak and not ipv6_exposed:
            console.print("[green]✓ Privacy configuration is optimal[/green]")
        elif running and tor_available:
            console.print("[yellow]⚠ Privacy configuration has warnings[/yellow]")
        else:
            console.print("[red]✗ Privacy configuration is not secure[/red]")

    asyncio.run(_check())


@app.command()
def recon(
    targets: list[str] = typer.Argument(..., help="Target domains or IP addresses"),
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for results"
    )
) -> None:
    """Run reconnaissance on targets."""
    console.print(Panel.fit("[bold blue]Reconnaissance[/bold blue]"))
    console.print(f"Targets: {', '.join(targets)}")
    console.print("[yellow]Reconnaissance module to be implemented in Stage 4[/yellow]")


@app.command()
def scan(
    targets: list[str] = typer.Argument(..., help="Target IP addresses or ranges"),
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    ),
    ports: str = typer.Option(
        "1-1000",
        "--ports",
        "-p",
        help="Port range to scan (e.g., 1-1000, 22,80,443)"
    )
) -> None:
    """Run network scan on targets."""
    console.print(Panel.fit("[bold blue]Network Scanning[/bold blue]"))
    console.print(f"Targets: {', '.join(targets)}")
    console.print(f"Ports: {ports}")
    console.print("[yellow]Scanning module to be implemented in Stage 4[/yellow]")


@app.command()
def web(
    targets: list[str] = typer.Argument(..., help="Target URLs or domains"),
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    )
) -> None:
    """Run web application security assessment."""
    console.print(Panel.fit("[bold blue]Web Assessment[/bold blue]"))
    console.print(f"Targets: {', '.join(targets)}")
    console.print("[yellow]Web assessment module to be implemented in Stage 5[/yellow]")


@app.command()
def api(
    targets: list[str] = typer.Argument(..., help="Target API endpoints"),
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    )
) -> None:
    """Run API security assessment."""
    console.print(Panel.fit("[bold blue]API Security Assessment[/bold blue]"))
    console.print(f"Targets: {', '.join(targets)}")
    console.print("[yellow]API assessment module to be implemented in Stage 5[/yellow]")


@app.command()
def research(
    cve_id: Optional[str] = typer.Argument(None, help="CVE ID to research"),
    service: Optional[str] = typer.Option(None, "--service", help="Service name"),
    version: Optional[str] = typer.Option(None, "--version", help="Service version")
) -> None:
    """Research vulnerabilities and exploits."""
    console.print(Panel.fit("[bold blue]Vulnerability Research[/bold blue]"))

    if cve_id:
        console.print(f"CVE: {cve_id}")
    elif service and version:
        console.print(f"Service: {service} {version}")
    else:
        console.print("[yellow]Vulnerability research module to be implemented in Stage 6[/yellow]")


@app.command()
def exploit_list() -> None:
    """List available exploits."""
    console.print(Panel.fit("[bold blue]Exploit Registry[/bold blue]"))
    console.print("[yellow]Exploit module to be implemented in Stage 7[/yellow]")


@app.command()
def exploit_inspect(
    exploit_id: str = typer.Argument(..., help="Exploit ID to inspect")
) -> None:
    """Inspect exploit details."""
    console.print(Panel.fit("[bold blue]Exploit Inspection[/bold blue]"))
    console.print(f"Exploit ID: {exploit_id}")
    console.print("[yellow]Exploit inspection to be implemented in Stage 7[/yellow]")


@app.command()
def exploit_check(
    exploit_id: str = typer.Argument(..., help="Exploit ID to check"),
    target: str = typer.Argument(..., help="Target to check against")
) -> None:
    """Check exploit compatibility with target."""
    console.print(Panel.fit("[bold blue]Exploit Compatibility Check[/bold blue]"))
    console.print(f"Exploit: {exploit_id}")
    console.print(f"Target: {target}")
    console.print("[yellow]Exploit check to be implemented in Stage 7[/yellow]")


@app.command()
def exploit_lab(
    exploit_id: str = typer.Argument(..., help="Exploit ID to execute"),
    target: str = typer.Argument(..., help="Lab target"),
    timeout: int = typer.Option(300, "--timeout", "-t", help="Execution timeout in seconds")
) -> None:
    """Execute exploit in isolated lab environment."""
    console.print(Panel.fit("[bold blue]Lab Exploit Execution[/bold blue]"))
    console.print(f"Exploit: {exploit_id}")
    console.print(f"Target: {target}")
    console.print(f"Timeout: {timeout}s")
    console.print("[yellow]Lab execution to be implemented in Stage 8[/yellow]")


@app.command()
def post_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run post-exploitation security audit."""
    console.print(Panel.fit("[bold blue]Post-Exploitation Audit[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Post-assessment module to be implemented in Stage 9[/yellow]")


@app.command()
def lateral_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run lateral movement audit."""
    console.print(Panel.fit("[bold blue]Lateral Movement Audit[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Lateral movement audit to be implemented in Stage 9[/yellow]")


@app.command()
def persistence_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run persistence mechanism audit."""
    console.print(Panel.fit("[bold blue]Persistence Audit[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Persistence audit to be implemented in Stage 9[/yellow]")


@app.command()
def exfil_simulate(
    target: str = typer.Argument(..., help="Target to simulate against")
) -> None:
    """Run data exfiltration simulation."""
    console.print(Panel.fit("[bold blue]Data Exfiltration Simulation[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Exfiltration simulation to be implemented in Stage 9[/yellow]")


@app.command()
def code_analyze(
    path: Path = typer.Argument(..., help="Path to source code"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file")
) -> None:
    """Analyze source code for security issues."""
    console.print(Panel.fit("[bold blue]Source Code Analysis[/bold blue]"))
    console.print(f"Path: {path}")
    console.print("[yellow]Code analysis module to be implemented in Stage 10[/yellow]")


@app.command()
def report(
    assessment_id: str = typer.Argument(..., help="Assessment ID"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html, pdf, json, markdown)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file")
) -> None:
    """Generate assessment report."""
    console.print(Panel.fit("[bold blue]Report Generation[/bold blue]"))
    console.print(f"Assessment ID: {assessment_id}")
    console.print(f"Format: {format}")
    console.print("[yellow]Report generation to be implemented in Stage 11[/yellow]")


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to")
) -> None:
    """Start the HAZARUS web dashboard."""
    console.print(Panel.fit("[bold blue]HAZARUS Dashboard[/bold blue]"))
    console.print(f"Host: {host}")
    console.print(f"Port: {port}")
    console.print("[yellow]Dashboard to be implemented in Stage 11[/yellow]")


@app.command()
def update() -> None:
    """Update HAZARUS and its dependencies."""
    console.print(Panel.fit("[bold blue]HAZARUS Update[/bold blue]"))
    console.print("[yellow]Update functionality to be implemented in Stage 12[/yellow]")


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
