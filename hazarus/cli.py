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
from pathlib import Path as PathType

from hazarus.core import HazarusEngine, AssessmentConfig
from hazarus.security import ScopeManager, AuthorizationManager, AuditLogger
from hazarus.anonymity import AnonsurfManager

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

    async def _run_recon():
        from hazarus.reconnaissance.dns import DNSRecon
        from hazarus.reconnaissance.whois import WhoisRecon
        from hazarus.security import ScopeManager

        # Validate scope
        scope_manager = ScopeManager(str(scope_file))
        if not await scope_manager.load_scope():
            console.print("[red]✗ Failed to load scope file[/red]")
            raise typer.Exit(1)

        # Validate targets against scope
        valid_targets = []
        for target in targets:
            if await scope_manager.validate_target(target):
                valid_targets.append(target)
            else:
                console.print(f"[yellow]⚠ Target {target} not in authorized scope[/yellow]")

        if not valid_targets:
            console.print("[red]✗ No valid targets in scope[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓ Validated {len(valid_targets)} targets[/green]")

        # Run DNS reconnaissance
        dns_recon = DNSRecon()
        for target in valid_targets:
            console.print(f"Scanning {target}...")
            try:
                result = await dns_recon.enumerate(target)
                console.print(f"  A records: {result.get('a', [])}")
                console.print(f"  AAAA records: {result.get('aaaa', [])}")
                console.print(f"  MX records: {result.get('mx', [])}")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

        console.print("[green]✓ Reconnaissance complete[/green]")

    asyncio.run(_run_recon())


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

    async def _run_scan():
        from hazarus.scanning.nmap import NmapScanner
        from hazarus.security import ScopeManager

        # Validate scope
        scope_manager = ScopeManager(str(scope_file))
        if not await scope_manager.load_scope():
            console.print("[red]✗ Failed to load scope file[/red]")
            raise typer.Exit(1)

        # Validate targets
        valid_targets = []
        for target in targets:
            if await scope_manager.validate_target(target):
                valid_targets.append(target)
            else:
                console.print(f"[yellow]⚠ Target {target} not in authorized scope[/yellow]")

        if not valid_targets:
            console.print("[red]✗ No valid targets in scope[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓ Validated {len(valid_targets)} targets[/green]")

        # Run Nmap scan
        scanner = NmapScanner()
        for target in valid_targets:
            console.print(f"Scanning {target}...")
            try:
                result = await scanner.scan(target, ports=ports)
                console.print(f"  Ports found: {len(result.open_ports)}")
                console.print(f"  Open ports: {result.open_ports[:10]}")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

        console.print("[green]✓ Scan complete[/green]")

    asyncio.run(_run_scan())


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

    async def _run_web():
        from hazarus.scanning.http_scanner import HTTPScanner
        from hazarus.security import ScopeManager

        scope_manager = ScopeManager(str(scope_file))
        if not await scope_manager.load_scope():
            console.print("[red]✗ Failed to load scope file[/red]")
            raise typer.Exit(1)

        valid_targets = []
        for target in targets:
            if await scope_manager.validate_target(target):
                valid_targets.append(target)
            else:
                console.print(f"[yellow]⚠ Target {target} not in authorized scope[/yellow]")

        if not valid_targets:
            console.print("[red]✗ No valid targets in scope[/red]")
            raise typer.Exit(1)

        scanner = HTTPScanner()
        for target in valid_targets:
            console.print(f"Scanning {target}...")
            try:
                result = await scanner.scan(target)
                console.print(f"  Server: {result.get('server', 'N/A')}")
                console.print(f"  Headers: {len(result.get('headers', {}))}")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

        console.print("[green]✓ Web assessment complete[/green]")

    asyncio.run(_run_web())


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
    console.print("[yellow]API assessment feature - basic implementation[/yellow]")


@app.command()
def research(
    cve_id: Optional[str] = typer.Argument(None, help="CVE ID to research"),
    service: Optional[str] = typer.Option(None, "--service", help="Service name"),
    version: Optional[str] = typer.Option(None, "--version", help="Service version")
) -> None:
    """Research vulnerabilities and exploits."""
    console.print(Panel.fit("[bold blue]Vulnerability Research[/bold blue]"))

    async def _run_research():
        from hazarus.vulnerability.cve_matcher import CVEMatcher
        from hazarus.vulnerability.exploitdb import ExploitIntelligence

        if cve_id:
            console.print(f"Researching CVE: {cve_id}")
            matcher = CVEMatcher()
            try:
                result = await matcher.search_cve(cve_id)
                console.print(f"  Description: {result.get('description', 'N/A')}")
                console.print(f"  Severity: {result.get('severity', 'N/A')}")
                console.print(f"  CVSS Score: {result.get('cvss_score', 'N/A')}")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

        elif service and version:
            console.print(f"Researching: {service} {version}")
            exploit_intel = ExploitIntelligence()
            try:
                results = await exploit_intel.search_by_service(service, version)
                console.print(f"  Exploits found: {len(results)}")
                for result in results[:5]:
                    console.print(f"    - {result.title} (EDB-ID: {result.edb_id})")
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")
        else:
            console.print("[yellow]Please provide either a CVE ID or service/version[/yellow]")

    asyncio.run(_run_research())


@app.command()
def exploit_list() -> None:
    """List available exploits."""
    console.print(Panel.fit("[bold blue]Exploit Registry[/bold blue]"))

    async def _list_exploits():
        from hazarus.exploitation.exploit_registry import ExploitRegistry

        registry = ExploitRegistry()
        exploits = registry.list_all()

        table = Table(title="Available Exploits")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Category", style="yellow")
        table.add_column("Risk", style="red")

        for exploit in exploits[:20]:  # Show first 20
            table.add_row(
                exploit.exploit_id,
                exploit.name,
                exploit.category,
                exploit.risk_level
            )

        console.print(table)
        console.print(f"\nTotal exploits: {len(exploits)}")

    asyncio.run(_list_exploits())


@app.command()
def exploit_inspect(
    exploit_id: str = typer.Argument(..., help="Exploit ID to inspect")
) -> None:
    """Inspect exploit details."""
    console.print(Panel.fit("[bold blue]Exploit Inspection[/bold blue]"))
    console.print(f"Exploit ID: {exploit_id}")

    async def _inspect_exploit():
        from hazarus.exploitation.exploit_registry import ExploitRegistry

        registry = ExploitRegistry()
        exploit = registry.get(exploit_id)

        if not exploit:
            console.print(f"[red]✗ Exploit {exploit_id} not found[/red]")
            raise typer.Exit(1)

        table = Table(title="Exploit Details")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("ID", exploit.exploit_id)
        table.add_row("Name", exploit.name)
        table.add_row("Description", exploit.description)
        table.add_row("Author", exploit.author)
        table.add_row("Category", exploit.category)
        table.add_row("Risk Level", exploit.risk_level)
        table.add_row("Platform", ", ".join(exploit.platform))
        table.add_row("CVE", exploit.cve_id or "N/A")
        table.add_row("Requires Lab", "Yes" if exploit.requires_lab else "No")

        console.print(table)

    asyncio.run(_inspect_exploit())


@app.command()
def exploit_check(
    exploit_id: str = typer.Argument(..., help="Exploit ID to check"),
    target: str = typer.Argument(..., help="Target to check against")
) -> None:
    """Check exploit compatibility with target."""
    console.print(Panel.fit("[bold blue]Exploit Compatibility Check[/bold blue]"))
    console.print(f"Exploit: {exploit_id}")
    console.print(f"Target: {target}")
    console.print("[yellow]Exploit check feature - basic implementation[/yellow]")


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
    console.print("[yellow]Lab execution feature - requires lab configuration[/yellow]")


@app.command()
def post_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run post-exploitation security audit."""
    console.print(Panel.fit("[bold blue]Post-Exploitation Audit[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Post-assessment feature - basic implementation[/yellow]")


@app.command()
def lateral_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run lateral movement audit."""
    console.print(Panel.fit("[bold blue]Lateral Movement Audit[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Lateral movement audit feature - basic implementation[/yellow]")


@app.command()
def persistence_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run persistence mechanism audit."""
    console.print(Panel.fit("[bold blue]Persistence Audit[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Persistence audit feature - basic implementation[/yellow]")


@app.command()
def exfil_simulate(
    target: str = typer.Argument(..., help="Target to simulate against")
) -> None:
    """Run data exfiltration simulation."""
    console.print(Panel.fit("[bold blue]Data Exfiltration Simulation[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]Exfiltration simulation feature - basic implementation[/yellow]")


@app.command()
def code_analyze(
    path: Path = typer.Argument(..., help="Path to source code"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file")
) -> None:
    """Analyze source code for security issues."""
    console.print(Panel.fit("[bold blue]Source Code Analysis[/bold blue]"))
    console.print(f"Path: {path}")
    console.print("[yellow]Code analysis feature - basic implementation[/yellow]")


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

    async def _generate_report():
        from hazarus.reporting.report_engine import ReportEngine, ReportConfig

        engine = ReportEngine()

        # Mock assessment data for demonstration
        assessment_data = {
            "assessment_id": assessment_id,
            "target": "example.com",
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2025-01-01T01:00:00Z",
            "duration": "1 hour",
            "executive_summary": "Assessment completed successfully with no critical findings.",
            "findings": [
                {
                    "title": "SSL Certificate Expiring Soon",
                    "severity": "medium",
                    "description": "SSL certificate expires in 30 days"
                }
            ],
            "recommendations": [
                "Renew SSL certificate before expiration",
                "Implement HSTS header"
            ]
        }

        config = ReportConfig(
            assessment_id=assessment_id,
            format=format,
            output_path=str(output) if output else None
        )

        result = await engine.generate(config, assessment_data)

        if result["status"] == "completed":
            console.print(f"[green]✓ Report generated: {result['output_path']}[/green]")
        else:
            console.print(f"[red]✗ Report generation failed: {result.get('error', 'Unknown error')}[/red]")
            raise typer.Exit(1)

    asyncio.run(_generate_report())


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to")
) -> None:
    """Start the HAZARUS web dashboard."""
    console.print(Panel.fit("[bold blue]HAZARUS Dashboard[/bold blue]"))
    console.print(f"Host: {host}")
    console.print(f"Port: {port}")

    def _start_dashboard():
        import uvicorn
        from dashboard.backend.main import app

        console.print(f"[green]Starting dashboard on http://{host}:{port}[/green]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]")

        uvicorn.run(app, host=host, port=port)

    _start_dashboard()


@app.command()
def update() -> None:
    """Update HAZARUS and its dependencies."""
    console.print(Panel.fit("[bold blue]HAZARUS Update[/bold blue]"))
    console.print("Updating HAZARUS...")

    def _update():
        import subprocess
        import sys

        # Update Python dependencies
        console.print("Updating Python dependencies...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"], check=True)
            console.print("[green]✓ Python dependencies updated[/green]")
        except subprocess.CalledProcessError:
            console.print("[red]✗ Failed to update Python dependencies[/red]")
            raise typer.Exit(1)

        console.print("[green]✓ Update complete[/green]")

    _update()


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
