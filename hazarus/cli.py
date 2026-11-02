"""
HAZARUS CLI
Command-line interface for the HAZARUS Security Assessment Framework.
"""

import asyncio
import sys
import os
import subprocess
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint
from pathlib import Path as PathType

from core import HazarusEngine, AssessmentConfig
from security import ScopeManager, AuthorizationManager, AuditLogger
from anonymity import AnonsurfManager

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
    console.print("   Or use: hazarus scope add-target <domain>")
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

        console.print("[green]✓ Scope configuration is valid[/green]")

    asyncio.run(_validate())


@app.command()
def scope_edit(
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    )
) -> None:
    """Edit scope configuration in default editor."""
    console.print(Panel.fit("[bold blue]Scope Edit[/bold blue]"))
    
    if not scope_file.exists():
        console.print(f"[yellow]Scope file {scope_file} does not exist. Creating template...[/yellow]")
        scope_manager = ScopeManager(str(scope_file))
        scope_manager.create_scope_template(scope_file)
    
    console.print(f"Opening {scope_file} in your default editor...")
    
    # Use EDITOR environment variable or default to nano
    editor = os.environ.get("EDITOR", "nano")
    
    try:
        subprocess.run([editor, str(scope_file)], check=True)
        console.print("[green]✓ Scope file saved[/green]")
        console.print("\nRun 'hazarus scope validate' to verify your changes")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ Editor failed: {e}[/red]")
    except FileNotFoundError:
        console.print(f"[yellow]Editor '{editor}' not found. Trying nano...[/yellow]")
        try:
            subprocess.run(["nano", str(scope_file)], check=True)
            console.print("[green]✓ Scope file saved[/green]")
        except:
            console.print("[red]✗ Could not open editor. Please edit the file manually:[/red]")
            console.print(f"  {scope_file}")


@app.command()
def scope_add_target(
    target: str = typer.Argument(..., help="Target to add (domain, IP, or URL)"),
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    )
) -> None:
    """Add a target to the scope configuration."""
    console.print(Panel.fit("[bold blue]Add Target to Scope[/bold blue]"))
    
    # Load existing scope
    import yaml
    if scope_file.exists():
        with open(scope_file, "r") as f:
            scope_data = yaml.safe_load(f) or {}
    else:
        scope_data = {}
        console.print(f"[yellow]Creating new scope file at {scope_file}[/yellow]")
    
    # Initialize lists if they don't exist
    if "allowed_targets" not in scope_data:
        scope_data["allowed_targets"] = []
    if "allowed_domains" not in scope_data:
        scope_data["allowed_domains"] = []
    
    # Determine target type and add to appropriate list
    target_lower = target.lower()
    
    if target_lower.startswith(("http://", "https://")):
        # URL - add to allowed_targets
        if target not in scope_data["allowed_targets"]:
            scope_data["allowed_targets"].append(target)
            console.print(f"[green]✓ Added URL to allowed_targets: {target}[/green]")
        else:
            console.print(f"[yellow]⚠ Target already in scope: {target}[/yellow]")
    elif "/" in target:
        # CIDR - add to allowed_targets
        if "allowed_cidrs" not in scope_data:
            scope_data["allowed_cidrs"] = []
        if target not in scope_data["allowed_cidrs"]:
            scope_data["allowed_cidrs"].append(target)
            console.print(f"[green]✓ Added CIDR to allowed_cidrs: {target}[/green]")
        else:
            console.print(f"[yellow]⚠ CIDR already in scope: {target}[/yellow]")
    else:
        # Domain or IP - add to both
        if target not in scope_data["allowed_targets"]:
            scope_data["allowed_targets"].append(target)
            console.print(f"[green]✓ Added to allowed_targets: {target}[/green]")
        
        # If it looks like a domain (not an IP), add to allowed_domains
        if not target.replace(".", "").isdigit():
            if target not in scope_data["allowed_domains"]:
                scope_data["allowed_domains"].append(target)
                console.print(f"[green]✓ Added to allowed_domains: {target}[/green]")
    
    # Save the updated scope
    with open(scope_file, "w") as f:
        yaml.dump(scope_data, f, default_flow_style=False, sort_keys=False)
    
    console.print(f"\nScope file updated: {scope_file}")
    console.print("Run 'hazarus scope validate' to verify")


@app.command()
def scope_list(
    scope_file: Path = typer.Option(
        "config/scope.yaml",
        "--scope-file",
        "-s",
        help="Path to scope configuration file"
    )
) -> None:
    """List all targets in the scope configuration."""
    console.print(Panel.fit("[bold blue]Scope Targets[/bold blue]"))
    
    import yaml
    if not scope_file.exists():
        console.print(f"[red]✗ Scope file not found: {scope_file}[/red]")
        console.print("Run 'hazarus init' to create a scope file")
        return
    
    with open(scope_file, "r") as f:
        scope_data = yaml.safe_load(f) or {}
    
    # Display targets
    if scope_data.get("allowed_targets"):
        console.print("\n[bold]Allowed Targets:[/bold]")
        for target in scope_data["allowed_targets"]:
            console.print(f"  • {target}")
    
    if scope_data.get("allowed_domains"):
        console.print("\n[bold]Allowed Domains:[/bold]")
        for domain in scope_data["allowed_domains"]:
            console.print(f"  • {domain}")
    
    if scope_data.get("allowed_cidrs"):
        console.print("\n[bold]Allowed CIDRs:[/bold]")
        for cidr in scope_data["allowed_cidrs"]:
            console.print(f"  • {cidr}")
    
    if scope_data.get("excluded_targets"):
        console.print("\n[bold]Excluded Targets:[/bold]")
        for target in scope_data["excluded_targets"]:
            console.print(f"  • {target}")
    
    if scope_data.get("allowed_ports"):
        console.print("\n[bold]Allowed Ports:[/bold]")
        for port in scope_data["allowed_ports"]:
            console.print(f"  • {port}")

    # Check if scope has any targets
    has_targets = any([
        scope_data.get("allowed_targets"),
        scope_data.get("allowed_domains"),
        scope_data.get("allowed_cidrs")
    ])

    if has_targets:
        console.print("\n[green]✓ Scope configuration is valid[/green]")
    else:
        console.print("\n[yellow]⚠ Scope is empty[/yellow]")


@app.command()
def privacy_check() -> None:
    """Check privacy and anonymity configuration."""
    console.print(Panel.fit("[bold blue]Privacy Check[/bold blue]"))

    async def _check():
        from anonymity.anonsurf import AnonsurfManager
        from anonymity.dns_leak import DNSLeakChecker
        from anonymity.ipv6_check import IPv6Checker

        anonsurf = AnonsurfManager()
        dns_checker = DNSLeakChecker()
        ipv6_checker = IPv6Checker()

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

            dns_result = await dns_checker.check_leaks()
            dns_leak = dns_result.get("leaking", False)
            progress.update(task, description="Checking IPv6 exposure...")

            ipv6_enabled = await ipv6_checker.check_ipv6_enabled()
            ipv6_exposed = ipv6_enabled

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
        from reconnaissance.dns import DNSRecon
        from reconnaissance.whois import WhoisRecon
        from security import ScopeManager

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

        # Run comprehensive reconnaissance
        from reconnaissance.dns import DNSRecon
        from reconnaissance.subdomains import SubdomainDiscovery
        from reconnaissance.whois import WhoisRecon
        from scanning.nmap import NmapScanner
        
        for target in valid_targets:
            console.print(f"\n[bold]Scanning {target}...[/bold]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("DNS enumeration...", total=None)
                
                dns_recon = DNSRecon()
                try:
                    result = await dns_recon.enumerate_records(target)
                    progress.update(task, description="DNS enumeration complete")
                    
                    # Display DNS results
                    console.print(f"\n  [cyan]DNS Records:[/cyan]")
                    if result.records:
                        for record in result.records[:10]:  # Show first 10
                            console.print(f"    {record.record_type}: {record.value}")
                    
                    if result.nameservers:
                        console.print(f"\n  [cyan]Nameservers:[/cyan]")
                        for ns in result.nameservers:
                            console.print(f"    • {ns}")
                    
                    if result.mx_records:
                        console.print(f"\n  [cyan]MX Records:[/cyan]")
                        for mx in result.mx_records:
                            console.print(f"    • {mx.get('exchange', 'N/A')}")
                    
                    if result.spf_record:
                        console.print(f"\n  [cyan]SPF Record:[/cyan]")
                        console.print(f"    {result.spf_record}")
                    
                    if result.dmarc_record:
                        console.print(f"\n  [cyan]DMARC Record:[/cyan]")
                        console.print(f"    {result.dmarc_record}")
                    
                    if result.txt_records:
                        console.print(f"\n  [cyan]TXT Records:[/cyan]")
                        for txt in result.txt_records[:5]:
                            console.print(f"    • {txt}")
                    
                    # Subdomain enumeration with advanced tools
                    progress.update(task, description="Checking tool availability...")
                    
                    # Check Amass availability (Linux/Parrot OS)
                    amass_available = False
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "command", "-v", "amass",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await proc.communicate()
                        amass_available = proc.returncode == 0
                    except:
                        try:
                            # Fallback to which on some systems
                            proc = await asyncio.create_subprocess_exec(
                                "which", "amass",
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            await proc.communicate()
                            amass_available = proc.returncode == 0
                        except:
                            pass
                    
                    # Amass enumeration with advanced OSINT capabilities
                    progress.update(task, description="Amass comprehensive enumeration...")
                    amass_available = False
                    try:
                        # Use 'which' for Linux/Parrot OS compatibility
                        proc = await asyncio.create_subprocess_exec(
                            "which", "amass",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        await proc.communicate()
                        amass_available = proc.returncode == 0
                    except:
                        pass
                    
                    amass_result = {}
                    amass_subdomains = []
                    if amass_available:
                        try:
                            amass_result = await dns_recon.query_amass_advanced(target)
                            amass_subdomains = amass_result.get("subdomains", [])
                            
                            if amass_subdomains:
                                console.print(f"    [green]✓ Amass: {len(amass_subdomains)} subdomains[/green]")
                            else:
                                console.print(f"    [yellow]⚠ Amass: No subdomains found[/yellow]")
                            
                            # Display ASN information
                            if amass_result.get("asn_info"):
                                console.print(f"\n  [cyan]ASN Information:[/cyan]")
                                for asn in amass_result["asn_info"][:5]:
                                    console.print(f"    • {asn}")
                            
                            # Display certificates
                            if amass_result.get("certificates"):
                                console.print(f"\n  [cyan]Certificates:[/cyan]")
                                for cert in amass_result["certificates"][:5]:
                                    console.print(f"    • {cert}")
                            
                            # Display related domains
                            if amass_result.get("related_domains"):
                                console.print(f"\n  [cyan]Related Domains:[/cyan]")
                                for rel in amass_result["related_domains"][:5]:
                                    console.print(f"    • {rel}")
                            
                            # Display infrastructure
                            if amass_result.get("infrastructure"):
                                console.print(f"\n  [cyan]Infrastructure:[/cyan]")
                                for infra in amass_result["infrastructure"][:5]:
                                    console.print(f"    • {infra}")
                            
                        except Exception as e:
                            console.print(f"    [red]✗ Amass advanced query failed: {e}[/red]")
                    else:
                        console.print(f"    [yellow]⚠ Amass: Not installed[/yellow]")
                    
                    # crt.sh enumeration
                    crtsh_subdomains = []
                    progress.update(task, description="Subdomain enumeration (crt.sh)...")
                    try:
                        crtsh_subdomains = await dns_recon.query_crtsh(target)
                        if crtsh_subdomains:
                            console.print(f"    [green]✓ crt.sh: {len(crtsh_subdomains)} subdomains[/green]")
                        else:
                            console.print(f"    [yellow]⚠ crt.sh: No subdomains found[/yellow]")
                    except Exception as e:
                        console.print(f"    [red]✗ crt.sh failed: {e}[/red]")
                    
                    # Brute force enumeration with DNS validation
                    progress.update(task, description="Subdomain enumeration (brute force)...")
                    subdiscovery = SubdomainDiscovery()
                    bruteforce_result = await subdiscovery.discover(target)
                    bruteforce_subdomains = list(bruteforce_result.subdomains)
                    
                    # Validate brute force subdomains actually resolve
                    validated_subdomains = []
                    if bruteforce_subdomains:
                        progress.update(task, description="Validating subdomains...")
                        for sub in bruteforce_subdomains:
                            try:
                                import dns.resolver
                                dns.resolver.resolve(sub, 'A')
                                validated_subdomains.append(sub)
                            except:
                                pass  # Subdomain doesn't resolve, skip it
                    
                    if validated_subdomains:
                        console.print(f"    [green]✓ Brute force: {len(validated_subdomains)} resolving subdomains[/green]")
                    else:
                        console.print(f"    [yellow]⚠ Brute force: No resolving subdomains found[/yellow]")
                    
                    # Combine all subdomain sources
                    all_subdomains = set()
                    all_subdomains.update(amass_subdomains)
                    all_subdomains.update(crtsh_subdomains)
                    all_subdomains.update(validated_subdomains)
                    
                    if all_subdomains:
                        console.print(f"\n  [cyan]Subdomains Found:[/cyan] ({len(all_subdomains)} total)")
                        
                        # Show breakdown by source
                        breakdown = []
                        if amass_subdomains:
                            breakdown.append(f"Amass: {len(amass_subdomains)}")
                        if crtsh_subdomains:
                            breakdown.append(f"crt.sh: {len(crtsh_subdomains)}")
                        if validated_subdomains:
                            breakdown.append(f"Brute force: {len(validated_subdomains)}")
                        
                        if breakdown:
                            console.print(f"  Sources: {', '.join(breakdown)}")
                        
                        console.print(f"\n  [cyan]Subdomain List:[/cyan]")
                        for sub in sorted(all_subdomains)[:20]:  # Show first 20
                            console.print(f"    • {sub}")
                        if len(all_subdomains) > 20:
                            console.print(f"    ... and {len(all_subdomains) - 20} more")
                    else:
                        console.print(f"\n  [yellow]No subdomains found[/yellow]")
                    
                    # WHOIS information
                    progress.update(task, description="Querying WHOIS...")
                    try:
                        whois_recon = WhoisRecon()
                        whois_result = await whois_recon.query(target)
                        if whois_result:
                            console.print(f"\n  [cyan]WHOIS Information:[/cyan]")
                            if whois_result.registrar:
                                console.print(f"    Registrar: {whois_result.registrar}")
                            if whois_result.created_date:
                                console.print(f"    Created: {whois_result.created_date}")
                            if whois_result.expiration_date:
                                console.print(f"    Expires: {whois_result.expiration_date}")
                            if whois_result.status:
                                console.print(f"    Status: {whois_result.status}")
                            if whois_result.name_servers:
                                console.print(f"    Nameservers: {', '.join(whois_result.name_servers[:3])}")
                    except Exception as e:
                        console.print(f"    [yellow]⚠ WHOIS query failed: {e}[/yellow]")
                    
                    # Port scanning (advanced deep scan)
                    progress.update(task, description="Port scanning...")
                    try:
                        # Check if Nmap is available (Linux/Parrot OS)
                        nmap_available = False
                        try:
                            proc = await asyncio.create_subprocess_exec(
                                "which", "nmap",
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            await proc.communicate()
                            nmap_available = proc.returncode == 0
                        except:
                            pass

                        if nmap_available:
                            nmap = NmapScanner()
                            # Use advanced deep scan by default
                            nmap_result = await nmap.advanced_scan(
                                targets=[target],
                                ports="1-65535",
                                tcp_scan=True,
                                udp_scan=True,
                                service_detection=True,
                                os_detection=True,
                                script_scan=True,
                                vuln_scan=True,
                                traceroute=True,
                                aggressive=False,
                                timing=4
                            )
                            open_ports = []
                            for host in nmap_result.hosts:
                                if host.os:
                                    console.print(f"\n  [cyan]OS Detection:[/cyan] {host.os}")
                                for port in host.ports:
                                    if port.state == "open":
                                        service_info = f"{port.service or 'unknown'}"
                                        version_info = f" ({port.version})" if port.version else ""
                                        open_ports.append(f"{port.port}/{port.protocol}: {service_info}{version_info}")

                            if open_ports:
                                console.print(f"\n  [cyan]Open Ports:[/cyan] ({len(open_ports)} found)")
                                for port in open_ports[:20]:  # Show first 20
                                    console.print(f"    • {port}")
                                if len(open_ports) > 20:
                                    console.print(f"    ... and {len(open_ports) - 20} more")
                            else:
                                console.print(f"\n  [yellow]No open ports detected[/yellow]")
                        else:
                            console.print(f"\n  [yellow]⚠ Nmap not installed - skipping port scan[/yellow]")
                            console.print(f"    Install Nmap for port scanning capabilities")
                    except Exception as e:
                        console.print(f"\n  [yellow]⚠ Port scan failed: {e}[/yellow]")
                    
                    progress.update(task, description="Reconnaissance complete")
                    
                except Exception as e:
                    console.print(f"  [red]Error: {e}[/red]")
                    console.print(f"  [yellow]Error type: {type(e).__name__}[/yellow]")

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
        "1-65535",
        "--ports",
        "-p",
        help="Port range to scan (e.g., 1-65535, 22,80,443)"
    ),
    basic: bool = typer.Option(
        False,
        "--basic",
        "-b",
        help="Use basic scanning instead of advanced deep scan"
    ),
    aggressive: bool = typer.Option(
        False,
        "--aggressive",
        "-A",
        help="Enable aggressive scanning (even more comprehensive)"
    ),
    timing: int = typer.Option(
        4,
        "--timing",
        "-T",
        help="Timing template (0-5, 4 is normal, higher is faster but more detectable)"
    )
) -> None:
    """Run network scan on targets (advanced deep scan by default)."""
    console.print(Panel.fit("[bold blue]Network Scanning[/bold blue]"))
    console.print(f"Targets: {', '.join(targets)}")
    console.print(f"Ports: {ports}")

    if basic:
        console.print("[yellow]Basic scanning mode[/yellow]")
    else:
        console.print("[green]Advanced deep scanning enabled (default)[/green]")
        console.print("  - TCP SYN scan")
        console.print("  - UDP scan")
        console.print("  - Service detection")
        console.print("  - OS detection")
        console.print("  - Script scanning")
        console.print("  - Vulnerability detection")
        console.print("  - Traceroute")

    if aggressive:
        console.print("[yellow]Aggressive scanning enabled[/yellow]")

    async def _run_scan():
        from scanning.nmap import NmapScanner
        from security import ScopeManager

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
                if basic:
                    # Use basic scan
                    result = await scanner.scan(
                        targets=[target],
                        ports=ports,
                        scan_type="sT",
                        service_detection=True,
                        os_detection=False,
                        aggressive=False
                    )
                else:
                    # Use advanced deep scan by default
                    result = await scanner.advanced_scan(
                        targets=[target],
                        ports=ports,
                        tcp_scan=True,
                        udp_scan=True,
                        service_detection=True,
                        os_detection=True,
                        script_scan=True,
                        vuln_scan=True,
                        traceroute=True,
                        aggressive=aggressive,
                        timing=timing
                    )

                # Display results
                if result.exit_status == 0:
                    for host in result.hosts:
                        console.print(f"  Host: {host.ip}")
                        if host.hostname:
                            console.print(f"    Hostname: {host.hostname}")
                        if host.os:
                            console.print(f"    OS: {host.os}")
                        if host.ports:
                            console.print(f"    Open ports ({len(host.ports)}):")
                            for port in host.ports:
                                if port.state == "open":
                                    service_info = f"{port.service}" if port.service else "unknown"
                                    version_info = f" ({port.version})" if port.version else ""
                                    console.print(f"      {port.port}/{port.protocol}: {service_info}{version_info}")
                        else:
                            console.print("    No open ports found")
                else:
                    console.print(f"  [red]Scan failed with exit code {result.exit_status}[/red]")

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
    ),
    timeout: int = typer.Option(
        10,
        "--timeout",
        "-t",
        help="Connection timeout in seconds (default: 10)"
    ),
    skip_advanced: bool = typer.Option(
        False,
        "--skip-advanced",
        help="Skip advanced scans (SSL, directories, WAF) for faster results"
    )
) -> None:
    """Run web application security assessment."""
    console.print(Panel.fit("[bold blue]Web Assessment[/bold blue]"))
    console.print(f"Targets: {', '.join(targets)}")
    console.print(f"Timeout: {timeout}s")
    if skip_advanced:
        console.print("[yellow]Advanced scans disabled (faster mode)[/yellow]")

    async def _run_web():
        from scanning.http_scanner import HTTPScanner
        from security import ScopeManager

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

        scanner = HTTPScanner(timeout=timeout, connect_timeout=min(timeout, 5), skip_advanced=skip_advanced)
        for target in valid_targets:
            console.print(f"\n[bold]Scanning {target}...[/bold]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Initializing scan...", total=None)
                
                try:
                    progress.update(task, description="Connecting to target...")
                    result = await scanner.scan(target)
                    
                    progress.update(task, description="Analyzing results...")
                    
                    console.print(f"\n  [cyan]Target:[/cyan] {result.target}")
                    console.print(f"  [cyan]Scan Duration:[/cyan] {result.scan_duration:.2f}s")
                    console.print(f"  [cyan]DNS Resolution:[/cyan] {result.dns_resolution_time:.2f}s")
                    console.print(f"  [cyan]Connection Time:[/cyan] {result.connection_time:.2f}s")
                    console.print(f"  [cyan]Response Time:[/cyan] {result.response_time:.2f}s")
                    console.print(f"  [cyan]Security Headers:[/cyan] {len(result.security_headers)}")
                    console.print(f"  [cyan]Cookies:[/cyan] {len(result.cookies)}")
                    console.print(f"  [cyan]Vulnerabilities:[/cyan] {len(result.vulnerabilities)}")
                    
                    if result.waf_detected:
                        console.print(f"\n  [yellow]WAF Detected:[/yellow] {result.waf_detected}")
                    
                    if result.technologies:
                        console.print(f"\n  [cyan]Technologies Detected:[/cyan]")
                        for tech in result.technologies:
                            console.print(f"    • {tech}")
                    
                    if result.ssl_info:
                        console.print(f"\n  [cyan]SSL/TLS Information:[/cyan]")
                        for key, value in result.ssl_info.items():
                            console.print(f"    {key}: {value}")
                    
                    if result.open_directories:
                        console.print(f"\n  [yellow]Open/Restricted Directories:[/yellow]")
                        for directory in result.open_directories:
                            console.print(f"    • {directory}")
                    
                    if result.sqlmap_findings:
                        console.print(f"\n  [red]SQLMap Findings:[/red]")
                        for finding in result.sqlmap_findings:
                            console.print(f"    • {finding}")
                    
                    if result.ssl_labs_grade:
                        console.print(f"\n  [cyan]SSL Labs Grade:[/cyan] {result.ssl_labs_grade} (Score: {result.ssl_labs_score})")
                    
                    if result.nuclei_findings:
                        console.print(f"\n  [red]Nuclei Findings:[/red]")
                        for finding in result.nuclei_findings:
                            console.print(f"    • {finding}")
                    
                    if result.security_headers:
                        console.print(f"\n  [yellow]Security Headers Found:[/yellow]")
                        for header in result.security_headers:
                            status = "✓" if header.present else "✗"
                            console.print(f"    {status} {header.name}")
                    
                    if result.vulnerabilities:
                        console.print(f"\n  [red]Vulnerabilities:[/red]")
                        for vuln in result.vulnerabilities:
                            console.print(f"    • {vuln}")
                    
                    if result.recommendations:
                        console.print(f"\n  [green]Recommendations:[/green]")
                        for rec in result.recommendations:
                            console.print(f"    • {rec}")
                    
                    if result.cors_config:
                        console.print(f"\n  [cyan]CORS Configuration:[/cyan]")
                        for key, value in result.cors_config.items():
                            console.print(f"    {key}: {value}")
                    
                    progress.update(task, description="Scan complete")
                    
                except Exception as e:
                    console.print(f"  [red]Error: {e}[/red]")
                    console.print(f"  [yellow]Error type: {type(e).__name__}[/yellow]")

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

    async def _run_api():
        from scanning.api_discovery import APIDiscovery
        from security import ScopeManager

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

        console.print(f"[green]✓ Validated {len(valid_targets)} targets[/green]")

        api_discovery = APIDiscovery()
        for target in valid_targets:
            console.print(f"\n[bold]Scanning {target}...[/bold]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Discovering API endpoints...", total=None)

                try:
                    result = await api_discovery.discover(target)
                    progress.update(task, description="Analyzing results...")

                    console.print(f"\n  [cyan]Target:[/cyan] {result.target}")
                    console.print(f"  [cyan]Endpoints Discovered:[/cyan] {len(result.endpoints)}")

                    if result.openapi_spec:
                        console.print(f"\n  [green]✓ OpenAPI Specification Found[/green]")
                        console.print(f"    Paths: {len(result.openapi_spec.get('paths', {}))}")

                    if result.graphql_endpoints:
                        console.print(f"\n  [cyan]GraphQL Endpoints:[/cyan]")
                        for endpoint in result.graphql_endpoints:
                            console.print(f"    • {endpoint}")

                    if result.rest_endpoints:
                        console.print(f"\n  [cyan]REST Endpoints:[/cyan]")
                        for endpoint in result.rest_endpoints[:10]:
                            console.print(f"    • {endpoint}")
                        if len(result.rest_endpoints) > 10:
                            console.print(f"    ... and {len(result.rest_endpoints) - 10} more")

                    if result.endpoints:
                        console.print(f"\n  [cyan]Detailed Endpoints:[/cyan]")
                        for endpoint in result.endpoints[:15]:
                            console.print(f"    {endpoint.method} {endpoint.path}")
                        if len(result.endpoints) > 15:
                            console.print(f"    ... and {len(result.endpoints) - 15} more")

                    if result.security_issues:
                        console.print(f"\n  [red]Security Issues:[/red]")
                        for issue in result.security_issues:
                            console.print(f"    • {issue}")

                    progress.update(task, description="Scan complete")

                except Exception as e:
                    console.print(f"  [red]Error: {e}[/red]")
                    console.print(f"  [yellow]Error type: {type(e).__name__}[/yellow]")

        console.print("[green]✓ API assessment complete[/green]")

    asyncio.run(_run_api())


@app.command()
def research(
    cve_id: Optional[str] = typer.Argument(None, help="CVE ID to research"),
    service: Optional[str] = typer.Option(None, "--service", help="Service name"),
    version: Optional[str] = typer.Option(None, "--version", help="Service version")
) -> None:
    """Research vulnerabilities and exploits."""
    console.print(Panel.fit("[bold blue]Vulnerability Research[/bold blue]"))

    async def _run_research():
        from vulnerability.cve_matcher import CVEMatcher
        from vulnerability.exploitdb import ExploitIntelligence

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
        from exploitation.exploit_registry import ExploitRegistry

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
        from exploitation.exploit_registry import ExploitRegistry

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

    async def _check_compatibility():
        from exploitation.exploit_registry import ExploitRegistry
        from exploitation.exploit_matcher import ExploitMatcher
        from scanning.service_detection import ServiceDetection

        registry = ExploitRegistry()
        exploit = registry.get(exploit_id)

        if not exploit:
            console.print(f"[red]✗ Exploit {exploit_id} not found[/red]")
            raise typer.Exit(1)

        # Get exploit details
        table = Table(title="Exploit Details")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("ID", exploit.exploit_id)
        table.add_row("Name", exploit.name)
        table.add_row("Description", exploit.description)
        table.add_row("Target Service", exploit.target_service or "N/A")
        table.add_row("Target Version", exploit.target_version or "Any")
        table.add_row("Platform", ", ".join(exploit.platform))
        table.add_row("Risk Level", exploit.risk_level)
        table.add_row("Requires Lab", "Yes" if exploit.requires_lab else "No")

        console.print(table)

        # Detect services on target
        console.print(f"\n[bold]Detecting services on {target}...[/bold]")

        # Try common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

        service_detection = ServiceDetection()
        detected_services = await service_detection.detect_multiple(target, common_ports)

        if detected_services:
            console.print(f"\n[cyan]Detected Services:[/cyan]")
            for port, result in detected_services.items():
                for service in result.services:
                    console.print(f"  Port {port}: {service.service} {service.version or ''} (confidence: {service.confidence:.2f})")

            # Check compatibility
            console.print(f"\n[bold]Compatibility Check:[/bold]")

            compatible = False
            compatibility_score = 0.0

            # Check platform
            if "linux" in [p.lower() for p in exploit.platform]:
                compatibility_score += 0.3
                console.print(f"  ✓ Platform: Linux (compatible)")
            elif "windows" in [p.lower() for p in exploit.platform]:
                compatibility_score += 0.3
                console.print(f"  ✓ Platform: Windows (compatible)")
            else:
                console.print(f"  ? Platform: {', '.join(exploit.platform)} (unknown compatibility)")

            # Check service
            if exploit.target_service:
                service_match = False
                for port, result in detected_services.items():
                    for service in result.services:
                        if exploit.target_service.lower() in service.service.lower():
                            service_match = True
                            compatibility_score += 0.4
                            console.print(f"  ✓ Service: {service.service} matches {exploit.target_service}")

                            # Check version
                            if exploit.target_version and service.version:
                                if exploit.target_version in service.version:
                                    compatibility_score += 0.3
                                    console.print(f"  ✓ Version: {service.version} matches {exploit.target_version}")
                                else:
                                    console.print(f"  ⚠ Version: {service.version} (target: {exploit.target_version})")
                            else:
                                console.print(f"  ✓ Version: Any (no specific requirement)")

                if not service_match:
                    console.print(f"  ✗ Service: {exploit.target_service} not detected")

            if compatibility_score >= 0.7:
                console.print(f"\n[green]✓ Exploit is COMPATIBLE (score: {compatibility_score:.2f})[/green]")
                compatible = True
            elif compatibility_score >= 0.4:
                console.print(f"\n[yellow]⚠ Exploit is PARTIALLY COMPATIBLE (score: {compatibility_score:.2f})[/yellow]")
                compatible = True
            else:
                console.print(f"\n[red]✗ Exploit is NOT COMPATIBLE (score: {compatibility_score:.2f})[/red]")

            if exploit.requires_lab:
                console.print(f"\n[yellow]⚠ This exploit requires a lab environment for execution[/yellow]")

        else:
            console.print(f"\n[yellow]⚠ No services detected on {target}[/yellow]")
            console.print(f"[red]✗ Cannot determine compatibility - no service information[/red]")

    asyncio.run(_check_compatibility())


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
    console.print("[yellow]⚠ This command runs on the local system for audit purposes[/yellow]")

    async def _run_audit():
        from post_assessment.lateral_movement_audit import LateralMovementAudit
        from post_assessment.persistence_audit import PersistenceAudit
        from post_assessment.credential_exposure import CredentialExposure

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Lateral Movement Audit
            task = progress.add_task("Running lateral movement audit...", total=None)
            lateral_audit = LateralMovementAudit()
            lateral_result = await lateral_audit.audit(target)
            progress.update(task, description="Lateral movement audit complete")

            # Persistence Audit
            task = progress.add_task("Running persistence audit...", total=None)
            persistence_audit = PersistenceAudit()
            persistence_result = await persistence_audit.audit(target)
            progress.update(task, description="Persistence audit complete")

            # Credential Exposure Audit
            task = progress.add_task("Running credential exposure audit...", total=None)
            credential_audit = CredentialExposure()
            credential_result = await credential_audit.detect(target)
            progress.update(task, description="Credential exposure audit complete")

        # Display results
        console.print(f"\n[bold]Lateral Movement Audit:[/bold]")
        console.print(f"  Network hosts discovered: {len(lateral_result.network_hosts)}")
        if lateral_result.network_hosts:
            console.print(f"  [cyan]Hosts:[/cyan]")
            for host in lateral_result.network_hosts[:10]:
                console.print(f"    • {host}")

        console.print(f"  Lateral paths found: {len(lateral_result.paths)}")
        if lateral_result.paths:
            console.print(f"  [cyan]Paths:[/cyan]")
            for path in lateral_result.paths[:10]:
                console.print(f"    {path.method}: {path.source} -> {path.destination}")

        console.print(f"\n[bold]Persistence Audit:[/bold]")
        console.print(f"  Persistence mechanisms: {len(persistence_result.mechanisms)}")
        if persistence_result.mechanisms:
            console.print(f"  [cyan]Mechanisms:[/cyan]")
            for mech in persistence_result.mechanisms[:10]:
                console.print(f"    [{mech.severity}] {mech.type}: {mech.location}")

        console.print(f"  Systemd services: {len(persistence_result.systemd_services)}")
        console.print(f"  Cron jobs: {len(persistence_result.cron_jobs)}")
        console.print(f"  Startup files: {len(persistence_result.startup_files)}")

        console.print(f"\n[bold]Credential Exposure Audit:[/bold]")
        console.print(f"  Findings: {len(credential_result.findings)}")
        if credential_result.findings:
            console.print(f"  [cyan]Findings:[/cyan]")
            for finding in credential_result.findings[:10]:
                console.print(f"    [{finding.severity}] {finding.type}: {finding.location}")

        console.print(f"  SSH keys found: {len(credential_result.ssh_keys)}")
        console.print(f"  Password files found: {len(credential_result.password_files)}")

        console.print("\n[green]✓ Post-exploitation audit complete[/green]")

    asyncio.run(_run_audit())


@app.command()
def lateral_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run lateral movement audit."""
    console.print(Panel.fit("[bold blue]Lateral Movement Audit[/bold blue]"))
    console.print(f"Target: {target}")

    async def _run_audit():
        from post_assessment.lateral_movement_audit import LateralMovementAudit

        audit = LateralMovementAudit()
        result = await audit.audit(target)

        console.print(f"\n[cyan]Network Hosts:[/cyan] {len(result.network_hosts)}")
        for host in result.network_hosts[:20]:
            console.print(f"  • {host}")

        console.print(f"\n[cyan]Lateral Paths:[/cyan] {len(result.paths)}")
        for path in result.paths[:20]:
            console.print(f"  {path.method}: {path.source} -> {path.destination}")
            if path.credentials:
                console.print(f"    Credentials: {', '.join(path.credentials)}")

        console.print(f"\n[cyan]Trust Relationships:[/cyan] {len(result.trust_relationships)}")
        for trust in result.trust_relationships[:10]:
            console.print(f"  • {trust}")

        console.print("\n[green]✓ Lateral movement audit complete[/green]")

    asyncio.run(_run_audit())


@app.command()
def persistence_audit(
    target: str = typer.Argument(..., help="Target to audit")
) -> None:
    """Run persistence mechanism audit."""
    console.print(Panel.fit("[bold blue]Persistence Audit[/bold blue]"))
    console.print(f"Target: {target}")

    async def _run_audit():
        from post_assessment.persistence_audit import PersistenceAudit

        audit = PersistenceAudit()
        result = await audit.audit(target)

        console.print(f"\n[cyan]Persistence Mechanisms:[/cyan] {len(result.mechanisms)}")
        for mech in result.mechanisms[:20]:
            console.print(f"  [{mech.severity}] {mech.type}: {mech.location}")
            console.print(f"    {mech.description}")

        console.print(f"\n[cyan]Systemd Services:[/cyan] {len(result.systemd_services)}")
        for service in result.systemd_services[:10]:
            console.print(f"  • {service}")

        console.print(f"\n[cyan]Cron Jobs:[/cyan] {len(result.cron_jobs)}")
        for job in result.cron_jobs[:10]:
            console.print(f"  • {job}")

        console.print(f"\n[cyan]Startup Files:[/cyan] {len(result.startup_files)}")
        for file in result.startup_files[:10]:
            console.print(f"  • {file}")

        console.print("\n[green]✓ Persistence audit complete[/green]")

    asyncio.run(_run_audit())


@app.command()
def exfil_simulate(
    target: str = typer.Argument(..., help="Target to simulate against")
) -> None:
    """Run data exfiltration simulation."""
    console.print(Panel.fit("[bold blue]Data Exfiltration Simulation[/bold blue]"))
    console.print(f"Target: {target}")
    console.print("[yellow]⚠ This is a simulation only - no actual data exfiltration occurs[/yellow]")

    async def _run_simulation():
        from post_assessment.exfiltration_simulation import ExfiltrationSimulation

        sim = ExfiltrationSimulation()
        result = await sim.simulate(target)

        console.print(f"\n[cyan]Exfiltration Tests:[/cyan] {len(result.tests)}")
        for test in result.tests:
            status = "✓" if test.successful else "✗"
            blocked_status = " (blocked)" if test.blocked else ""
            console.print(f"  {status} {test.method.upper()}: {test.details}{blocked_status}")
            console.print(f"    Data size: {test.data_size} bytes, Duration: {test.duration:.2f}s")

        console.print(f"\n[cyan]Egress Status:[/cyan]")
        console.print(f"  DNS egress: {'✓ Allowed' if result.dns_egress_allowed else '✗ Blocked'}")
        console.print(f"  HTTP egress: {'✓ Allowed' if result.http_egress_allowed else '✗ Blocked'}")
        console.print(f"  FTP egress: {'✓ Allowed' if result.ftp_egress_allowed else '✗ Blocked'}")
        console.print(f"  Overall: {'✓ EXFILTRATION POSSIBLE' if result.overall_allowed else '✗ EXFILTRATION BLOCKED'}")

        console.print(f"\n[cyan]Test Data:[/cyan]")
        console.print(f"  Synthetic data preview: {result.synthetic_data[:20]}...")

        console.print("\n[green]✓ Exfiltration simulation complete[/green]")
        console.print("[yellow]⚠ This was a simulation - no data was actually exfiltrated[/yellow]")

    asyncio.run(_run_simulation())


@app.command()
def code_analyze(
    path: Path = typer.Argument(..., help="Path to source code"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
    scan_secrets: bool = typer.Option(True, "--secrets/--no-secrets", help="Scan for secrets"),
    scan_deps: bool = typer.Option(True, "--deps/--no-deps", help="Scan dependencies"),
    scan_sast: bool = typer.Option(True, "--sast/--no-sast", help="Run static analysis")
) -> None:
    """Analyze source code for security issues."""
    console.print(Panel.fit("[bold blue]Source Code Analysis[/bold blue]"))
    console.print(f"Path: {path}")
    console.print(f"Scan secrets: {scan_secrets}")
    console.print(f"Scan dependencies: {scan_deps}")
    console.print(f"Static analysis: {scan_sast}")

    async def _run_analysis():
        from code_analysis.semgrep import SemgrepAnalyzer
        from code_analysis.gitleaks import GitleaksScanner
        from code_analysis.trivy import TrivyScanner

        if not path.exists():
            console.print(f"[red]✗ Path does not exist: {path}[/red]")
            raise typer.Exit(1)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            # Static Analysis (Semgrep)
            sast_result = None
            if scan_sast:
                task = progress.add_task("Checking Semgrep installation...", total=None)
                semgrep = SemgrepAnalyzer()
                semgrep_installed = await semgrep.check_installed()

                if semgrep_installed:
                    progress.update(task, description="Running static analysis (Semgrep)...")
                    sast_result = await semgrep.analyze(str(path))
                    progress.update(task, description="Static analysis complete")
                else:
                    progress.update(task, description="Semgrep not installed, skipping SAST")
                    console.print("[yellow]⚠ Semgrep not installed - skipping static analysis[/yellow]")

            # Secret Scanning (Gitleaks)
            secret_result = None
            if scan_secrets:
                task = progress.add_task("Checking Gitleaks installation...", total=None)
                gitleaks = GitleaksScanner()
                gitleaks_installed = await gitleaks.check_installed()

                if gitleaks_installed:
                    progress.update(task, description="Scanning for secrets (Gitleaks)...")
                    secret_result = await gitleaks.scan(str(path))
                    progress.update(task, description="Secret scan complete")
                else:
                    progress.update(task, description="Gitleaks not installed, skipping secret scan")
                    console.print("[yellow]⚠ Gitleaks not installed - skipping secret scan[/yellow]")

            # Dependency Scanning (Trivy)
            dep_result = None
            if scan_deps:
                task = progress.add_task("Checking Trivy installation...", total=None)
                trivy = TrivyScanner()
                trivy_installed = await trivy.check_installed()

                if trivy_installed:
                    progress.update(task, description="Scanning dependencies (Trivy)...")
                    dep_result = await trivy.scan(str(path), scan_type="fs")
                    progress.update(task, description="Dependency scan complete")
                else:
                    progress.update(task, description="Trivy not installed, skipping dependency scan")
                    console.print("[yellow]⚠ Trivy not installed - skipping dependency scan[/yellow]")

        # Display results
        console.print(f"\n[bold]Analysis Results:[/bold]")

        if sast_result:
            console.print(f"\n[cyan]Static Analysis (Semgrep):[/cyan]")
            console.print(f"  Scan duration: {sast_result.scan_duration:.2f}s")
            console.print(f"  Findings: {len(sast_result.findings)}")

            if sast_result.severity_summary:
                console.print(f"  [cyan]Severity Summary:[/cyan]")
                for severity, count in sast_result.severity_summary.items():
                    console.print(f"    {severity}: {count}")

            if sast_result.findings:
                console.print(f"\n  [cyan]Top Findings:[/cyan]")
                for finding in sast_result.findings[:10]:
                    console.print(f"    [{finding.severity}] {finding.rule_id}")
                    console.print(f"      {finding.message}")
                    console.print(f"      {finding.file}:{finding.line}")

        if secret_result:
            console.print(f"\n[cyan]Secret Scanning (Gitleaks):[/cyan]")
            console.print(f"  Scan duration: {secret_result.scan_duration:.2f}s")
            console.print(f"  Secrets found: {len(secret_result.findings)}")

            if secret_result.severity_summary:
                console.print(f"  [cyan]Severity Summary:[/cyan]")
                for severity, count in secret_result.severity_summary.items():
                    console.print(f"    {severity}: {count}")

            if secret_result.findings:
                console.print(f"\n  [red]Secret Findings:[/red]")
                for finding in secret_result.findings[:10]:
                    console.print(f"    [{finding.severity}] {finding.rule_id}")
                    console.print(f"      {finding.description}")
                    console.print(f"      {finding.file}:{finding.line}")

        if dep_result:
            console.print(f"\n[cyan]Dependency Scanning (Trivy):[/cyan]")
            console.print(f"  Scan duration: {dep_result.scan_duration:.2f}s")
            console.print(f"  Vulnerabilities: {len(dep_result.vulnerabilities)}")

            if dep_result.severity_summary:
                console.print(f"  [cyan]Severity Summary:[/cyan]")
                for severity, count in dep_result.severity_summary.items():
                    console.print(f"    {severity}: {count}")

            if dep_result.vulnerabilities:
                console.print(f"\n  [cyan]Top Vulnerabilities:[/cyan]")
                for vuln in dep_result.vulnerabilities[:10]:
                    console.print(f"    [{vuln.severity}] {vuln.vulnerability_id}")
                    console.print(f"      {vuln.package_name} ({vuln.installed_version})")
                    console.print(f"      Fixed in: {vuln.fixed_version or 'N/A'}")

        # Save results if output specified
        if output:
            import json
            results = {
                "path": str(path),
                "sast": sast_result.__dict__ if sast_result else None,
                "secrets": secret_result.__dict__ if secret_result else None,
                "dependencies": dep_result.__dict__ if dep_result else None
            }

            with open(output, "w") as f:
                json.dump(results, f, indent=2, default=str)

            console.print(f"\n[green]✓ Results saved to {output}[/green]")

        console.print("\n[green]✓ Code analysis complete[/green]")

    asyncio.run(_run_analysis())


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
        from reporting.report_engine import ReportEngine, ReportConfig

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
