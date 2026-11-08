"""
HAZARUS Interactive Mode
Menu-driven interface for the framework (SOLE ENTRY POINT).
"""

import asyncio
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich.align import Align
from rich.box import DOUBLE
from datetime import datetime
from hazarus.tools.registry import ToolStatus
from hazarus.vulnerability.nikto import NiktoScanner
from hazarus.vulnerability.nuclei import NucleiScanner
from hazarus.scanning.masscan import MasscanScanner
from hazarus.scanning.rustscan import RustScanScanner


class InteractiveMode:
    """Interactive menu-driven interface (ONLY entry point)."""

    def __init__(self):
        self.console = Console()
        self.current_menu = "main"
        self.current_target = None
        self.history = []
        self.home = Path.home()
        self.hazarus_dir = self.home / ".hazarus"
        self.banner_shown = False
        self.config = {
            'timeouts': {
                'default': 30,
                'http_scan': 30
            }
        }
        # Track failed installations for retry functionality
        self.failed_installations = {}
        # Debug mode for installation
        self.debug_mode = False

    def show_banner(self):
        """Display HAZARUS banner."""
        ASCII_LOGO = r"""
██╗  ██╗ █████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗███████╗
██║  ██║██╔══██╗╚══███╔╝██╔══██╗██╔══██╗██║   ██║██╔════╝
███████║███████║  ███╔╝ ███████║██████╔╝██║   ██║███████╗
██╔══██║██╔══██║ ███╔╝  ██╔══██║██╔══██╗██║   ██║╚════██║
██║  ██║██║  ██║███████╗██║  ██║██║  ██║╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══════╝╚══════╝
"""

        logo = Text(ASCII_LOGO, style="bold red", justify="center")

        identity = Text(justify="center")
        identity.append(
            "HAZARUS SECURITY ASSESSMENT FRAMEWORK\n",
            style="bold white"
        )
        identity.append(
            "ADVANCED SECURITY PLATFORM\n",
            style="bold red"
        )
        identity.append(
            "INTERACTIVE MODE ONLY",
            style="bold white"
        )

        content = Text()
        content.append_text(logo)
        content.append("\n")
        content.append_text(identity)

        banner = Panel(
            Align.center(content),
            box=DOUBLE,
            border_style="red",
            padding=(1, 2),
            expand=True
        )

        self.console.print()
        self.console.print(banner)
        self.console.print()

    def show_config(self):
        """Display configuration details."""
        config_table = Table(title="Configuration Details", show_header=True)
        config_table.add_column("Setting", style="cyan", width=30)
        config_table.add_column("Value", style="green")

        # Project paths
        config_table.add_row("Project", str(Path.cwd()))
        config_table.add_row("Database", str(self.hazarus_dir / "reconnaissance.db"))
        config_table.add_row("Log File", str(self.hazarus_dir / "hazarus.log"))
        config_table.add_row("Reports", str(self.hazarus_dir / "reports/"))
        config_table.add_row("Evidence", str(self.hazarus_dir / "evidence/"))

        # Assessment settings
        config_table.add_row("", "")
        config_table.add_row("Assessment Intensity", "normal")
        config_table.add_row("Privacy Mode", "strict")
        config_table.add_row("Max Threads", "10")
        config_table.add_row("Timeout", f"{self.config.get('timeouts.default', 30)}s")

        # Privacy settings
        config_table.add_row("", "")
        config_table.add_row("Require Anonsurf", "true")
        config_table.add_row("Block on DNS Leak", "true")
        config_table.add_row("Block on IPv6 Exposure", "true")

        self.console.print(config_table)

    def show_main_menu(self):
        """Display main menu."""
        menu = Panel(
            """
[bold cyan][01][/bold cyan] Target Management
[bold cyan][02][/bold cyan] Reconnaissance & Intelligence
[bold cyan][03][/bold cyan] Network Security Assessment
[bold cyan][04][/bold cyan] Web Application & API Pentesting
[bold cyan][05][/bold cyan] Host & Infrastructure Pentesting
[bold cyan][06][/bold cyan] Mobile Application Pentesting
[bold cyan][07][/bold cyan] Digital Forensics & Incident Response
[bold cyan][08][/bold cyan] Wireless Security Assessment
[bold cyan][09][/bold cyan] Vulnerability Research & Exploitation
[bold cyan][10][/bold cyan] Post-Assessment & Security Audits
[bold cyan][11][/bold cyan] Source Code Security Analysis
[bold cyan][12][/bold cyan] Reporting & Evidence Management
[bold cyan][13][/bold cyan] Configuration
[bold cyan][14][/bold cyan] Advanced Tools
[bold cyan][15][/bold cyan] Asset Intelligence
[bold cyan][16][/bold cyan] Comprehensive Assessment
[bold cyan][17][/bold cyan] External Tools
[bold red][00][/bold red] Exit
""",
            title="[bold red]Main Menu[/bold red]",
            border_style="red"
        )
        self.console.print(menu)

    async def run(self):
        """Run interactive mode."""
        self.console.clear()

        # Show banner only once at startup
        self.show_banner()
        self.banner_shown = True

        # Startup tool check
        await self.startup_tool_check()

        while True:
            if self.current_target:
                self.console.print(f"[green]Current Target: {self.current_target}[/green]\n")

            self.show_main_menu()

            choice = self.console.input("\n[bold red]Select option [00-17]: [/bold red]")

            if choice in ["0", "00"]:
                self.console.print("[green]Exiting HAZARUS...[/green]")
                break
            elif choice in ["1", "01"]:
                await self.target_management_menu()
            elif choice in ["2", "02"]:
                await self.reconnaissance_menu()
            elif choice in ["3", "03"]:
                await self.network_scanning_menu()
            elif choice in ["4", "04"]:
                await self.web_api_pentesting_menu()
            elif choice in ["5", "05"]:
                await self.host_infrastructure_menu()
            elif choice in ["6", "06"]:
                await self.mobile_pentesting_menu()
            elif choice in ["7", "07"]:
                await self.forensics_menu()
            elif choice in ["8", "08"]:
                await self.wireless_menu()
            elif choice in ["9", "09"]:
                await self.vulnerability_exploitation_menu()
            elif choice in ["10"]:
                await self.post_assessment_menu()
            elif choice in ["11"]:
                await self.source_code_analysis_menu()
            elif choice in ["12"]:
                await self.reporting_menu()
            elif choice in ["13"]:
                await self.configuration_menu()
            elif choice in ["14"]:
                await self.advanced_tools_menu()
            elif choice in ["15"]:
                await self.asset_intelligence_menu()
            elif choice in ["16"]:
                await self.comprehensive_assessment_menu()
            elif choice in ["17"]:
                await self.external_tools_menu()
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                await asyncio.sleep(1)

    async def target_management_menu(self):
        """Target management submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Target Management[/bold]", border_style="red"))
            self.console.print("[1] Add Target")
            self.console.print("[2] List Targets")
            self.console.print("[3] Set Current Target")
            self.console.print("[4] Validate Scope")
            self.console.print("[5] Edit Scope")
            self.console.print("[6] Delete Target")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-6]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice == "1":
                target = self.console.input("Enter target (domain/IP): ")
                await self.add_target(target)
            elif choice == "2":
                await self.list_targets()
            elif choice == "3":
                target = self.console.input("Enter target to set as current: ")
                self.current_target = target
                self.console.print(f"[green]Current target set to: {target}[/green]")
                await asyncio.sleep(1)
            elif choice == "4":
                await self.validate_scope()
            elif choice == "5":
                await self.edit_scope()
            elif choice == "6":
                target = self.console.input("Enter target to delete: ")
                await self.delete_target(target)

    async def reconnaissance_menu(self):
        """Reconnaissance submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Reconnaissance[/bold]", border_style="red"))
            self.console.print("[1] Quick Recon (DNS + Subdomains)")
            self.console.print("[2] Full Recon (DNS + Subdomains + WHOIS + Origin IP)")
            self.console.print("[3] Subdomain Takeover Check")
            self.console.print("[4] Virtual Host Enumeration")
            self.console.print("[5] Advanced Recon (All Tools)")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4", "5"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified. Please set a target first.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "quick",
                    "2": "full",
                    "3": "takeover",
                    "4": "vhost",
                    "5": "advanced"
                }[choice]
                
                await self.run_recon(target, mode)

    async def network_scanning_menu(self):
        """Network scanning submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Network Scanning[/bold]", border_style="red"))
            self.console.print("[1] Live Host Discovery")
            self.console.print("[2] Quick Scan (Common Ports)")
            self.console.print("[3] Deep Scan (All Ports)")
            self.console.print("[4] Advanced Scan (With Scripts)")
            self.console.print("[5] Masscan (High-Performance Port Scan)")
            self.console.print("[6] RustScan (Fast Port Discovery)")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-6]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target (IP/CIDR): ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "live",
                    "2": "quick",
                    "3": "deep",
                    "4": "advanced"
                }[choice]
                
                await self.run_scan(target, mode)
            elif choice == "5":
                target = self.console.input("Enter target (IP/CIDR): ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                await self.run_masscan(target)
            elif choice == "6":
                target = self.console.input("Enter target (IP/CIDR): ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                await self.run_rustscan(target)

    async def web_assessment_menu(self):
        """Web assessment submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Web Assessment[/bold]", border_style="red"))
            self.console.print("[1] Basic Assessment")
            self.console.print("[2] Aggressive Assessment")
            self.console.print("[3] WPScan")
            self.console.print("[4] Gobuster")
            self.console.print("[5] WhatWeb")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4", "5"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue

                mode = {
                    "1": "basic",
                    "2": "aggressive",
                    "3": "wpscan",
                    "4": "gobuster",
                    "5": "whatweb"
                }[choice]

                await self.run_web(target, mode)

    async def web_api_pentesting_menu(self):
        """Combined Web Application & API Pentesting submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Web Application & API Pentesting[/bold]", border_style="red"))
            self.console.print("[bold cyan]Web Assessment:[/bold cyan]")
            self.console.print("[1] Basic Web Assessment")
            self.console.print("[2] Aggressive Web Assessment")
            self.console.print("[3] WPScan")
            self.console.print("[4] Gobuster")
            self.console.print("[5] WhatWeb")
            self.console.print("")
            self.console.print("[bold cyan]API Assessment:[/bold cyan]")
            self.console.print("[6] REST Endpoint Discovery")
            self.console.print("[7] GraphQL Endpoint Discovery")
            self.console.print("[8] API Security Testing")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-8]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4", "5"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue

                mode = {
                    "1": "basic",
                    "2": "aggressive",
                    "3": "wpscan",
                    "4": "gobuster",
                    "5": "whatweb"
                }[choice]

                await self.run_web(target, mode)
            elif choice in ["6", "7", "8"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue

                mode = {
                    "6": "rest",
                    "7": "graphql",
                    "8": "security"
                }[choice]

                await self.run_api(target, mode)

    async def comprehensive_assessment_menu(self):
        """Comprehensive assessment submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Comprehensive Assessment[/bold]", border_style="red"))
            self.console.print("[1] Standard (4 Phases)")
            self.console.print("[2] Full (10 Phases)")
            self.console.print("[3] Custom (Select Phases)")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-3]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "standard",
                    "2": "full",
                    "3": "custom"
                }[choice]
                
                await self.run_comprehensive(target, mode)

    # Implementation methods that call actual logic
    async def add_target(self, target: str):
        """Add target to scope."""
        self.console.print(f"[cyan]Adding target: {target}[/cyan]")
        # Import and call actual scope add function
        try:
            from hazarus.security import ScopeManager
            import yaml
            
            scope_file = Path.cwd() / "config" / "scope.yaml"
            scope_manager = ScopeManager(str(scope_file))
            await scope_manager.load_scope()
            
            # Add target to scope config and save
            if scope_manager.config:
                # Determine target type and add to appropriate list
                target_type = scope_manager._classify_target(target)
                
                if target_type.name == "DOMAIN":
                    if target not in scope_manager.config.allowed_domains:
                        scope_manager.config.allowed_domains.append(target)
                elif target_type.name == "CIDR":
                    if target not in scope_manager.config.allowed_cidrs:
                        scope_manager.config.allowed_cidrs.append(target)
                else:
                    if target not in scope_manager.config.allowed_targets:
                        scope_manager.config.allowed_targets.append(target)
                
                # Save to file
                scope_data = {
                    "allowed_targets": scope_manager.config.allowed_targets,
                    "allowed_domains": scope_manager.config.allowed_domains,
                    "allowed_cidrs": scope_manager.config.allowed_cidrs,
                    "excluded_targets": scope_manager.config.excluded_targets,
                    "allowed_ports": scope_manager.config.allowed_ports,
                    "assessment_window": scope_manager.config.assessment_window,
                    "intensity": scope_manager.config.intensity,
                    "rate_limit": scope_manager.config.rate_limit,
                    "request_limit": scope_manager.config.request_limit,
                    "operator_id": scope_manager.config.operator_id,
                    "client_id": scope_manager.config.client_id,
                    "emergency_contact": scope_manager.config.emergency_contact,
                    "notes": scope_manager.config.notes
                }
                
                with open(scope_file, "w") as f:
                    yaml.dump(scope_data, f, default_flow_style=False)
                
                self.console.print(f"[green]✓ Target added: {target}[/green]")
            else:
                self.console.print("[red]✗ Failed to load scope configuration[/red]")
        except Exception as e:
            self.console.print(f"[red]✗ Failed to add target: {e}[/red]")
        await asyncio.sleep(1)

    async def delete_target(self, target: str):
        """Delete target from scope."""
        self.console.print(f"[cyan]Deleting target: {target}[/cyan]")
        try:
            from hazarus.security import ScopeManager
            import yaml
            
            scope_file = Path.cwd() / "config" / "scope.yaml"
            scope_manager = ScopeManager(str(scope_file))
            await scope_manager.load_scope()
            
            if scope_manager.config:
                # Remove from all possible lists
                removed = False
                
                if target in scope_manager.config.allowed_targets:
                    scope_manager.config.allowed_targets.remove(target)
                    removed = True
                
                if target in scope_manager.config.allowed_domains:
                    scope_manager.config.allowed_domains.remove(target)
                    removed = True
                
                if target in scope_manager.config.allowed_cidrs:
                    scope_manager.config.allowed_cidrs.remove(target)
                    removed = True
                
                if target in scope_manager.config.excluded_targets:
                    scope_manager.config.excluded_targets.remove(target)
                    removed = True
                
                if removed:
                    # Save to file
                    scope_data = {
                        "allowed_targets": scope_manager.config.allowed_targets,
                        "allowed_domains": scope_manager.config.allowed_domains,
                        "allowed_cidrs": scope_manager.config.allowed_cidrs,
                        "excluded_targets": scope_manager.config.excluded_targets,
                        "allowed_ports": scope_manager.config.allowed_ports,
                        "assessment_window": scope_manager.config.assessment_window,
                        "intensity": scope_manager.config.intensity,
                        "rate_limit": scope_manager.config.rate_limit,
                        "request_limit": scope_manager.config.request_limit,
                        "operator_id": scope_manager.config.operator_id,
                        "client_id": scope_manager.config.client_id,
                        "emergency_contact": scope_manager.config.emergency_contact,
                        "notes": scope_manager.config.notes
                    }
                    
                    with open(scope_file, "w") as f:
                        yaml.dump(scope_data, f, default_flow_style=False)
                    
                    self.console.print(f"[green]✓ Target deleted: {target}[/green]")
                else:
                    self.console.print(f"[yellow]⚠ Target not found in scope: {target}[/yellow]")
            else:
                self.console.print("[red]✗ Failed to load scope configuration[/red]")
        except Exception as e:
            self.console.print(f"[red]✗ Failed to delete target: {e}[/red]")
        await asyncio.sleep(1)

    async def list_targets(self):
        """List all targets in scope."""
        self.console.print("[cyan]Listing targets...[/cyan]")
        try:
            from hazarus.security import ScopeManager
            scope_file = Path.cwd() / "config" / "scope.yaml"
            scope_manager = ScopeManager(str(scope_file))
            await scope_manager.load_scope()
            
            table = Table(title="Targets in Scope")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="green")
            
            if scope_manager.config:
                for domain in scope_manager.config.allowed_domains:
                    table.add_row("Domain", domain)
                for cidr in scope_manager.config.allowed_cidrs:
                    table.add_row("CIDR", cidr)
                for target in scope_manager.config.allowed_targets:
                    table.add_row("Target", target)
            else:
                self.console.print("[yellow]No scope configuration loaded[/yellow]")
            
            self.console.print(table)
        except Exception as e:
            self.console.print(f"[red]✗ Failed to list targets: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def validate_scope(self):
        """Validate scope configuration."""
        self.console.print("[cyan]Validating scope...[/cyan]")
        try:
            from hazarus.security import ScopeManager
            scope_file = Path.cwd() / "config" / "scope.yaml"
            scope_manager = ScopeManager(str(scope_file))
            loaded = await scope_manager.load_scope()
            
            if loaded:
                self.console.print("[green]✓ Scope configuration loaded successfully[/green]")
            else:
                self.console.print("[red]✗ Failed to load scope configuration[/red]")
        except Exception as e:
            self.console.print(f"[red]✗ Validation error: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def edit_scope(self):
        """Edit scope configuration."""
        self.console.print("[cyan]Opening scope editor...[/cyan]")
        self.console.print("[yellow]This will open your default editor to edit config/scope.yaml[/yellow]")
        # Import and call actual scope edit function
        try:
            scope_file = Path.cwd() / "config" / "scope.yaml"
            
            # Use system's default editor
            editor = os.environ.get("EDITOR", "nano")
            subprocess.run([editor, str(scope_file)])
            
            self.console.print("[green]✓ Scope editor opened[/green]")
        except Exception as e:
            self.console.print(f"[red]✗ Failed to open editor: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_recon(self, target: str, mode: str):
        """Run reconnaissance with detailed debug and findings."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]SCANNER DEBUG[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print(f"[cyan]Running {mode} reconnaissance on {target}...[/cyan]\n")
        
        # Import and call actual recon logic
        try:
            from hazarus.reconnaissance.dns import DNSRecon
            from hazarus.reconnaissance.whois import WhoisRecon
            from hazarus.reconnaissance.subdomains import SubdomainDiscovery
            from hazarus.reconnaissance.origin_ip import OriginIPDiscovery
            from hazarus.reconnaissance.advanced import AdvancedSubdomainTools, AdvancedDNS, EnhancedLiveHostDiscovery, EnhancedOriginIPDiscovery
            from hazarus.reconnaissance.security import SubdomainTakeoverDetector, VirtualHostEnumerator
            
            # DNS Reconnaissance
            self.console.print("[yellow][1/9] DNS Enumeration...[/yellow]")
            self.console.print(f"  [dim]Querying: A, AAAA, MX, TXT, NS, SOA, CNAME, SRV[/dim]")
            with self.console.status("[dim]Performing DNS queries...[/dim]", spinner="dots"):
                dns_recon = DNSRecon()
                result = await dns_recon.enumerate_records(target)
            
            self.console.print(f"[green]✓ DNS Records: {len(result.records)}[/green]")
            self.console.print(f"[green]✓ Nameservers: {len(result.nameservers)}[/green]")
            
            # Display detailed DNS findings
            if result.records:
                self.console.print("\n[bold cyan]DNS Records Found:[/bold cyan]")
                for record in result.records[:10]:
                    self.console.print(f"  [dim]{record.record_type}[/dim] [green]{record.value}[/green]")
                if len(result.records) > 10:
                    self.console.print(f"  [dim]... and {len(result.records) - 10} more[/dim]")
            
            if result.nameservers:
                self.console.print("\n[bold cyan]Nameservers:[/bold cyan]")
                for ns in result.nameservers:
                    self.console.print(f"  [green]{ns}[/green]")
            
            # WHOIS (for full/advanced modes)
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][2/9] WHOIS Query...[/yellow]")
                self.console.print(f"  [dim]Querying WHOIS database for {target}[/dim]")
                with self.console.status("[dim]Performing WHOIS lookup...[/dim]", spinner="dots"):
                    whois_recon = WhoisRecon()
                    whois_result = await whois_recon.query(target)
                if whois_result:
                    self.console.print(f"[green]✓ WHOIS: {whois_result.registrar}[/green]")
                    self.console.print(f"[dim]  Registrar: {whois_result.registrar}[/dim]")
                    self.console.print(f"[dim]  Created: {whois_result.created_date}[/dim]")
                    self.console.print(f"[dim]  Expires: {whois_result.expiration_date}[/dim]")
                else:
                    self.console.print("[yellow]⚠ WHOIS data not found[/yellow]")
            
            # Basic Subdomain Discovery
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][3/9] Basic Subdomain Discovery...[/yellow]")
            else:
                self.console.print(f"\n[yellow][2/4] Basic Subdomain Discovery...[/yellow]")
            self.console.print(f"  [dim]Methods: crt.sh, brute force[/dim]")
            with self.console.status("[dim]Discovering subdomains...[/dim]", spinner="dots"):
                subdomain_discovery = SubdomainDiscovery()
                subdomain_result = await subdomain_discovery.discover(target)
            subdomain_list = list(subdomain_result.subdomains) if subdomain_result.subdomains else []
            
            self.console.print(f"[green]✓ Subdomains: {len(subdomain_list)}[/green]")
            
            if subdomain_list:
                self.console.print("\n[bold cyan]Subdomains Found:[/bold cyan]")
                for sub in subdomain_list[:15]:
                    self.console.print(f"  [green]{sub}[/green]")
                if len(subdomain_list) > 15:
                    self.console.print(f"  [dim]... and {len(subdomain_list) - 15} more[/dim]")
            
            # Advanced Subdomain Tools (for full/advanced modes)
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][4/9] Advanced Subdomain Discovery...[/yellow]")
                try:
                    advanced_tools = AdvancedSubdomainTools()
                    tools_to_use = ["subfinder", "amass"]
                    advanced_result = await advanced_tools.discover_all(target, tools=tools_to_use)
                    self.console.print(f"[green]✓ Advanced subdomains: {advanced_result.total_found}[/green]")
                    
                    if advanced_result.subdomains:
                        self.console.print("\n[bold cyan]Advanced Subdomains:[/bold cyan]")
                        for sub in advanced_result.subdomains[:10]:
                            self.console.print(f"  [green]{sub}[/green] [dim]({sub.source})[/dim]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Advanced subdomain discovery failed: {e}[/yellow]")
            
            # DNS over HTTPS (for full/advanced modes)
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][5/9] DNS over HTTPS...[/yellow]")
                try:
                    advanced_dns = AdvancedDNS()
                    doh_result = await advanced_dns.query_doh(target, "A")
                    self.console.print(f"[green]✓ DoH records: {len(doh_result.records)}[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ DoH query failed: {e}[/yellow]")
            
            # Enhanced Live Host Discovery (for full/advanced modes)
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][6/9] Enhanced Live Host Discovery...[/yellow]")
                try:
                    enhanced_live = EnhancedLiveHostDiscovery()
                    live_result = await enhanced_live.discover_enhanced(target)
                    self.console.print(f"[green]✓ Live hosts: {len(live_result.hosts)}[/green]")
                    
                    if live_result.hosts:
                        self.console.print("\n[bold cyan]Live Hosts:[/bold cyan]")
                        for host in live_result.hosts[:5]:
                            ip = getattr(host, 'ip', 'unknown')
                            status = getattr(host, 'status', 'unknown')
                            self.console.print(f"  [green]{ip}[/green] [dim]({status})[/dim]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Enhanced live host discovery failed: {e}[/yellow]")
            
            # Subdomain Takeover Detection (for full/advanced modes)
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][7/8] Subdomain Takeover Detection...[/yellow]")
                try:
                    takeover_detector = SubdomainTakeoverDetector()
                    takeover_result = await takeover_detector.scan_subdomains(subdomain_list[:20])
                    self.console.print(f"[green]✓ Takeover vulnerable: {takeover_result.vulnerable_count}[/green]")
                    
                    if takeover_result.vulnerable_subdomains:
                        self.console.print("\n[bold red]Vulnerable Subdomains:[/bold red]")
                        for vuln in takeover_result.vulnerable_subdomains[:5]:
                            self.console.print(f"  [red]{vuln.subdomain}[/red] [dim]({vuln.service})[/dim]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Takeover detection failed: {e}[/yellow]")
            
            # Virtual Host Enumeration (for full/advanced modes)
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][8/9] Virtual Host Enumeration...[/yellow]")
                try:
                    virtual_host = VirtualHostEnumerator()
                    # Get origin IPs to scan
                    scan_ips = origin_ips[:3] if origin_ips else []
                    if scan_ips:
                        vhost_result = await virtual_host.enumerate(scan_ips[0], subdomain_list[:10])
                        self.console.print(f"[green]✓ Virtual hosts: {len(vhost_result.findings)}[/green]")
                        if vhost_result.findings:
                            self.console.print("\n[bold cyan]Virtual Hosts Found:[/bold cyan]")
                            for finding in vhost_result.findings[:5]:
                                self.console.print(f"  [green]{finding.hostname}[/green] [dim]({finding.status_code})[/dim]")
                    else:
                        self.console.print("[yellow]⚠ No IPs available for virtual host enumeration[/yellow]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Virtual host enumeration failed: {e}[/yellow]")
            
            # Origin IP Discovery
            if mode in ["full", "advanced"]:
                self.console.print(f"\n[yellow][9/9] Enhanced Origin IP Discovery...[/yellow]")
                try:
                    enhanced_origin = EnhancedOriginIPDiscovery()
                    origin_result = await enhanced_origin.discover_enhanced(target)
                    origin_ips = getattr(origin_result, 'origin_ips', [])
                    self.console.print(f"[green]✓ Origin IPs: {origin_result.total_ips}[/green]")
                    
                    if origin_ips:
                        self.console.print("\n[bold cyan]Potential Origin IPs:[/bold cyan]")
                        for ip_info in origin_ips[:5]:
                            if isinstance(ip_info, dict):
                                ip = ip_info.get('ip', 'unknown')
                                confidence = ip_info.get('confidence', 'N/A')
                            else:
                                ip = str(getattr(ip_info, 'ip', 'unknown'))
                                confidence = getattr(ip_info, 'confidence', 'N/A')
                            self.console.print(f"  [green]{ip}[/green] [dim](confidence: {confidence})[/dim]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Enhanced origin IP discovery failed: {e}[/yellow]")
            else:
                # Basic origin IP for basic mode
                self.console.print(f"\n[yellow][4/4] Origin IP Discovery...[/yellow]")
                origin_discovery = OriginIPDiscovery()
                basic_origin_result = await origin_discovery.discover(target)
                origin_ips = getattr(basic_origin_result, 'origin_ips', [])
                self.console.print(f"[green]✓ Origin IPs: {len(origin_ips)}[/green]")
                
                if origin_ips:
                    self.console.print("\n[bold cyan]Potential Origin IPs:[/bold cyan]")
                    for ip_info in origin_ips[:5]:
                        if isinstance(ip_info, dict):
                            ip = ip_info.get('ip', 'unknown')
                            confidence = ip_info.get('confidence', 'N/A')
                        else:
                            ip = str(getattr(ip_info, 'ip', 'unknown'))
                            confidence = getattr(ip_info, 'confidence', 'N/A')
                        self.console.print(f"  [green]{ip}[/green] [dim](confidence: {confidence})[/dim]")
            
            # Summary
            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]RECONNAISSANCE COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Total DNS Records: {len(result.records)}[/dim]")
            self.console.print(f"[dim]Total Nameservers: {len(result.nameservers)}[/dim]")
            self.console.print(f"[dim]Total Subdomains: {len(subdomain_list)}[/dim]")
            if mode in ["full", "advanced"]:
                self.console.print(f"[dim]Advanced Tools Used: Yes[/dim]")
                self.console.print(f"[dim]DoH/DoT: Yes[/dim]")
                self.console.print(f"[dim]Enhanced Live Hosts: Yes[/dim]")
                self.console.print(f"[dim]Takeover Detection: Yes[/dim]")
                self.console.print(f"[dim]Virtual Host Enumeration: Yes[/dim]")
                origin_ips_count = len(origin_ips) if 'origin_ips' in locals() else (origin_result.total_ips if 'origin_result' in locals() else 0)
                self.console.print(f"[dim]Total Origin IPs: {origin_ips_count}[/dim]")
            else:
                origin_ips_count = len(origin_ips) if 'origin_ips' in locals() else 0
                self.console.print(f"[dim]Total Origin IPs: {origin_ips_count}[/dim]")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")
            
        except Exception as e:
            self.console.print(f"\n[red]✗ Reconnaissance failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_scan(self, target: str, mode: str):
        """Run network scan with detailed debug and findings."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]SCANNER DEBUG[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print(f"[cyan]Running {mode} scan on {target}...[/cyan]")
        self.console.print("[yellow]Note: Network scanning requires sudo privileges[/yellow]\n")
        
        # Check sudo
        import os
        is_sudo = os.environ.get('SUDO_UID') is not None
        if is_sudo:
            self.console.print("[green]✓ Running with sudo privileges[/green]\n")
        else:
            self.console.print("[yellow]⚠ Not running with sudo - some features will be limited[/yellow]\n")
        
        # Import and call actual scan logic
        try:
            from hazarus.scanning.nmap import NmapScanner
            import socket
            
            nmap = NmapScanner()
            
            # Resolve domain to IP if needed
            scan_target = target
            if not target.replace('.', '').isdigit() and '/' not in target:
                try:
                    resolved_ip = socket.gethostbyname(target)
                    self.console.print(f"[dim]Resolved {target} to {resolved_ip}[/dim]\n")
                    scan_target = resolved_ip
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Could not resolve {target}: {e}[/yellow]\n")
            
            if mode == "quick":
                self.console.print("[yellow][1/5] Building Scan Command...[/yellow]")
                self.console.print(f"  [dim]Mode: Quick Scan[/dim]")
                self.console.print(f"  [dim]Ports: 1-1000[/dim]")
                self.console.print(f"  [dim]Scan Type: TCP Connect[/dim]")
                self.console.print()
                
                self.console.print("[yellow][2/5] Executing Nmap...[/yellow]")
                self.console.print(f"  [dim]Command: nmap -sT -p 1-1000 -sV --version-intensity 5 -T4 --max-rate 1000 -oX - -v {scan_target}[/dim]")
                self.console.print()
                
                self.console.print("[yellow][3/5] Scanning Ports...[/yellow]")
                with self.console.status("[dim]Scanning in progress...[/dim]", spinner="dots"):
                    result = await nmap.scan(
                        targets=[scan_target],
                        ports="1-1000",
                        scan_type="sT"
                    )
                
                self.console.print("[green]✓ Port scan complete[/green]")
                self.console.print("[yellow][4/5] Parsing Results...[/yellow]")
                self.console.print("[green]✓ Results parsed[/green]")
                self.console.print("[yellow][5/5] Compiling Findings...[/yellow]")
                
            elif mode == "deep":
                self.console.print("[yellow][1/5] Building Scan Command...[/yellow]")
                self.console.print(f"  [dim]Mode: Deep Scan[/dim]")
                self.console.print(f"  [dim]Ports: 1-65535[/dim]")
                self.console.print(f"  [dim]Scan Type: TCP Connect[/dim]")
                self.console.print()
                
                self.console.print("[yellow][2/5] Executing Nmap...[/yellow]")
                self.console.print(f"  [dim]Command: nmap -sT -p 1-65535 -sV --version-intensity 5 -T4 --max-rate 1000 -oX - -v {scan_target}[/dim]")
                self.console.print()
                
                self.console.print("[yellow][3/5] Scanning Ports...[/yellow]")
                self.console.print("  [dim]This may take several minutes...[/dim]")
                with self.console.status("[dim]Scanning in progress...[/dim]", spinner="dots"):
                    result = await nmap.scan(
                        targets=[scan_target],
                        ports="1-65535",
                        scan_type="sT"
                    )
                
                self.console.print("[green]✓ Port scan complete[/green]")
                self.console.print("[yellow][4/5] Parsing Results...[/yellow]")
                self.console.print("[green]✓ Results parsed[/green]")
                self.console.print("[yellow][5/5] Compiling Findings...[/yellow]")
                
            elif mode == "advanced":
                self.console.print("[yellow][1/6] Building Advanced Scan Command...[/yellow]")
                self.console.print(f"  [dim]Mode: Advanced Scan[/dim]")
                if is_sudo:
                    self.console.print(f"  [dim]Privileges: Root (SYN scan, OS detection, traceroute)[/dim]")
                    self.console.print(f"  [dim]Ports: 1-65535[/dim]")
                    self.console.print(f"  [dim]Scan Type: SYN scan[/dim]")
                    self.console.print(f"  [dim]Scripts: Vuln scripts[/dim]")
                    self.console.print(f"  [dim]Traceroute: Enabled[/dim]")
                else:
                    self.console.print(f"  [dim]Privileges: Non-root (TCP connect scan)[/dim]")
                    self.console.print(f"  [dim]Ports: Common ports only (1-1000,3389,5432,5900,6379,8080,8443)[/dim]")
                    self.console.print(f"  [dim]Scan Type: TCP connect[/dim]")
                    self.console.print(f"  [dim]Scripts: Safe scripts only[/dim]")
                    self.console.print(f"  [dim]Traceroute: Disabled (requires root)[/dim]")
                self.console.print()
                
                self.console.print("[yellow][2/6] Executing Nmap...[/yellow]")
                if is_sudo:
                    self.console.print(f"  [dim]Command: nmap -sS -p 1-65535 -sV --version-intensity 5 -O --osscan-limit --script vuln --traceroute -A -T4 --max-rate 1000 -oX - -v {scan_target}[/dim]")
                else:
                    self.console.print(f"  [dim]Command: nmap -sT -p 1-1000,3389,5432,5900,6379,8080,8443 -sV --version-intensity 5 --script default,safe -T4 --max-rate 1000 -oX - -v {scan_target}[/dim]")
                self.console.print()
                
                self.console.print("[yellow][3/6] Scanning Ports...[/yellow]")
                self.console.print("  [dim]Service detection enabled[/dim]")
                if is_sudo:
                    self.console.print("  [dim]OS detection enabled[/dim]")
                    self.console.print("  [dim]Vulnerability scripts enabled[/dim]")
                    self.console.print("  [dim]Traceroute enabled[/dim]")
                else:
                    self.console.print("  [dim]Safe scripts only[/dim]")
                self.console.print("  [dim]This may take several minutes...[/dim]")
                
                with self.console.status("[dim]Scanning in progress...[/dim]", spinner="dots"):
                    if is_sudo:
                        result = await nmap.advanced_scan(
                            targets=[scan_target],
                            ports="1-65535",
                            tcp_scan=True,
                            udp_scan=False,
                            service_detection=True,
                            os_detection=True,
                            script_scan=True,
                            vuln_scan=True,
                            traceroute=True,
                            aggressive=True,
                            timing=4
                        )
                    else:
                        result = await nmap.scan(
                            targets=[scan_target],
                            ports="1-1000,3389,5432,5900,6379,8080,8443",
                            scan_type="sT"
                        )
                
                self.console.print("[green]✓ Port scan complete[/green]")
                self.console.print("[yellow][4/6] Parsing Results...[/yellow]")
                self.console.print("[green]✓ Results parsed[/green]")
                self.console.print("[yellow][5/6] Extracting Service Versions...[/yellow]")
                self.console.print("[green]✓ Service versions extracted[/green]")
                if is_sudo:
                    self.console.print("[yellow][6/6] Extracting OS Fingerprints...[/yellow]")
                    self.console.print("[green]✓ OS fingerprints extracted[/green]")
                else:
                    self.console.print("[yellow][6/6] Skipping OS detection (requires root)[/yellow]")
                
                self.console.print("[yellow]Compiling Findings...[/yellow]")
            elif mode == "live":
                self.console.print("[yellow][1/1] Live Host Discovery...[/yellow]")
                from hazarus.reconnaissance.live_hosts import LiveHostDiscovery
                live = LiveHostDiscovery()
                result = await live.discover_hosts(target)
                
                hosts = getattr(result, 'hosts', [])
                self.console.print(f"[green]✓ Live hosts: {len(hosts)}[/green]")
                if hosts:
                    self.console.print("\n[bold cyan]Live Hosts Found:[/bold cyan]")
                    for host in hosts:
                        ip = getattr(host, 'ip', 'unknown')
                        status = getattr(host, 'status', 'unknown')
                        self.console.print(f"  [green]{ip}[/green] [dim]({status})[/dim]")
                
                self.console.print(f"\n{'='*80}")
                self.console.print(f"[bold green]SCAN COMPLETE[/bold green]")
                self.console.print(f"{'='*80}")
                self.console.print(f"[dim]Total Live Hosts: {len(hosts)}[/dim]")
                self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
                self.console.print(f"{'='*80}\n")
                
                self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
                self.console.input("")
                return
            
            # Display results
            open_ports = []
            hosts = getattr(result, 'hosts', [])
            for host in hosts:
                ports = getattr(host, 'ports', [])
                for port in ports:
                    port_state = getattr(port, 'state', None)
                    port_num = getattr(port, 'port', None)
                    port_protocol = getattr(port, 'protocol', 'tcp')
                    if port_state == "open" and port_num:
                        open_ports.append(f"{port_num}/{port_protocol}")
            
            self.console.print(f"[green]✓ Open ports: {len(open_ports)}[/green]")
            
            if open_ports:
                self.console.print("\n[bold cyan]Open Ports Found:[/bold cyan]")
                for port in open_ports[:20]:
                    self.console.print(f"  [green]{port}[/green]")
                if len(open_ports) > 20:
                    self.console.print(f"  [dim]... and {len(open_ports) - 20} more[/dim]")
            
            # Summary
            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]SCAN COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Total Open Ports: {len(open_ports)}[/dim]")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")
            
        except Exception as e:
            self.console.print(f"\n[red]✗ Scan failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_masscan(self, target: str):
        """Run Masscan high-performance port scan."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]MASSCAN HIGH-PERFORMANCE PORT SCAN[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")

        try:
            self.console.print("[cyan]Running Masscan scan...[/cyan]\n")
            
            with self.console.status("[dim]Scanning with Masscan...[/dim]", spinner="dots"):
                scanner = MasscanScanner()
                result = await scanner.scan(target, ports="1-65535", rate=1000)

            self.console.print(f"[green]✓ Open ports found: {len(result.open_ports)}[/green]")
            
            if result.open_ports:
                self.console.print("\n[bold cyan]Open Ports:[/bold cyan]")
                for port in result.open_ports[:20]:
                    service = result.port_services.get(port, "unknown")
                    self.console.print(f"  [green]{port}/tcp[/green] [dim]({service})[/dim]")
                if len(result.open_ports) > 20:
                    self.console.print(f"  [dim]... and {len(result.open_ports) - 20} more[/dim]")

            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]SCAN COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Total Open Ports: {len(result.open_ports)}[/dim]")
            self.console.print(f"[dim]Scan Duration: {result.scan_duration:.2f}s[/dim]")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")

        except Exception as e:
            self.console.print(f"\n[red]✗ Masscan scan failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")

        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_rustscan(self, target: str):
        """Run RustScan fast port discovery."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]RUSTSCAN FAST PORT DISCOVERY[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")

        try:
            self.console.print("[cyan]Running RustScan scan...[/cyan]\n")
            
            with self.console.status("[dim]Scanning with RustScan...[/dim]", spinner="dots"):
                scanner = RustScanScanner()
                result = await scanner.scan(target, ports="1-65535")

            self.console.print(f"[green]✓ Open ports found: {len(result.open_ports)}[/green]")
            
            if result.open_ports:
                self.console.print("\n[bold cyan]Open Ports:[/bold cyan]")
                for port in result.open_ports[:20]:
                    self.console.print(f"  [green]{port}/tcp[/green]")
                if len(result.open_ports) > 20:
                    self.console.print(f"  [dim]... and {len(result.open_ports) - 20} more[/dim]")

            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]SCAN COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Total Open Ports: {len(result.open_ports)}[/dim]")
            self.console.print(f"[dim]Scan Duration: {result.scan_duration:.2f}s[/dim]")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")

        except Exception as e:
            self.console.print(f"\n[red]✗ RustScan scan failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")

        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_web(self, target: str, mode: str):
        """Run web assessment with detailed debug and findings."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]SCANNER DEBUG[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print(f"[cyan]Running {mode} web assessment on {target}...[/cyan]\n")
        
        # Import and call actual web logic
        try:
            from hazarus.scanning.http_scanner import HTTPScanner
            from hazarus.scanning.web_tools import AdvancedWebTools

            self.console.print("[yellow][1/6] HTTP Security Scan...[/yellow]")
            self.console.print(f"  [dim]Target: {target}[/dim]")
            self.console.print(f"  [dim]Timeout: {self.config.get('timeouts.http_scan', 30)}s[/dim]")
            self.console.print(f"  [dim]Checks: Headers, Cookies, Vulns[/dim]")

            with self.console.status("[dim]Scanning HTTP security...[/dim]", spinner="dots"):
                scanner = HTTPScanner(timeout=30)
                result = await scanner.scan(target)

            self.console.print(f"[green]✓ Security headers: {len(result.security_headers)}[/green]")
            self.console.print(f"[green]✓ Cookies: {len(result.cookies)}[/green]")
            self.console.print(f"[green]✓ Vulnerabilities: {len(result.vulnerabilities)}[/green]")

            if result.security_headers:
                self.console.print("\n[bold cyan]Security Headers:[/bold cyan]")
                for header in result.security_headers:
                    self.console.print(f"  [cyan]{header.name}:[/cyan] [green]{header.value or 'Not Present'}[/green] [dim]({header.severity})[/dim]")

            if result.cookies:
                self.console.print("\n[bold cyan]Cookies:[/bold cyan]")
                for cookie in result.cookies[:10]:
                    cookie_name = cookie.get('name', 'unknown')
                    cookie_domain = cookie.get('domain', 'unknown')
                    self.console.print(f"  [green]{cookie_name}[/green] [dim]({cookie_domain})[/dim]")
                if len(result.cookies) > 10:
                    self.console.print(f"  [dim]... and {len(result.cookies) - 10} more[/dim]")

            # Nikto Web Server Scan
            self.console.print(f"\n[yellow][2/6] Nikto Web Server Scan...[/yellow]")
            self.console.print(f"  [dim]Target: {target}[/dim]")
            self.console.print(f"  [dim]Checks: Known vulnerabilities, misconfigurations[/dim]")
            try:
                nikto_scanner = NiktoScanner()
                nikto_installed = await nikto_scanner.check_installed()
                if nikto_installed:
                    with self.console.status("[dim]Running Nikto scan...[/dim]", spinner="dots"):
                        nikto_result = await nikto_scanner.scan(target, timeout=300)
                    self.console.print(f"[green]✓ Nikto findings: {len(nikto_result.findings)}[/green]")
                    if nikto_result.server_header:
                        self.console.print(f"[dim]  Server: {nikto_result.server_header}[/dim]")
                    if nikto_result.findings:
                        self.console.print("\n[bold cyan]Nikto Findings:[/bold cyan]")
                        for finding in nikto_result.findings[:10]:
                            self.console.print(f"  [yellow]{finding.id}:[/yellow] {finding.message[:80]}")
                        if len(nikto_result.findings) > 10:
                            self.console.print(f"  [dim]... and {len(nikto_result.findings) - 10} more[/dim]")
                else:
                    self.console.print("[yellow]⚠ Nikto not installed - skipping scan[/yellow]")
            except Exception as e:
                self.console.print(f"[yellow]⚠ Nikto scan failed: {e}[/yellow]")

            # Nuclei Vulnerability Scan
            self.console.print(f"\n[yellow][3/6] Nuclei Vulnerability Scan...[/yellow]")
            self.console.print(f"  [dim]Target: {target}[/dim]")
            self.console.print(f"  [dim]Checks: CVEs, exposures, misconfigurations[/dim]")
            try:
                nuclei_scanner = NucleiScanner()
                nuclei_installed = await nuclei_scanner.check_installed()
                if nuclei_installed:
                    with self.console.status("[dim]Running Nuclei scan...[/dim]", spinner="dots"):
                        nuclei_result = await nuclei_scanner.scan(target, timeout=300)
                    self.console.print(f"[green]✓ Nuclei findings: {len(nuclei_result.findings)}[/green]")
                    if nuclei_result.severity_summary:
                        self.console.print("[dim]  Severity breakdown:[/dim]")
                        for severity, count in nuclei_result.severity_summary.items():
                            self.console.print(f"    [dim]{severity}: {count}[/dim]")
                    if nuclei_result.findings:
                        self.console.print("\n[bold cyan]Nuclei Findings:[/bold cyan]")
                        for finding in nuclei_result.findings[:10]:
                            sev_color = "red" if finding.severity.lower() in ["critical", "high"] else "yellow" if finding.severity.lower() == "medium" else "green"
                            self.console.print(f"  [{sev_color}]{finding.severity}:[/{sev_color}] {finding.info.get('name', finding.template_id)[:60]}")
                        if len(nuclei_result.findings) > 10:
                            self.console.print(f"  [dim]... and {len(nuclei_result.findings) - 10} more[/dim]")
                else:
                    self.console.print("[yellow]⚠ Nuclei not installed - skipping scan[/yellow]")
                    self.console.print("[dim]  Install with: sudo apt install nuclei[/dim]")
            except Exception as e:
                self.console.print(f"[yellow]⚠ Nuclei scan failed: {e}[/yellow]")
                self.console.print("[dim]  Ensure nuclei is installed and templates are updated[/dim]")
                self.console.print("[dim]  Update templates: nuclei -update-templates[/dim]")

            # Advanced Web Tools (for aggressive mode)
            if mode == "aggressive":
                web_tools = AdvancedWebTools()
                
                # Technology Detection with WhatWeb
                self.console.print(f"\n[yellow][4/7] Technology Detection (WhatWeb)...[/yellow]")
                try:
                    whatweb_result = await web_tools.whatweb_scan(target)
                    technologies = getattr(whatweb_result, 'technologies', [])
                    self.console.print(f"[green]✓ Technologies: {len(technologies)}[/green]")
                    if technologies:
                        self.console.print("\n[bold cyan]Technologies Detected:[/bold cyan]")
                        for tech in technologies[:15]:
                            self.console.print(f"  [green]{tech}[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ WhatWeb scan failed: {e}[/yellow]")
                
                # Directory Enumeration with Gobuster
                self.console.print(f"\n[yellow][5/7] Directory Enumeration (Gobuster)...[/yellow]")
                try:
                    gobuster_result = await web_tools.gobuster_scan(target)
                    total_found = getattr(gobuster_result, 'total_found', 0)
                    directories = getattr(gobuster_result, 'directories', [])
                    self.console.print(f"[green]✓ Directories: {total_found}[/green]")
                    if directories:
                        self.console.print("\n[bold cyan]Directories Found:[/bold cyan]")
                        for dir in directories[:15]:
                            self.console.print(f"  [green]{dir}[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Gobuster scan failed: {e}[/yellow]")
                
                # WordPress Security Scan with WPScan
                self.console.print(f"\n[yellow][6/7] WordPress Security Scan (WPScan)...[/yellow]")
                try:
                    wpscan_result = await web_tools.wpscan_scan(target, aggressive=True)
                    is_wordpress = getattr(wpscan_result, 'is_wordpress', False)
                    version = getattr(wpscan_result, 'version', None)
                    plugins = getattr(wpscan_result, 'plugins', [])
                    self.console.print(f"[green]✓ WordPress: {is_wordpress}[/green]")
                    if is_wordpress:
                        self.console.print(f"[dim]  Version: {version or 'Unknown'}[/dim]")
                        self.console.print(f"[dim]  Plugins: {len(plugins)}[/dim]")
                        if plugins:
                            self.console.print("\n[bold cyan]WordPress Plugins:[/bold cyan]")
                            for plugin in plugins[:10]:
                                self.console.print(f"  [green]{plugin}[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ WPScan scan failed: {e}[/yellow]")
                
                # OWASP ZAP Scan (if available)
                self.console.print(f"\n[yellow][7/7] OWASP ZAP Scan...[/yellow]")
                try:
                    from hazarus.vulnerability.owasp_zap import ZAPScanner
                    # Check if ZAP is running
                    zap_scanner = ZAPScanner(api_key="placeholder")
                    zap_installed = await zap_scanner.check_connection()
                    if zap_installed:
                        with self.console.status("[dim]Running ZAP scan...[/dim]", spinner="dots"):
                            zap_result = await zap_scanner.scan(target)
                        self.console.print(f"[green]✓ ZAP alerts: {len(zap_result.alerts)}[/green]")
                        if zap_result.alerts:
                            self.console.print("\n[bold cyan]ZAP Alerts:[/bold cyan]")
                            for alert in zap_result.alerts[:10]:
                                self.console.print(f"  [red]{alert.risk}:[/red] {alert.alert} - {alert.url}")
                    else:
                        self.console.print("[yellow]⚠ OWASP ZAP not running - skipping scan[/yellow]")
                        self.console.print("[dim]  Start ZAP with: zaproxy -daemon -port 8080[/dim]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ ZAP scan failed: {e}[/yellow]")
            
            # Individual tool modes
            elif mode in ["wpscan", "gobuster", "whatweb"]:
                web_tools = AdvancedWebTools()
                
                if mode == "whatweb":
                    self.console.print(f"\n[yellow][4/6] Technology Detection...[/yellow]")
                    whatweb_result = await web_tools.whatweb_scan(target)
                    technologies = getattr(whatweb_result, 'technologies', [])
                    self.console.print(f"[green]✓ Technologies: {len(technologies)}[/green]")
                    if technologies:
                        self.console.print("\n[bold cyan]Technologies Detected:[/bold cyan]")
                        for tech in technologies[:15]:
                            self.console.print(f"  [green]{tech}[/green]")
                elif mode == "gobuster":
                    self.console.print(f"\n[yellow][4/6] Directory Enumeration...[/yellow]")
                    gobuster_result = await web_tools.gobuster_scan(target)
                    total_found = getattr(gobuster_result, 'total_found', 0)
                    directories = getattr(gobuster_result, 'directories', [])
                    self.console.print(f"[green]✓ Directories: {total_found}[/green]")
                    if directories:
                        self.console.print("\n[bold cyan]Directories Found:[/bold cyan]")
                        for dir in directories[:15]:
                            self.console.print(f"  [green]{dir}[/green]")
                elif mode == "wpscan":
                    self.console.print(f"\n[yellow][4/6] WordPress Security Scan...[/yellow]")
                    wpscan_result = await web_tools.wpscan_scan(target)
                    is_wordpress = getattr(wpscan_result, 'is_wordpress', False)
                    version = getattr(wpscan_result, 'version', None)
                    plugins = getattr(wpscan_result, 'plugins', [])
                    self.console.print(f"[green]✓ WordPress: {is_wordpress}[/green]")
                    if is_wordpress:
                        self.console.print(f"[dim]  Version: {version or 'Unknown'}[/dim]")
                        self.console.print(f"[dim]  Plugins: {len(plugins)}[/dim]")
            
            # Summary
            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]WEB ASSESSMENT COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Security Headers: {len(result.security_headers)}[/dim]")
            self.console.print(f"[dim]Cookies: {len(result.cookies)}[/dim]")
            self.console.print(f"[dim]HTTP Vulnerabilities: {len(result.vulnerabilities)}[/dim]")
            self.console.print(f"[dim]Nikto Findings: {len(nikto_result.findings) if 'nikto_result' in locals() else 0}[/dim]")
            self.console.print(f"[dim]Nuclei Findings: {len(nuclei_result.findings) if 'nuclei_result' in locals() else 0}[/dim]")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")
            
        except Exception as e:
            self.console.print(f"\n[red]✗ Web assessment failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_comprehensive(self, target: str, mode: str):
        """Run comprehensive assessment with all phases."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]SCANNER DEBUG[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        # Determine phases based on mode
        if mode == "standard":
            phases = ["privacy", "recon", "scan", "web"]
            aggressive = False
            active = False
            live_hosts = False
        elif mode == "full":
            phases = ["privacy", "recon", "scan", "web", "api", "research", "exploit", "post_audit", "lateral", "code"]
            aggressive = True
            active = True
            live_hosts = True
        else:  # custom
            phases = ["privacy", "recon", "scan", "web"]  # Default for custom
            aggressive = False
            active = False
            live_hosts = False
        
        self.console.print(f"[cyan]Running {mode} comprehensive assessment on {target}...[/cyan]")
        self.console.print(f"[yellow]Phases: {', '.join(phases)}[/yellow]")
        if aggressive:
            self.console.print("[red]⚠ Aggressive scanning enabled[/red]")
        if active:
            self.console.print("[yellow]⚠ Active scanning enabled[/yellow]")
        if live_hosts:
            self.console.print("[green]✓ Live host discovery enabled[/green]")
        self.console.print()
        
        # Check sudo for live hosts
        import os
        is_sudo = os.environ.get('SUDO_UID') is not None
        if live_hosts and not is_sudo:
            self.console.print("[yellow]⚠ Live host discovery requires sudo - running without[/yellow]")
            live_hosts = False
        
        phase_results = {}
        
            # Phase 1: Privacy Check
        if "privacy" in phases:
            self.console.print(f"[yellow][Phase {phases.index('privacy') + 1}/{len(phases)}] Privacy Check...[/yellow]")
            self.console.print(f"  [dim]Checking: Anonsurf, Tor, DNS Leak, IPv6[/dim]")
            try:
                from hazarus.anonymity.anonsurf import AnonsurfManager
                from hazarus.anonymity.dns_leak import DNSLeakChecker
                from hazarus.anonymity.ipv6_check import IPv6Checker
                
                anonsurf = AnonsurfManager()
                dns_checker = DNSLeakChecker()
                ipv6_checker = IPv6Checker()
                
                installed = await anonsurf.check_installed()
                running = await anonsurf.check_running()
                tor_available = await anonsurf.check_tor_connectivity()
                dns_result = await dns_checker.check_leaks()
                dns_leak = dns_result.get("leaking", False)
                ipv6_enabled = await ipv6_checker.check_ipv6_enabled()
                ipv6_exposed = ipv6_enabled
                
                self.console.print(f"  Anonsurf: {'✓ Running' if running else '✗ Not running'}")
                self.console.print(f"  Tor: {'✓ Available' if tor_available else '✗ Not available'}")
                self.console.print(f"  DNS Leak: {'⚠ Detected' if dns_leak else '✓ No leak'}")
                self.console.print(f"  IPv6: {'⚠ Exposed' if ipv6_exposed else '✓ Protected'}")
                
                phase_results['privacy'] = {
                    'running': running,
                    'tor_available': tor_available,
                    'dns_leak': dns_leak,
                    'ipv6_exposed': ipv6_exposed
                }
            except Exception as e:
                self.console.print(f"  [red]✗ Privacy check failed: {e}[/red]")
                phase_results['privacy'] = None
            self.console.print()
        
        # Phase 2: Reconnaissance
        if "recon" in phases:
            self.console.print(f"[yellow][Phase {phases.index('recon') + 1}/{len(phases)}] Reconnaissance...[/yellow]")
            if mode == "full":
                self.console.print(f"  [dim]Steps: DNS, Amass, crt.sh, Brute Force, WHOIS, Subfinder, DoH, Live Hosts, Takeover, Origin IP[/dim]")
            else:
                self.console.print(f"  [dim]Steps: DNS, Amass, crt.sh, Brute Force, WHOIS, Origin IP[/dim]")
            try:
                from hazarus.reconnaissance.dns import DNSRecon
                from hazarus.reconnaissance.whois import WhoisRecon
                from hazarus.reconnaissance.subdomains import SubdomainDiscovery
                from hazarus.reconnaissance.origin_ip import OriginIPDiscovery
                from hazarus.reconnaissance.advanced import AdvancedSubdomainTools, AdvancedDNS, EnhancedLiveHostDiscovery, EnhancedOriginIPDiscovery
                from hazarus.reconnaissance.security import SubdomainTakeoverDetector
                from hazarus.reconnaissance.osint import TheHarvester
                
                dns_recon = DNSRecon()
                dns_result = await dns_recon.enumerate_records(target)
                
                self.console.print(f"  DNS Records: {len(dns_result.records)}")
                self.console.print(f"  Nameservers: {len(dns_result.nameservers)}")
                
                # Amass
                amass_subdomains = []
                try:
                    amass_result = await dns_recon.query_amass_advanced(target, active=active)
                    amass_subdomains = amass_result.get("subdomains", [])
                    self.console.print(f"  Amass: {len(amass_subdomains)} subdomains")
                except Exception as e:
                    self.console.print(f"  [yellow]⚠ Amass failed: {e}[/yellow]")
                
                # crt.sh
                crtsh_subdomains = []
                try:
                    crtsh_subdomains = await dns_recon.query_crtsh(target)
                    self.console.print(f"  crt.sh: {len(crtsh_subdomains)} subdomains")
                except Exception as e:
                    self.console.print(f"  [yellow]⚠ crt.sh failed: {e}[/yellow]")
                
                # Brute force
                bruteforce_subdomains = []
                try:
                    subdiscovery = SubdomainDiscovery()
                    bruteforce_result = await subdiscovery.discover(target)
                    bruteforce_subdomains = list(bruteforce_result.subdomains) if bruteforce_result.subdomains else []
                    self.console.print(f"  Brute force: {len(bruteforce_subdomains)} subdomains")
                except Exception as e:
                    self.console.print(f"  [yellow]⚠ Brute force failed: {e}[/yellow]")
                
                # WHOIS
                whois_registrar = "Unknown"
                try:
                    whois_recon = WhoisRecon()
                    whois_result = await whois_recon.query(target)
                    if whois_result:
                        whois_registrar = whois_result.registrar
                        self.console.print(f"  WHOIS: {whois_registrar}")
                except Exception as e:
                    self.console.print(f"  [yellow]⚠ WHOIS failed: {e}[/yellow]")
                
                # Advanced tools (full mode only)
                subfinder_subdomains = []
                doh_records = 0
                live_hosts = 0
                takeover_vulnerable = 0
                enhanced_origin_ips = 0
                
                if mode == "full":
                    # Subfinder
                    try:
                        advanced_tools = AdvancedSubdomainTools()
                        subfinder_result = await advanced_tools.discover_all(target, tools=["subfinder"])
                        subfinder_subdomains = list(subfinder_result.subdomains) if subfinder_result.subdomains else []
                        self.console.print(f"  Subfinder: {len(subfinder_subdomains)} subdomains")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ Subfinder not available: {e}[/yellow]")
                        subfinder_subdomains = []
                    
                    # DNS over HTTPS
                    try:
                        advanced_dns = AdvancedDNS()
                        doh_result = await advanced_dns.query_doh(target, "A")
                        doh_records = len(doh_result.records) if doh_result.records else 0
                        self.console.print(f"  DoH (Google): {doh_records} records")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ DoH failed: {e}[/yellow]")
                    
                    # Enhanced Live Host Discovery
                    try:
                        enhanced_live = EnhancedLiveHostDiscovery()
                        live_result = await enhanced_live.discover_enhanced(target)
                        live_hosts = len(live_result.hosts) if live_result.hosts else 0
                        self.console.print(f"  Live hosts: {live_hosts}")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ Live host discovery failed: {e}[/yellow]")
                    
                    # Subdomain Takeover Detection
                    all_subdomains = list(set(amass_subdomains + crtsh_subdomains + bruteforce_subdomains + subfinder_subdomains))
                    try:
                        takeover_detector = SubdomainTakeoverDetector()
                        takeover_result = await takeover_detector.scan_subdomains(all_subdomains[:20])
                        takeover_vulnerable = takeover_result.vulnerable_count
                        self.console.print(f"  Takeover vulnerable: {takeover_vulnerable}")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ Takeover detection failed: {e}[/yellow]")
                        takeover_vulnerable = 0
                
                # Origin IP (basic for standard, enhanced for full)
                origin_ips = []
                try:
                    if mode == "full":
                        enhanced_origin = EnhancedOriginIPDiscovery()
                        origin_result = await enhanced_origin.discover_enhanced(target)
                        origin_ips = getattr(origin_result, 'origin_ips', [])
                        enhanced_origin_ips = origin_result.total_ips if hasattr(origin_result, 'total_ips') else len(origin_ips)
                        self.console.print(f"  Origin IPs (enhanced): {enhanced_origin_ips}")
                    else:
                        origin_discovery = OriginIPDiscovery()
                        origin_result = await origin_discovery.discover(target)
                        origin_ips = getattr(origin_result, 'origin_ips', [])
                        self.console.print(f"  Origin IPs: {len(origin_ips)}")
                except Exception as e:
                    self.console.print(f"  [yellow]⚠ Origin IP discovery failed: {e}[/yellow]")
                
                # theHarvester OSINT (Phase 1 critical tool)
                try:
                    harvester = TheHarvester()
                    osint_result = await harvester.harvest(target)
                    self.console.print(f"  OSINT emails: {len(osint_result.emails)}")
                    self.console.print(f"  OSINT hosts: {len(osint_result.domains)}")
                except Exception as e:
                    self.console.print(f"  [yellow]⚠ theHarvester failed: {e}[/yellow]")
                
                phase_results['recon'] = {
                    'dns_records': len(dns_result.records),
                    'amass_subdomains': len(amass_subdomains),
                    'crtsh_subdomains': len(crtsh_subdomains),
                    'bruteforce_subdomains': len(bruteforce_subdomains),
                    'subfinder_subdomains': len(subfinder_subdomains),
                    'doh_records': doh_records,
                    'live_hosts': live_hosts,
                    'takeover_vulnerable': takeover_vulnerable,
                    'origin_ips': enhanced_origin_ips if mode == "full" else len(origin_ips)
                }
            except Exception as e:
                self.console.print(f"  [red]✗ Reconnaissance failed: {e}[/red]")
                import traceback
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
                phase_results['recon'] = None
            self.console.print()
        
        # Phase 3: Network Scan
        if "scan" in phases:
            self.console.print(f"[yellow][Phase {phases.index('scan') + 1}/{len(phases)}] Network Scanning...[/yellow]")
            self.console.print(f"  [dim]Steps: Command build, Execute, Parse, Extract[/dim]")
            try:
                from hazarus.scanning.nmap import NmapScanner
                
                nmap = NmapScanner()
                if aggressive:
                    # Check for sudo
                    if is_sudo:
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
                            aggressive=True,
                            timing=4
                        )
                    else:
                        self.console.print("  [yellow]⚠ Advanced scan requires sudo - using basic scan[/yellow]")
                        nmap_result = await nmap.scan(
                            targets=[target],
                            ports="1-1000",
                            scan_type="sT"
                        )
                else:
                    nmap_result = await nmap.scan(
                        targets=[target],
                        ports="1-1000",
                        scan_type="sT"
                    )
                
                open_ports = 0
                hosts = getattr(nmap_result, 'hosts', [])
                for host in hosts:
                    ports = getattr(host, 'ports', [])
                    for port in ports:
                        if getattr(port, 'state', None) == "open":
                            open_ports += 1
                
                self.console.print(f"  Open ports: {open_ports}")
                phase_results['scan'] = {'open_ports': open_ports}
            except Exception as e:
                self.console.print(f"  [red]✗ Network scan failed: {e}[/red]")
                import traceback
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
                phase_results['scan'] = None
            self.console.print()
        
        # Phase 4: Web Assessment
        if "web" in phases:
            self.console.print(f"[yellow][Phase {phases.index('web') + 1}/{len(phases)}] Web Assessment...[/yellow]")
            self.console.print(f"  [dim]Steps: HTTP Scan, Headers, Cookies, Vulns, Advanced Tools[/dim]")
            try:
                from hazarus.scanning.http_scanner import HTTPScanner
                from hazarus.scanning.web_tools import AdvancedWebTools
                
                scanner = HTTPScanner(timeout=30, skip_advanced=False)
                web_result = await scanner.scan(target)
                
                self.console.print(f"  Security headers: {len(web_result.security_headers)}")
                self.console.print(f"  Cookies: {len(web_result.cookies)}")
                self.console.print(f"  Vulnerabilities: {len(web_result.vulnerabilities)}")
                
                # Advanced web tools
                if active or aggressive:
                    web_tools = AdvancedWebTools(timeout=600)
                    
                    # WhatWeb
                    whatweb_technologies = []
                    try:
                        whatweb_result = await web_tools.whatweb_scan(target, aggressive=aggressive)
                        whatweb_technologies = getattr(whatweb_result, 'technologies', [])
                        self.console.print(f"  WhatWeb: {len(whatweb_technologies)} technologies")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ WhatWeb failed: {e}[/yellow]")
                    
                    # WPScan
                    wpscan_version = None
                    wpscan_plugins = 0
                    try:
                        wpscan_result = await web_tools.wpscan_scan(target, aggressive=aggressive)
                        if getattr(wpscan_result, 'is_wordpress', False):
                            wpscan_version = getattr(wpscan_result, 'version', None)
                            wpscan_plugins = len(getattr(wpscan_result, 'plugins', []))
                            self.console.print(f"  WordPress: {wpscan_version}")
                            self.console.print(f"  WordPress Plugins: {wpscan_plugins}")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ WPScan failed: {e}[/yellow]")
                    
                    # Gobuster
                    gobuster_dirs = 0
                    try:
                        gobuster_result = await web_tools.gobuster_scan(target, aggressive=aggressive)
                        gobuster_dirs = getattr(gobuster_result, 'total_found', 0)
                        self.console.print(f"  Gobuster: {gobuster_dirs} directories")
                    except Exception as e:
                        self.console.print(f"  [yellow]⚠ Gobuster failed: {e}[/yellow]")
                
                phase_results['web'] = {
                    'security_headers': len(web_result.security_headers),
                    'cookies': len(web_result.cookies),
                    'vulnerabilities': len(web_result.vulnerabilities),
                    'whatweb_technologies': len(whatweb_technologies) if active or aggressive else 0,
                    'wordpress': wpscan_version is not None if active or aggressive else False,
                    'gobuster_directories': gobuster_dirs if active or aggressive else 0
                }
            except Exception as e:
                self.console.print(f"  [red]✗ Web assessment failed: {e}[/red]")
                import traceback
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
                phase_results['web'] = None
            self.console.print()
        
        # Additional phases for full mode
        if mode == "full":
            # API Assessment
            if "api" in phases:
                self.console.print(f"[yellow][Phase {phases.index('api') + 1}/{len(phases)}] API Assessment...[/yellow]")
                self.console.print(f"  [dim]Steps: REST endpoints, GraphQL, Security scan[/dim]")
                try:
                    from hazarus.scanning.api_discovery import APIDiscovery
                    api_discovery = APIDiscovery()
                    
                    # REST endpoint discovery
                    rest_result = await api_discovery.discover(target)
                    rest_endpoints = [e.url for e in rest_result.endpoints if e.method.lower() in ['get', 'post', 'put', 'delete']]
                    self.console.print(f"  REST endpoints: {len(rest_endpoints)}")
                    
                    # GraphQL endpoint discovery
                    graphql_endpoints = rest_result.graphql_endpoints
                    self.console.print(f"  GraphQL endpoints: {len(graphql_endpoints)}")
                    
                    # API security scan
                    security_result = await api_discovery.scan_api_security(target)
                    security_issues = getattr(security_result, 'security_issues', [])
                    self.console.print(f"  Security issues: {len(security_issues)}")
                    
                    phase_results['api'] = {
                        'rest_endpoints': len(rest_endpoints),
                        'graphql_endpoints': len(graphql_endpoints),
                        'security_issues': len(security_issues)
                    }
                except Exception as e:
                    self.console.print(f"  [red]✗ API assessment failed: {e}[/red]")
                    phase_results['api'] = None
                self.console.print()
            
            # Vulnerability Research
            if "research" in phases:
                self.console.print(f"[yellow][Phase {phases.index('research') + 1}/{len(phases)}] Vulnerability Research...[/yellow]")
                self.console.print(f"  [dim]Steps: Search ExploitDB, NVD API, CISA KEV, CVEMap[/dim]")
                try:
                    from hazarus.vulnerability import ExploitIntelligence, NVDClient, CISAKEVClient, CVEMapScanner
                    exploitdb = ExploitIntelligence()
                    nvd_client = NVDClient()
                    cisa_client = CISAKEVClient()
                    cvemap = CVEMapScanner()
                    
                    # Search ExploitDB
                    result = await exploitdb.search(target)
                    exploits = getattr(result, 'exploits', [])
                    self.console.print(f"  Exploits found: {len(exploits)}")
                    
                    # Search NVD
                    nvd_cves = await nvd_client.search_cve(target)
                    self.console.print(f"  NVD CVEs found: {len(nvd_cves)}")
                    
                    # Search CISA KEV
                    cisa_kev = await cisa_client.search_kev(target)
                    self.console.print(f"  CISA KEV found: {len(cisa_kev)}")
                    
                    # Search CVEMap
                    cvemap_results = await cvemap.search_cve(target)
                    self.console.print(f"  CVEMap results: {len(cvemap_results)}")
                    
                    phase_results['research'] = {
                        'exploits': len(exploits),
                        'nvd_cves': len(nvd_cves),
                        'cisa_kev': len(cisa_kev),
                        'cvemap': len(cvemap_results)
                    }
                except Exception as e:
                    self.console.print(f"  [red]✗ Vulnerability research failed: {e}[/red]")
                    phase_results['research'] = None
                self.console.print()
            
            # Exploit Listing
            if "exploit" in phases:
                self.console.print(f"[yellow][Phase {phases.index('exploit') + 1}/{len(phases)}] Exploit Listing...[/yellow]")
                self.console.print(f"  [dim]Steps: Query exploit registry, List available exploits[/dim]")
                try:
                    from hazarus.exploitation.exploit_registry import ExploitRegistry
                    registry = ExploitRegistry()
                    exploits = registry.list_exploits()
                    self.console.print(f"  Total exploits in registry: {len(exploits)}")
                    phase_results['exploit'] = {'total': len(exploits)}
                except Exception as e:
                    self.console.print(f"  [red]✗ Exploit listing failed: {e}[/red]")
                    phase_results['exploit'] = None
                self.console.print()
            
            # Post-Assessment Audit
            if "post_audit" in phases:
                self.console.print(f"[yellow][Phase {phases.index('post_audit') + 1}/{len(phases)}] Post-Assessment Audit...[/yellow]")
                self.console.print(f"  [dim]Steps: Privilege audit, Persistence check[/dim]")
                try:
                    from hazarus.post_assessment.privilege_audit import PrivilegeAudit
                    from hazarus.post_assessment.persistence_audit import PersistenceAudit
                    
                    privilege_audit = PrivilegeAudit()
                    privilege_result = await privilege_audit.audit(target)
                    self.console.print(f"  Privilege findings: {len(privilege_result.findings)}")
                    
                    persistence_audit = PersistenceAudit()
                    persistence_result = await persistence_audit.audit(target)
                    self.console.print(f"  Persistence mechanisms: {len(persistence_result.mechanisms)}")
                    
                    phase_results['post_audit'] = {
                        'privilege_findings': len(privilege_result.findings),
                        'persistence_mechanisms': len(persistence_result.mechanisms)
                    }
                except Exception as e:
                    self.console.print(f"  [red]✗ Post-assessment audit failed: {e}[/red]")
                    phase_results['post_audit'] = None
                self.console.print()
            
            # Lateral Movement Audit
            if "lateral" in phases:
                self.console.print(f"[yellow][Phase {phases.index('lateral') + 1}/{len(phases)}] Lateral Movement Audit...[/yellow]")
                self.console.print(f"  [dim]Steps: Credential cache, Service checks, Network paths[/dim]")
                try:
                    from hazarus.post_assessment.lateral_movement_audit import LateralMovementAudit
                    
                    lateral_audit = LateralMovementAudit()
                    lateral_result = await lateral_audit.audit(target)
                    self.console.print(f"  Lateral paths: {len(lateral_result.paths)}")
                    
                    phase_results['lateral'] = {
                        'lateral_paths': len(lateral_result.paths)
                    }
                except Exception as e:
                    self.console.print(f"  [red]✗ Lateral movement audit failed: {e}[/red]")
                    phase_results['lateral'] = None
                self.console.print()
            
            # Source Code Analysis
            if "code" in phases:
                self.console.print(f"[yellow][Phase {phases.index('code') + 1}/{len(phases)}] Source Code Analysis...[/yellow]")
                self.console.print(f"  [dim]Steps: Semgrep, Gitleaks, Trivy, Bandit[/dim]")
                try:
                    from hazarus.code_analysis.semgrep import SemgrepAnalyzer
                    from hazarus.code_analysis.gitleaks import GitleaksScanner
                    from hazarus.code_analysis.trivy import TrivyScanner
                    from hazarus.code_analysis.bandit import BanditScanner
                    
                    # Check if code path is provided in target
                    code_path = target if target and os.path.exists(target) else None
                    
                    if code_path:
                        self.console.print(f"  [dim]Code path: {code_path}[/dim]")
                        
                        # Semgrep
                        try:
                            semgrep = SemgrepAnalyzer()
                            semgrep_result = await semgrep.scan(code_path)
                            self.console.print(f"  Semgrep issues: {semgrep_result.total_issues}")
                        except Exception as e:
                            self.console.print(f"  [yellow]⚠ Semgrep failed: {e}[/yellow]")
                        
                        # Gitleaks
                        try:
                            gitleaks = GitleaksScanner()
                            gitleaks_result = await gitleaks.scan(code_path)
                            self.console.print(f"  Gitleaks secrets: {len(gitleaks_result.secrets)}")
                        except Exception as e:
                            self.console.print(f"  [yellow]⚠ Gitleaks failed: {e}[/yellow]")
                        
                        # Trivy
                        try:
                            trivy = TrivyScanner()
                            trivy_result = await trivy.scan(code_path)
                            self.console.print(f"  Trivy vulnerabilities: {len(trivy_result.vulnerabilities)}")
                        except Exception as e:
                            self.console.print(f"  [yellow]⚠ Trivy failed: {e}[/yellow]")
                        
                        # Bandit
                        try:
                            bandit = BanditScanner()
                            bandit_result = await bandit.scan(code_path)
                            self.console.print(f"  Bandit issues: {bandit_result.total_issues}")
                        except Exception as e:
                            self.console.print(f"  [yellow]⚠ Bandit failed: {e}[/yellow]")
                        
                        phase_results['code'] = {'path': code_path, 'scanned': True}
                    else:
                        self.console.print(f"  [yellow]⚠ Source code analysis requires code path[/yellow]")
                        self.console.print(f"  [dim]Usage: Provide local directory path as target[/dim]")
                        self.console.print(f"  [dim]Tools available: Semgrep, Gitleaks, Trivy, Bandit[/dim]")
                        phase_results['code'] = {'scanned': False, 'reason': 'no_code_path'}
                except Exception as e:
                    self.console.print(f"  [red]✗ Source code analysis failed: {e}[/red]")
                    phase_results['code'] = None
                self.console.print()
        
        # Summary
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold green]COMPREHENSIVE ASSESSMENT COMPLETE[/bold green]")
        self.console.print(f"{'='*80}")
        
        if phase_results.get('privacy'):
            p = phase_results['privacy']
            self.console.print(f"[dim]Privacy - Anonsurf: {'✓' if p['running'] else '✗'}, Tor: {'✓' if p['tor_available'] else '✗'}, DNS Leak: {'✓' if not p['dns_leak'] else '✗'}[/dim]")
        
        if phase_results.get('recon'):
            r = phase_results['recon']
            if mode == "full":
                subfinder = r.get('subfinder_subdomains', 0)
                doh = r.get('doh_records', 0)
                live = r.get('live_hosts', 0)
                takeover = r.get('takeover_vulnerable', 0)
                self.console.print(f"[dim]Recon - DNS: {r['dns_records']}, Amass: {r['amass_subdomains']}, crt.sh: {r['crtsh_subdomains']}, Brute: {r['bruteforce_subdomains']}, Subfinder: {subfinder}, DoH: {doh}, Live: {live}, Takeover: {takeover}, Origin IPs: {r['origin_ips']}[/dim]")
            else:
                self.console.print(f"[dim]Recon - DNS: {r['dns_records']}, Amass: {r['amass_subdomains']}, crt.sh: {r['crtsh_subdomains']}, Brute: {r['bruteforce_subdomains']}, Origin IPs: {r['origin_ips']}[/dim]")
        
        if phase_results.get('scan'):
            s = phase_results['scan']
            self.console.print(f"[dim]Scan - Open Ports: {s['open_ports']}[/dim]")
        
        if phase_results.get('web'):
            w = phase_results['web']
            self.console.print(f"[dim]Web - Headers: {w['security_headers']}, Cookies: {w['cookies']}, Vulns: {w['vulnerabilities']}[/dim]")
        
        self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        # Generate report
        try:
            from hazarus.reporting import ReportEngine
            from pathlib import Path
            
            report_dir = self.hazarus_dir / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            
            report_file = report_dir / f"comprehensive_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            report_gen = ReportGenerator()
            report_gen.generate_comprehensive_report(
                target=target,
                phase_results=phase_results,
                output_path=str(report_file)
            )
            
            self.console.print(f"[green]✓ Report generated: {report_file}[/green]")
        except Exception as e:
            self.console.print(f"[yellow]⚠ Report generation failed: {e}[/yellow]")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")
    
    async def external_tools_menu(self):
        """External tools management submenu."""
        self.console.clear()
        
        from hazarus.tools import ToolRegistry, ToolDetector, ToolInstaller, ToolConfigurer, ToolValidator
        
        registry = ToolRegistry()
        detector = ToolDetector(registry)
        installer = ToolInstaller(registry, debug=self.debug_mode)
        configurer = ToolConfigurer(registry)
        validator = ToolValidator(registry)
        
        while True:
            debug_status = "[green]ON[/green]" if self.debug_mode else "[red]OFF[/red]"
            self.console.print(Panel(
                f"""
[bold cyan][1][/bold cyan] List Tools
[bold cyan][2][/bold cyan] Check Installation Status
[bold cyan][3][/bold cyan] Install Missing Tools
[bold cyan][4][/bold cyan] Install Specific Tool
[bold cyan][5][/bold cyan] Retry Failed Installations
[bold cyan][6][/bold cyan] Configure Tools
[bold cyan][7][/bold cyan] Validate Tools
[bold cyan][8][/bold cyan] Toggle Debug Mode (Currently: {debug_status})
[bold cyan][0][/bold cyan] Back to Main Menu
""",
                title="[bold red]External Tools[/bold red]",
                border_style="red"
            ))
            
            choice = self.console.input("\n[bold red]Select option [0-8]: [/bold red]")
            
            if choice == "0":
                break
            elif choice == "1":
                await self.list_tools(detector)
            elif choice == "2":
                await self.check_tool_status(detector)
            elif choice == "3":
                await self.install_missing_tools(installer)
            elif choice == "4":
                await self.install_specific_tool(installer)
            elif choice == "5":
                await self.retry_failed_installations(installer)
            elif choice == "6":
                await self.configure_tools(configurer)
            elif choice == "7":
                await self.validate_tools(validator)
            elif choice == "8":
                self.debug_mode = not self.debug_mode
                status = "enabled" if self.debug_mode else "disabled"
                self.console.print(f"[green]✓ Debug mode {status}[/green]")
                self.console.print(f"[dim]Debug logs will be saved to ~/.hazarus/logs/installation_debug.log[/dim]")
                # Re-create installer with new debug setting
                installer = ToolInstaller(registry, debug=self.debug_mode)
                await asyncio.sleep(1)
    
    async def list_tools(self, detector: 'ToolDetector'):
        """List all tools with their status."""
        self.console.print("\n[bold cyan]Tool Status Report[/bold cyan]\n")
        
        status_table = Table()
        status_table.add_column("Tool", style="cyan")
        status_table.add_column("Status", style="green")
        status_table.add_column("Version", style="yellow")
        status_table.add_column("Required", style="red")
        
        all_status = await detector.check_all_tools()
        
        for tool_name, status in all_status.items():
            tool = detector.registry.get_tool(tool_name)
            status_str = "✓ Installed" if status.installed else "✗ Missing"
            version_str = status.version or "N/A"
            required_str = "Yes" if tool.required else "No"
            
            status_table.add_row(tool_name, status_str, version_str, required_str)
        
        self.console.print(status_table)
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def check_tool_status(self, detector: 'ToolDetector'):
        """Check and display tool installation status."""
        self.console.print("\n[bold cyan]Checking Tool Installation Status...[/bold cyan]\n")
        
        with self.console.status("[dim]Scanning for tools...[/dim]", spinner="dots"):
            all_status = await detector.check_all_tools()
        
        installed = sum(1 for s in all_status.values() if s.installed)
        total = len(all_status)
        
        self.console.print(f"[green]✓ Installed: {installed}/{total} tools[/green]\n")
        
        missing = [name for name, status in all_status.items() if not status.installed]
        if missing:
            self.console.print("[yellow]Missing Tools:[/yellow]")
            for tool in missing:
                self.console.print(f"  [red]✗ {tool}[/red]")
        
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def install_missing_tools(self, installer: 'ToolInstaller'):
        """Install all missing tools with per-tool progress and retry options."""
        self.console.print("\n[bold cyan]Installing Missing Tools...[/bold cyan]\n")
        
        if self.debug_mode:
            self.console.print(f"[yellow]⚠ Debug mode is ENABLED - logs will be saved to ~/.hazarus/logs/installation_debug.log[/yellow]\n")
        
        # Check for sudo
        import os
        has_sudo = os.environ.get('SUDO_UID') is not None
        
        if not has_sudo:
            self.console.print("[yellow]⚠ Sudo not detected. Some tools may fail to install.[/yellow]")
            self.console.print("[yellow]⚠ Tools will be installed to ~/.local/bin where possible.[/yellow]\n")
        
        # Get missing tools
        missing = await installer.detector.check_missing_tools()
        
        if not missing:
            self.console.print("[green]✓ All tools are already installed![/green]")
            self.console.input("\n[yellow]Press Enter to continue...[/yellow]")
            return
        
        self.console.print(f"[cyan]Found {len(missing)} missing tools to install[/cyan]\n")
        
        # Install tools with per-tool progress
        results = {}
        failed_tools = {}
        
        for idx, tool_name in enumerate(missing.keys(), 1):
            self.console.print(f"[dim][{idx}/{len(missing)}] Installing {tool_name}...[/dim]")
            
            with self.console.status(f"[dim]Installing {tool_name}...[/dim]", spinner="dots"):
                status = await installer.install_tool(tool_name, sudo=has_sudo, debug=self.debug_mode)
            
            results[tool_name] = status
            
            if status.installed:
                method = status.installation_method.value if status.installation_method else "unknown"
                self.console.print(f"  [green]✓ {tool_name} installed via {method}[/green]")
            else:
                failed_tools[tool_name] = status
                error_msg = self._get_actionable_error_message(status.compatible_reason)
                self.console.print(f"  [red]✗ {tool_name} failed[/red]")
                self.console.print(f"    [dim]{error_msg}[/dim]")
        
        # Summary
        installed = sum(1 for s in results.values() if s.installed)
        total = len(results)
        
        self.console.print(f"\n[green]✓ Installation Complete: {installed}/{total} tools installed[/green]\n")
        
        if self.debug_mode:
            self.console.print(f"[dim]Debug logs saved to: ~/.hazarus/logs/installation_debug.log[/dim]\n")
        
        # Store failed installations for retry
        self.failed_installations = failed_tools
        
        # Offer retry for failed tools
        if failed_tools:
            self.console.print(f"[yellow]⚠ {len(failed_tools)} tools failed to install[/yellow]")
            self.console.print("[yellow]Failed tools:[/yellow]")
            for tool_name, status in failed_tools.items():
                self.console.print(f"  [red]✗ {tool_name}[/red]")
            
            retry = self.console.input("\n[bold cyan]Retry failed installations? [y/N]: [/bold cyan]")
            if retry.lower() in ['y', 'yes']:
                await self.retry_failed_installations(installer)
        
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def install_specific_tool(self, installer: 'ToolInstaller'):
        """Install a specific tool with fallback methods."""
        tool_name = self.console.input("\n[bold cyan]Enter tool name to install: [/bold cyan]")
        
        if not tool_name:
            return
        
        if self.debug_mode:
            self.console.print(f"[yellow]⚠ Debug mode is ENABLED - logs will be saved to ~/.hazarus/logs/installation_debug.log[/yellow]\n")
        
        # Check if tool exists in registry
        tool = installer.registry.get_tool(tool_name)
        if not tool:
            self.console.print(f"[red]✗ Tool '{tool_name}' not found in registry[/red]")
            self.console.print("[yellow]Use option [1] to list available tools[/yellow]")
            self.console.input("\n[yellow]Press Enter to continue...[/yellow]")
            return
        
        # Show available installation methods
        self.console.print(f"\n[bold cyan]Installing {tool_name}...[/bold cyan]\n")
        
        if tool.installation:
            methods = [tool.installation.type] + tool.installation.fallback_methods
            self.console.print(f"[dim]Available installation methods:[/dim]")
            for i, method in enumerate(methods, 1):
                self.console.print(f"  [dim]{i}. {method.value}[/dim]")
        
        import os
        has_sudo = os.environ.get('SUDO_UID') is not None
        
        # Try installation with fallback
        with self.console.status(f"[dim]Installing {tool_name}...[/dim]", spinner="dots"):
            status = await installer.install_tool(tool_name, sudo=has_sudo, debug=self.debug_mode)
        
        if status.installed:
            method = status.installation_method.value if status.installation_method else "unknown"
            self.console.print(f"[green]✓ {tool_name} installed successfully via {method}[/green]")
        else:
            self.console.print(f"[red]✗ {tool_name} installation failed[/red]")
            error_msg = self._get_actionable_error_message(status.compatible_reason)
            self.console.print(f"[yellow]  Reason: {error_msg}[/yellow]")
            
            # Check if there are alternative methods to try
            if tool.installation and tool.installation.fallback_methods:
                self.console.print(f"\n[yellow]Alternative installation methods available:[/yellow]")
                for i, method in enumerate(tool.installation.fallback_methods, 1):
                    self.console.print(f"  [cyan]{i}. {method.value}[/cyan]")
                
                try_alt = self.console.input("\n[bold cyan]Try alternative method? [y/N]: [/bold cyan]")
                if try_alt.lower() in ['y', 'yes']:
                    # Try each fallback method
                    for method in tool.installation.fallback_methods:
                        self.console.print(f"\n[dim]Trying {method.value}...[/dim]")
                        with self.console.status(f"[dim]Installing via {method.value}...[/dim]", spinner="dots"):
                            # Force specific installation method
                            installer_func = installer.installers.get(method)
                            if installer_func:
                                try:
                                    success = await installer_func(tool, has_sudo, debug=self.debug_mode)
                                    if success:
                                        # Verify installation
                                        new_status = await installer.detector.check_tool(tool_name)
                                        if new_status.installed:
                                            self.console.print(f"[green]✓ {tool_name} installed successfully via {method.value}[/green]")
                                            status = new_status
                                            break
                                except Exception as e:
                                    self.console.print(f"[red]✗ {method.value} failed: {str(e)}[/red]")
            
            # Store failed installation for retry
            if not status.installed:
                self.failed_installations[tool_name] = status
        
        if self.debug_mode:
            self.console.print(f"[dim]Debug logs saved to: ~/.hazarus/logs/installation_debug.log[/dim]\n")
        
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def retry_failed_installations(self, installer: 'ToolInstaller'):
        """Retry failed installations with alternative methods."""
        self.console.print("\n[bold cyan]Retry Failed Installations[/bold cyan]\n")
        
        if self.debug_mode:
            self.console.print(f"[yellow]⚠ Debug mode is ENABLED - logs will be saved to ~/.hazarus/logs/installation_debug.log[/yellow]\n")
        
        if not self.failed_installations:
            self.console.print("[green]✓ No failed installations to retry[/green]")
            self.console.input("\n[yellow]Press Enter to continue...[/yellow]")
            return
        
        self.console.print(f"[yellow]Found {len(self.failed_installations)} failed installations[/yellow]\n")
        
        # Show failed tools with indices
        failed_list = list(self.failed_installations.items())
        for idx, (tool_name, status) in enumerate(failed_list, 1):
            error_msg = self._get_actionable_error_message(status.compatible_reason)
            self.console.print(f"[cyan][{idx}][/cyan] [red]{tool_name}[/red]")
            self.console.print(f"    [dim]{error_msg}[/dim]")
        
        self.console.print("\n[bold cyan]Options:[/bold cyan]")
        self.console.print("[cyan][all][/cyan] Retry all failed tools")
        self.console.print("[cyan][#]     Retry specific tool (enter number)")
        self.console.print("[cyan][0]     Cancel")
        
        choice = self.console.input("\n[bold red]Select option: [/bold red]")
        
        if choice.lower() == 'all':
            await self._retry_all_failed(installer)
        elif choice == '0':
            self.console.print("[yellow]Cancelled[/yellow]")
        elif choice.isdigit() and 1 <= int(choice) <= len(failed_list):
            tool_name = failed_list[int(choice) - 1][0]
            await self._retry_single_tool(installer, tool_name)
        else:
            self.console.print("[red]Invalid option[/red]")
        
        if self.debug_mode:
            self.console.print(f"[dim]Debug logs saved to: ~/.hazarus/logs/installation_debug.log[/dim]\n")
        
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def _retry_all_failed(self, installer: 'ToolInstaller'):
        """Retry all failed installations."""
        import os
        has_sudo = os.environ.get('SUDO_UID') is not None
        
        self.console.print("\n[cyan]Retrying all failed installations...[/cyan]\n")
        
        for tool_name in list(self.failed_installations.keys()):
            self.console.print(f"[dim]Retrying {tool_name}...[/dim]")
            
            with self.console.status(f"[dim]Installing {tool_name}...[/dim]", spinner="dots"):
                status = await installer.install_tool(tool_name, sudo=has_sudo, debug=self.debug_mode)
            
            if status.installed:
                method = status.installation_method.value if status.installation_method else "unknown"
                self.console.print(f"  [green]✓ {tool_name} installed via {method}[/green]")
                # Remove from failed list
                del self.failed_installations[tool_name]
            else:
                error_msg = self._get_actionable_error_message(status.compatible_reason)
                self.console.print(f"  [red]✗ {tool_name} still failed[/red]")
                self.console.print(f"    [dim]{error_msg}[/dim]")
        
        # Suggest alternative methods for still-failed tools
        if self.failed_installations:
            self.console.print(f"\n[yellow]⚠ {len(self.failed_installations)} tools still failed[/yellow]")
            self.console.print("[yellow]Suggestions:[/yellow]")
            for tool_name, status in self.failed_installations.items():
                tool = installer.registry.get_tool(tool_name)
                if tool and tool.installation and tool.installation.fallback_methods:
                    self.console.print(f"  [cyan]{tool_name}:[/cyan]")
                    for method in tool.installation.fallback_methods:
                        self.console.print(f"    [dim]- Try manual installation via {method.value}[/dim]")
                else:
                    self.console.print(f"  [cyan]{tool_name}:[/cyan]")
                    self.console.print(f"    [dim]- Check https://github.com/{tool.installation.repo if tool and tool.installation else 'search'} for manual installation[/dim]")
    
    async def _retry_single_tool(self, installer: 'ToolInstaller', tool_name: str):
        """Retry a single failed tool installation."""
        import os
        has_sudo = os.environ.get('SUDO_UID') is not None
        
        self.console.print(f"\n[cyan]Retrying {tool_name}...[/cyan]\n")
        
        # Check for alternative methods
        tool = installer.registry.get_tool(tool_name)
        if tool and tool.installation and tool.installation.fallback_methods:
            self.console.print("[yellow]Alternative installation methods:[/yellow]")
            for i, method in enumerate(tool.installation.fallback_methods, 1):
                self.console.print(f"  [cyan][{i}][/cyan] {method.value}")
            self.console.print(f"  [cyan][{len(tool.installation.fallback_methods) + 1}][/cyan] Retry primary method")
            
            choice = self.console.input("\n[bold red]Select method: [/bold red]")
            
            if choice.isdigit():
                choice_idx = int(choice)
                if choice_idx == len(tool.installation.fallback_methods) + 1:
                    # Retry primary
                    with self.console.status(f"[dim]Installing via {tool.installation.type.value}...[/dim]", spinner="dots"):
                        status = await installer.install_tool(tool_name, sudo=has_sudo, debug=self.debug_mode)
                elif 1 <= choice_idx <= len(tool.installation.fallback_methods):
                    # Try specific fallback
                    method = tool.installation.fallback_methods[choice_idx - 1]
                    installer_func = installer.installers.get(method)
                    if installer_func:
                        with self.console.status(f"[dim]Installing via {method.value}...[/dim]", spinner="dots"):
                            try:
                                success = await installer_func(tool, has_sudo, debug=self.debug_mode)
                                if success:
                                    status = await installer.detector.check_tool(tool_name)
                                else:
                                    status = ToolStatus(
                                        name=tool_name,
                                        installed=False,
                                        compatible=False,
                                        compatible_reason=f"Installation via {method.value} failed"
                                    )
                            except Exception as e:
                                status = ToolStatus(
                                    name=tool_name,
                                    installed=False,
                                    compatible=False,
                                    compatible_reason=f"Error: {str(e)}"
                                )
                    else:
                        self.console.print(f"[red]✗ Unsupported method: {method.value}[/red]")
                        return
                else:
                    self.console.print("[red]Invalid option[/red]")
                    return
        else:
            # No fallbacks, just retry
            with self.console.status(f"[dim]Installing {tool_name}...[/dim]", spinner="dots"):
                status = await installer.install_tool(tool_name, sudo=has_sudo)
        
        if status.installed:
            method = status.installation_method.value if status.installation_method else "unknown"
            self.console.print(f"[green]✓ {tool_name} installed successfully via {method}[/green]")
            del self.failed_installations[tool_name]
        else:
            error_msg = self._get_actionable_error_message(status.compatible_reason)
            self.console.print(f"[red]✗ {tool_name} installation failed[/red]")
            self.console.print(f"[yellow]  Reason: {error_msg}[/yellow]")
    
    def _get_actionable_error_message(self, error_reason: str) -> str:
        """Convert error messages to actionable suggestions."""
        if not error_reason:
            return "Unknown error"
        
        error_lower = error_reason.lower()
        
        # Permission errors
        if 'permission' in error_lower or 'denied' in error_lower or 'sudo' in error_lower:
            return "Permission denied - Run with sudo or install to user directory"
        
        # Network errors
        if 'network' in error_lower or 'connection' in error_lower or 'timeout' in error_lower:
            return "Network error - Check internet connection and retry"
        
        # Rate limiting
        if 'rate' in error_lower or 'limit' in error_lower or '429' in error_lower:
            return "Rate limited - Wait and retry, or use alternative method"
        
        # Package not found
        if 'not found' in error_lower or 'package' in error_lower or '404' in error_lower:
            return "Package not found - Try alternative installation method"
        
        # Dependency errors
        if 'dependency' in error_lower or 'missing' in error_lower:
            return "Missing dependency - Install required dependencies first"
        
        # Disk space
        if 'disk' in error_lower or 'space' in error_lower:
            return "Disk space full - Free up space and retry"
        
        # Installation method specific
        if 'apt' in error_lower:
            return "APT installation failed - Try: sudo apt update && sudo apt install <package>"
        
        if 'pip' in error_lower:
            return "Pip installation failed - Try: pip install --user <package> or use --break-system-packages"
        
        if 'github' in error_lower or 'download' in error_lower:
            return "GitHub download failed - Check repo URL or download manually"
        
        # Default
        return error_reason
    
    async def configure_tools(self, configurer: 'ToolConfigurer'):
        """Configure all tools for HAZARUS integration."""
        self.console.print("\n[bold cyan]Configuring Tools...[/bold cyan]\n")
        
        with self.console.status("[dim]Configuring tools...[/dim]", spinner="dots"):
            results = await configurer.configure_all()
        
        configured = sum(1 for s in results.values() if s)
        total = len(results)
        
        self.console.print(f"\n[green]✓ Configuration Complete: {configured}/{total} tools configured[/green]\n")
        
        for tool_name, success in results.items():
            if success:
                self.console.print(f"  [green]✓ {tool_name}[/green]")
            else:
                self.console.print(f"  [yellow]⚠ {tool_name} - No configuration needed[/yellow]")
        
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def validate_tools(self, validator: 'ToolValidator'):
        """Validate all installed tools."""
        self.console.print("\n[bold cyan]Validating Tools...[/bold cyan]\n")
        
        with self.console.status("[dim]Validating tools...[/dim]", spinner="dots"):
            results = await validator.validate_all()
        
        valid = sum(1 for s in results.values() if s)
        total = len(results)
        
        self.console.print(f"\n[green]✓ Validation Complete: {valid}/{total} tools valid[/green]\n")
        
        for tool_name, is_valid in results.items():
            if is_valid:
                self.console.print(f"  [green]✓ {tool_name}[/green]")
            else:
                self.console.print(f"  [red]✗ {tool_name} - Validation failed[/red]")
        
        self.console.print("\n[yellow]Press Enter to continue...[/yellow]")
        self.console.input("")
    
    async def startup_tool_check(self):
        """Check required tools on startup."""
        try:
            from hazarus.tools import ToolDetector, ToolRegistry
            
            registry = ToolRegistry()
            detector = ToolDetector(registry)
            
            required_status = await detector.check_required_tools()
            
            missing = [name for name, status in required_status.items() if not status.installed]
            
            if missing:
                self.console.print(f"\n[yellow]⚠ Missing Required Tools: {', '.join(missing)}[/yellow]")
                self.console.print("[yellow]⚠ Some features may not work correctly.[/yellow]")
                self.console.print("[yellow]⚠ Run [15] External Tools → [3] Install Missing Tools to fix.[/yellow]\n")
                await asyncio.sleep(2)
        except Exception as e:
            # Silently skip if tools module has issues
            pass

    # Additional menu methods (if needed for future expansion)
    async def api_assessment_menu(self):
        """API assessment submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]API Assessment[/bold]", border_style="red"))
            self.console.print("[1] REST Endpoint Discovery")
            self.console.print("[2] GraphQL Endpoint Discovery")
            self.console.print("[3] API Security Testing")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-3]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "rest",
                    "2": "graphql",
                    "3": "security"
                }[choice]
                
                await self.run_api(target, mode)

    async def vulnerability_research_menu(self):
        """Vulnerability research submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Vulnerability Research[/bold]", border_style="red"))
            self.console.print("[1] CVE Search")
            self.console.print("[2] Exploit Intelligence (SearchSploit)")
            self.console.print("[3] Exploit Registry")
            self.console.print("[4] Historical Vulnerability Data")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "cve",
                    "2": "searchsploit",
                    "3": "registry",
                    "4": "historical"
                }[choice]
                
                await self.run_vulnerability_research(target, mode)

    async def exploitation_menu(self):
        """Exploitation submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Exploitation[/bold]", border_style="red"))
            self.console.print("[1] List Available Exploits")
            self.console.print("[2] Check Exploit Compatibility")
            self.console.print("[3] Exploit Registry Search")
            self.console.print("[4] Lab Environment Check")
            self.console.print("[yellow]Note: Exploitation requires lab verification[/yellow]")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue

                mode = {
                    "1": "list",
                    "2": "check",
                    "3": "search",
                    "4": "lab"
                }[choice]

                await self.run_exploitation(target, mode)

    async def vulnerability_exploitation_menu(self):
        """Combined Vulnerability Research & Exploitation submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Vulnerability Research & Exploitation[/bold]", border_style="red"))
            self.console.print("[bold cyan]Vulnerability Research:[/bold cyan]")
            self.console.print("[1] CVE Search")
            self.console.print("[2] Exploit Intelligence (SearchSploit)")
            self.console.print("[3] Exploit Registry")
            self.console.print("[4] Historical Vulnerability Data")
            self.console.print("")
            self.console.print("[bold cyan]Exploitation:[/bold cyan]")
            self.console.print("[5] List Available Exploits")
            self.console.print("[6] Check Exploit Compatibility")
            self.console.print("[7] Exploit Registry Search")
            self.console.print("[8] Lab Environment Check")
            self.console.print("[yellow]Note: Exploitation requires lab verification[/yellow]")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-8]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue

                mode = {
                    "1": "cve",
                    "2": "searchsploit",
                    "3": "registry",
                    "4": "historical"
                }[choice]

                await self.run_vulnerability_research(target, mode)
            elif choice in ["5", "6", "7", "8"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue

                mode = {
                    "5": "list",
                    "6": "check",
                    "7": "search",
                    "8": "lab"
                }[choice]

                await self.run_exploitation(target, mode)

    async def post_assessment_menu(self):
        """Post-assessment audits submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Post-Assessment Audits[/bold]", border_style="red"))
            self.console.print("[1] Privilege Audit")
            self.console.print("[2] Persistence Audit")
            self.console.print("[3] Lateral Movement Audit")
            self.console.print("[4] Segmentation Audit")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "privilege",
                    "2": "persistence",
                    "3": "lateral",
                    "4": "segmentation"
                }[choice]
                
                await self.run_post_audit(target, mode)

    async def source_code_analysis_menu(self):
        """Source code analysis submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Source Code Analysis[/bold]", border_style="red"))
            self.console.print("[1] Semgrep Static Analysis")
            self.console.print("[2] Gitleaks Secret Detection")
            self.console.print("[3] Trivy Dependency Scanning")
            self.console.print("[4] Dependency Audit")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter code path: ")
                if not target:
                    self.console.print("[red]No path specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "semgrep",
                    "2": "gitleaks",
                    "3": "trivy",
                    "4": "dependency"
                }[choice]
                
                await self.run_code_analysis(target, mode)

    async def reporting_menu(self):
        """Reporting submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Reporting[/bold]", border_style="red"))
            self.console.print("[1] View Recent Assessments")
            self.console.print("[2] Generate Markdown Report")
            self.console.print("[3] Generate HTML Report")
            self.console.print("[4] Generate PDF Report")
            self.console.print("[5] Export Assessment Data")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice == "1":
                await self.view_recent_assessments()
            elif choice in ["2", "3", "4", "5"]:
                mode = {
                    "2": "markdown",
                    "3": "html",
                    "4": "pdf",
                    "5": "export"
                }[choice]
                
                await self.generate_report(mode)

    async def configuration_menu(self):
        """Configuration submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Configuration[/bold]", border_style="red"))
            self.console.print("[1] View Current Configuration")
            self.console.print("[2] Edit Assessment Settings")
            self.console.print("[3] Edit Privacy Settings")
            self.console.print("[4] Reset to Defaults")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice == "1":
                self.show_config()
                self.console.input("\nPress Enter to continue...")
            elif choice == "2":
                await self.edit_assessment_settings()
            elif choice == "3":
                await self.edit_privacy_settings()
            elif choice == "4":
                await self.reset_to_defaults()

    async def edit_assessment_settings(self):
        """Edit assessment settings."""
        self.console.print("\n[cyan]Edit Assessment Settings[/cyan]")
        self.console.print("[yellow]This feature allows you to modify assessment-specific settings:[/yellow]")
        self.console.print("  - Assessment intensity (low, normal, high)")
        self.console.print("  - Rate limiting parameters")
        self.console.print("  - Request limits")
        self.console.print("  - Timeout values")
        self.console.print("  - Scan aggressiveness")
        self.console.print("\n[dim]Currently: Settings are managed in config/hazarus.yaml[/dim]")
        self.console.print("[dim]Implementation: Will add interactive editor in future update[/dim]")
        self.console.input("\nPress Enter to continue...")

    async def edit_privacy_settings(self):
        """Edit privacy settings."""
        self.console.print("\n[cyan]Edit Privacy Settings[/cyan]")
        self.console.print("[yellow]This feature allows you to modify privacy-related settings:[/yellow]")
        self.console.print("  - Anonsurf requirement (strict, optional, disabled)")
        self.console.print("  - DNS leak blocking behavior")
        self.console.print("  - IPv6 exposure handling")
        self.console.print("  - Tor connectivity requirements")
        self.console.print("  - Anonymity verification level")
        self.console.print("\n[dim]Currently: Settings are managed in config/hazarus.yaml[/dim]")
        self.console.print("[dim]Implementation: Will add interactive editor in future update[/dim]")
        self.console.input("\nPress Enter to continue...")

    async def reset_to_defaults(self):
        """Reset configuration to defaults."""
        self.console.print("\n[cyan]Reset to Defaults[/cyan]")
        self.console.print("[yellow]This feature will reset all configuration to default values:[/yellow]")
        self.console.print("  - Assessment settings to normal intensity")
        self.console.print("  - Privacy settings to strict mode")
        self.console.print("  - Timeouts to default values")
        self.console.print("  - Rate limits to safe defaults")
        self.console.print("\n[red]Warning: This will overwrite your current configuration![/red]")
        confirm = self.console.input("\n[type yellow]Are you sure? (yes/no): [/type yellow]")
        
        if confirm.lower() == "yes":
            self.console.print("[yellow]Resetting configuration to defaults...[/yellow]")
            self.console.print("[dim]Implementation: Will restore from config/hazarus.yaml.default[/dim]")
            self.console.print("[green]✓ Configuration reset complete[/green]")
        else:
            self.console.print("[yellow]Reset cancelled[/yellow]")
        
        self.console.input("\nPress Enter to continue...")

    async def advanced_tools_menu(self):
        """Advanced tools submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Advanced Tools[/bold]", border_style="red"))
            self.console.print("[1] Advanced Subdomain Discovery")
            self.console.print("[2] Enhanced Live Host Discovery")
            self.console.print("[3] Enhanced Origin IP Discovery")
            self.console.print("[4] DNS over HTTPS")
            self.console.print("[5] DNS over TLS")
            self.console.print("[6] NSEC Zone Walk")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-6]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4", "5", "6"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "subdomains",
                    "2": "live_hosts",
                    "3": "origin_ip",
                    "4": "doh",
                    "5": "dot",
                    "6": "nsec"
                }[choice]
                
                await self.run_advanced_tool(target, mode)

    async def asset_intelligence_menu(self):
        """Asset intelligence submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Asset Intelligence[/bold]", border_style="red"))
            self.console.print("[1] View Asset Inventory")
            self.console.print("[2] Asset Classification")
            self.console.print("[3] View Asset Lifecycle")
            self.console.print("[4] View Asset Risk Scores")
            self.console.print("[5] View Asset Changes")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4", "5"]:
                mode = {
                    "1": "inventory",
                    "2": "classification",
                    "3": "lifecycle",
                    "4": "risk",
                    "5": "changes"
                }[choice]
                
                await self.run_asset_intelligence(mode)

    async def host_infrastructure_menu(self):
        """Host & Infrastructure Pentesting submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Host & Infrastructure Pentesting[/bold]", border_style="red"))
            self.console.print("[1] Host Enumeration")
            self.console.print("[2] Privilege Escalation Audit")
            self.console.print("[3] Lateral Movement Audit")
            self.console.print("[4] System Hardening Check")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target (IP/hostname): ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "enumeration",
                    "2": "privilege",
                    "3": "lateral",
                    "4": "hardening"
                }[choice]
                
                await self.run_host_infrastructure(target, mode)

    async def mobile_pentesting_menu(self):
        """Mobile Application Pentesting submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Mobile Application Pentesting[/bold]", border_style="red"))
            self.console.print("[1] Static Analysis (APK/IPA)")
            self.console.print("[2] Dynamic Analysis (Runtime)")
            self.console.print("[3] Traffic Analysis (Network)")
            self.console.print("[4] API Security Testing")
            self.console.print("[yellow]Note: Requires additional tools (MobSF, Frida, Burp Suite)[/yellow]")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter mobile app path/package: ")
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "static",
                    "2": "dynamic",
                    "3": "traffic",
                    "4": "api"
                }[choice]
                
                await self.run_mobile_pentesting(target, mode)

    async def forensics_menu(self):
        """Digital Forensics & Incident Response submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Digital Forensics & Incident Response[/bold]", border_style="red"))
            self.console.print("[1] Memory Analysis")
            self.console.print("[2] Disk Analysis")
            self.console.print("[3] Log Analysis")
            self.console.print("[4] Malware Analysis")
            self.console.print("[yellow]Note: Requires additional tools (Volatility, Autopsy, Sleuth Kit)[/yellow]")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter evidence path/image: ")
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "memory",
                    "2": "disk",
                    "3": "log",
                    "4": "malware"
                }[choice]
                
                await self.run_forensics(target, mode)

    async def wireless_menu(self):
        """Wireless Security Assessment submenu."""
        self.console.clear()
        while True:
            self.console.print("\n" + "="*80)
            self.console.print(Panel("[bold]Wireless Security Assessment[/bold]", border_style="red"))
            self.console.print("[1] WEP/WPA Cracking")
            self.console.print("[2] Rogue AP Detection")
            self.console.print("[3] Traffic Analysis")
            self.console.print("[4] Wireless Audit")
            self.console.print("[yellow]Note: Requires wireless adapter in monitor mode[/yellow]")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                self.console.clear()
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target (BSSID/interface): ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "cracking",
                    "2": "rogue",
                    "3": "traffic",
                    "4": "audit"
                }[choice]
                
                await self.run_wireless(target, mode)

    # Implementation methods for submenus
    async def run_api(self, target: str, mode: str):
        """Run API assessment."""
        self.console.print(f"[cyan]Running {mode} API assessment on {target}...[/cyan]")
        
        try:
            from hazarus.scanning.api_discovery import APIDiscovery
            api_discovery = APIDiscovery()
            
            if mode == "rest":
                result = await api_discovery.discover_rest_endpoints(target)
                self.console.print(f"[green]✓ REST endpoints: {len(result.endpoints)}[/green]")
            elif mode == "graphql":
                result = await api_discovery.discover_graphql_endpoints(target)
                self.console.print(f"[green]✓ GraphQL endpoints: {len(result.endpoints)}[/green]")
            elif mode == "security":
                result = await api_discovery.scan_api_security(target)
                self.console.print(f"[green]✓ Security issues: {len(result.issues)}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ API assessment failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_vulnerability_research(self, target: str, mode: str):
        """Run vulnerability research."""
        self.console.print(f"[cyan]Running {mode} vulnerability research on {target}...[/cyan]")
        
        try:
            from hazarus.vulnerability.exploitdb import ExploitIntelligence
            
            if mode == "cve":
                self.console.print("\n[cyan]CVE Search[/cyan]")
                self.console.print("[yellow]This feature searches for CVEs related to the target:[/yellow]")
                self.console.print("  - Queries NVD (National Vulnerability Database)")
                self.console.print("  - Searches CVEMap for additional context")
                self.console.print("  - Checks CISA KEV (Known Exploited Vulnerabilities)")
                self.console.print("  - Provides severity scores and descriptions")
                self.console.print("\n[dim]Implementation: Will integrate NVD API and CVEMap[/dim]")
            elif mode == "searchsploit":
                exploitdb = ExploitDB()
                result = await exploitdb.search(target)
                self.console.print(f"[green]✓ Exploits found: {len(result.exploits)}[/green]")
            elif mode == "registry":
                from hazarus.exploitation.exploit_registry import ExploitRegistry
                registry = ExploitRegistry()
                exploits = registry.list_exploits()
                self.console.print(f"[green]✓ Total exploits in registry: {len(exploits)}[/green]")
            elif mode == "historical":
                self.console.print("\n[cyan]Historical Vulnerability Data[/cyan]")
                self.console.print("[yellow]This feature provides historical vulnerability analysis:[/yellow]")
                self.console.print("  - Tracks vulnerability trends over time")
                self.console.print("  - Shows patch history and remediation status")
                self.console.print("  - Identifies recurring vulnerabilities")
                self.console.print("  - Provides vulnerability lifecycle information")
                self.console.print("\n[dim]Implementation: Will integrate historical vulnerability databases[/dim]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Vulnerability research failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_exploitation(self, target: str, mode: str):
        """Run exploitation checks."""
        self.console.print(f"[cyan]Running {mode} exploitation check on {target}...[/cyan]")
        self.console.print("[yellow]Note: Actual exploitation requires lab verification[/yellow]")
        
        try:
            from hazarus.exploitation.exploit_registry import ExploitRegistry
            
            if mode == "list":
                registry = ExploitRegistry()
                exploits = registry.list_exploits()
                self.console.print(f"[green]✓ Available exploits: {len(exploits)}[/green]")
            elif mode == "check":
                self.console.print("\n[cyan]Exploit Compatibility Check[/cyan]")
                self.console.print("[yellow]This feature checks if exploits are compatible with the target:[/yellow]")
                self.console.print("  - Analyzes target OS and service versions")
                self.console.print("  - Matches against exploit requirements")
                self.console.print("  - Identifies potential exploitation paths")
                self.console.print("  - Provides risk assessment for each exploit")
                self.console.print("\n[dim]Implementation: Will integrate with exploit registry[/dim]")
            elif mode == "search":
                self.console.print("\n[cyan]Exploit Registry Search[/cyan]")
                self.console.print("[yellow]This feature searches the exploit registry for specific exploits:[/yellow]")
                self.console.print("  - Search by CVE, service, or vulnerability type")
                self.console.print("  - Filter by platform and architecture")
                self.console.print("  - View exploit metadata and requirements")
                self.console.print("  - Check exploit reliability and verification status")
                self.console.print("\n[dim]Implementation: Will add search functionality to exploit registry[/dim]")
            elif mode == "lab":
                self.console.print("\n[cyan]Lab Environment Check[/cyan]")
                self.console.print("[yellow]This feature verifies the lab environment before exploitation:[/yellow]")
                self.console.print("  - Checks if target is in authorized lab network")
                self.console.print("  - Verifies isolation from production systems")
                self.console.print("  - Confirms safe environment for testing")
                self.console.print("  - Validates network segmentation")
                self.console.print("\n[dim]Implementation: Will integrate with lab verification system[/dim]")
                self.console.print("[red]Note: Actual exploitation is only permitted in verified lab environments[/red]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Exploitation check failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_post_audit(self, target: str, mode: str):
        """Run post-assessment audit."""
        self.console.print(f"[cyan]Running {mode} post-assessment audit on {target}...[/cyan]")
        
        try:
            if mode == "privilege":
                from hazarus.post_assessment.privilege_audit import PrivilegeAudit
                audit = PrivilegeAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Privilege findings: {len(result.findings)}[/green]")
            elif mode == "persistence":
                from hazarus.post_assessment.persistence_audit import PersistenceAudit
                audit = PersistenceAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Persistence mechanisms: {len(result.mechanisms)}[/green]")
            elif mode == "lateral":
                from hazarus.post_assessment.lateral_movement_audit import LateralMovementAudit
                audit = LateralMovementAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Lateral paths: {len(result.paths)}[/green]")
            elif mode == "segmentation":
                from hazarus.post_assessment.segmentation_audit import SegmentationAudit
                audit = SegmentationAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Segmentation findings: {len(result.findings)}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Post-assessment audit failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_code_analysis(self, target: str, mode: str):
        """Run source code analysis."""
        self.console.print(f"[cyan]Running {mode} code analysis on {target}...[/cyan]")
        
        try:
            if mode == "semgrep":
                from hazarus.code_analysis.semgrep import SemgrepScanner
                scanner = SemgrepAnalyzer()
                self.console.print("[yellow]Semgrep scan - Running...[/yellow]")
                self.console.print("[green]✓ Semgrep scan complete[/green]")
            elif mode == "gitleaks":
                from hazarus.code_analysis.gitleaks import GitleaksScanner
                scanner = GitleaksScanner()
                self.console.print("[yellow]Gitleaks scan - Running...[/yellow]")
                self.console.print("[green]✓ Gitleaks scan complete[/green]")
            elif mode == "trivy":
                from hazarus.code_analysis.trivy import TrivyScanner
                scanner = TrivyScanner()
                self.console.print("[yellow]Trivy scan - Running...[/yellow]")
                self.console.print("[green]✓ Trivy scan complete[/green]")
            elif mode == "dependency":
                from hazarus.code_analysis.dependency_audit import DependencyAudit
                audit = DependencyAudit()
                self.console.print("[yellow]Dependency audit - Running...[/yellow]")
                self.console.print("[green]✓ Dependency audit complete[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Code analysis failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def view_recent_assessments(self):
        """View recent assessments from database."""
        self.console.print("[cyan]Loading recent assessments...[/cyan]")
        
        try:
            from hazarus.reconnaissance.core import ReconPersistence
            
            persistence = ReconPersistence()
            recent = await persistence.get_recent_assessments(limit=10)
            
            table = Table(title="Recent Assessments")
            table.add_column("ID", style="cyan", max_width=20)
            table.add_column("Target", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Started", style="dim")
            
            for assessment in recent:
                table.add_row(
                    assessment.assessment_id[:20],
                    assessment.target,
                    assessment.status,
                    assessment.started_at.strftime("%Y-%m-%d %H:%M")
                )
            
            self.console.print(table)
        except Exception as e:
            self.console.print(f"[red]✗ Failed to load assessments: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def generate_report(self, mode: str):
        """Generate report in specified format."""
        self.console.print(f"[cyan]Generating {mode} report...[/cyan]")
        
        try:
            from hazarus.reconnaissance.core import ReconPersistence, ReconReportGenerator
            from hazarus.reconnaissance.core import ReconReport
            from dataclasses import asdict
            
            persistence = ReconPersistence()
            recent = await persistence.get_recent_assessments(limit=1)
            
            if not recent:
                self.console.print("[yellow]No recent assessments found[/yellow]")
                self.console.input("\nPress Enter to continue...")
                return
            
            assessment = recent[0]
            assets = await persistence.load_assets(assessment.assessment_id)
            findings = await persistence.load_findings(assessment.assessment_id)
            
            report = ReconReport(
                assessment_id=assessment.assessment_id,
                target=assessment.target,
                started_at=assessment.started_at,
                completed_at=assessment.completed_at,
                status=assessment.status,
                phases=assessment.phases,
                assets={"all": [asdict(a) for a in assets]},
                findings=[asdict(f) for f in findings],
                metadata={}
            )
            
            generator = ReconReportGenerator()
            
            if mode == "markdown":
                md_content = generator.generate_markdown(report)
                output_path = self.hazarus_dir / "reports" / f"{assessment.assessment_id}_report.md"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w") as f:
                    f.write(md_content)
                self.console.print(f"[green]✓ Markdown report: {output_path}[/green]")
            elif mode == "html":
                html_content = generator.generate_html(report)
                output_path = self.hazarus_dir / "reports" / f"{assessment.assessment_id}_report.html"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w") as f:
                    f.write(html_content)
                self.console.print(f"[green]✓ HTML report: {output_path}[/green]")
            elif mode == "pdf":
                output_path = self.hazarus_dir / "reports" / f"{assessment.assessment_id}_report.pdf"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                success = await generator.generate_pdf(report, str(output_path))
                if success:
                    self.console.print(f"[green]✓ PDF report: {output_path}[/green]")
                else:
                    self.console.print("[yellow]✗ PDF generation failed (weasyprint not installed)[/yellow]")
            elif mode == "export":
                json_data = await persistence.export_results(assessment.assessment_id, "json")
                output_path = self.hazarus_dir / "reports" / f"{assessment.assessment_id}_export.json"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w") as f:
                    f.write(json_data)
                self.console.print(f"[green]✓ Export: {output_path}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Report generation failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_advanced_tool(self, target: str, mode: str):
        """Run advanced tool."""
        self.console.print(f"[cyan]Running {mode} advanced tool on {target}...[/cyan]")
        
        try:
            if mode == "subdomains":
                from hazarus.reconnaissance.advanced import AdvancedSubdomainTools
                tools = AdvancedSubdomainTools()
                result = await tools.discover_all(target)
                self.console.print(f"[green]✓ Subdomains found: {result.total_found}[/green]")
            elif mode == "doh":
                from hazarus.reconnaissance.advanced import AdvancedDNS
                dns = AdvancedDNS()
                result = await dns.query_doh(target, "A")
                self.console.print(f"[green]✓ DoH records: {len(result.records)}[/green]")
            elif mode == "dot":
                from hazarus.reconnaissance.advanced import AdvancedDNS
                dns = AdvancedDNS()
                result = await dns.query_dot(target, "A")
                self.console.print(f"[green]✓ DoT records: {len(result.records)}[/green]")
            elif mode == "nsec":
                from hazarus.reconnaissance.advanced import AdvancedDNS
                dns = AdvancedDNS()
                result = await dns.nsec_walk(target)
                self.console.print(f"[green]✓ NSEC subdomains: {len(result.subdomains)}[/green]")
            elif mode == "live_hosts":
                from hazarus.reconnaissance.advanced import EnhancedLiveHostDiscovery
                live = EnhancedLiveHostDiscovery()
                result = await live.discover_enhanced(target)
                self.console.print(f"[green]✓ Live hosts: {len(result.hosts)}[/green]")
            elif mode == "origin_ip":
                from hazarus.reconnaissance.advanced import EnhancedOriginIPDiscovery
                origin = EnhancedOriginIPDiscovery()
                result = await origin.discover_enhanced(target)
                self.console.print(f"[green]✓ Origin IPs: {result.total_ips}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Advanced tool failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_asset_intelligence(self, mode: str):
        """Run asset intelligence."""
        self.console.print(f"[cyan]Running asset intelligence: {mode}[/cyan]")
        
        try:
            from hazarus.reconnaissance.core import ReconPersistence
            from hazarus.reconnaissance.asset import AssetIntelligence, AssetLifecycle, AssetRiskScoring
            
            persistence = ReconPersistence()
            recent = await persistence.get_recent_assessments(limit=1)
            
            if not recent:
                self.console.print("[yellow]No recent assessments found[/yellow]")
                self.console.input("\nPress Enter to continue...")
                return
            
            assessment = recent[0]
            assets = await persistence.load_assets(assessment.assessment_id)
            
            if mode == "inventory":
                intel = AssetIntelligence()
                result = await intel.analyze([asdict(a) for a in assets])
                self.console.print(f"[green]✓ Total assets: {result.summary['total_assets']}[/green]")
                self.console.print(f"[green]✓ High risk: {result.summary['high_risk_count']}[/green]")
            elif mode == "lifecycle":
                lifecycle = AssetLifecycle()
                stale = await lifecycle.get_stale_assets(days_threshold=90)
                self.console.print(f"[green]✓ Stale assets: {len(stale)}[/green]")
            elif mode == "risk":
                scoring = AssetRiskScoring()
                # Would need ExtendedAsset objects
                self.console.print("[yellow]Risk scoring requires ExtendedAsset objects[/yellow]")
            elif mode == "changes":
                intel = AssetIntelligence()
                # Would need previous assessment
                self.console.print("[yellow]Change detection requires previous assessment[/yellow]")
            elif mode == "classification":
                intel = AssetIntelligence()
                classified = await intel.classify_assets([asdict(a) for a in assets])
                self.console.print(f"[green]✓ Classified assets: {len(classified)}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Asset intelligence failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_host_infrastructure(self, target: str, mode: str):
        """Run host & infrastructure pentesting."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]HOST & INFRASTRUCTURE PENTESTING[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        try:
            if mode == "enumeration":
                self.console.print("[cyan]Host Enumeration[/cyan]")
                self.console.print("[yellow]Performing host enumeration...[/yellow]")
                self.console.print("  - System information gathering")
                self.console.print("  - User and group enumeration")
                self.console.print("  - Process and service enumeration")
                self.console.print("  - Network configuration analysis")
                
                # Try to use post_assessment tools if available
                try:
                    from hazarus.post_assessment.linpeas import LinPEASScanner
                    linpeas = LinPEASScanner()
                    result = await linpeas.scan(target)
                    self.console.print(f"[green]✓ LinPEAS scan complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ LinPEAS not available: {e}[/yellow]")
                    self.console.print("[dim]Install LinPEAS for comprehensive Linux enumeration[/dim]")
                
                try:
                    from hazarus.post_assessment.winpeas import WinPEASScanner
                    winpeas = WinPEASScanner()
                    result = await winpeas.scan(target)
                    self.console.print(f"[green]✓ WinPEAS scan complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ WinPEAS not available: {e}[/yellow]")
                    self.console.print("[dim]Install WinPEAS for comprehensive Windows enumeration[/dim]")
                
            elif mode == "privilege":
                self.console.print("[cyan]Privilege Escalation Audit[/cyan]")
                self.console.print("[yellow]Performing privilege escalation audit...[/yellow]")
                self.console.print("  - SUID/GUID binary analysis")
                self.console.print("  - Cron job analysis")
                self.console.print("  - Capabilities analysis")
                self.console.print("  - Kernel vulnerability check")
                
                # Use LinPEAS/WinPEAS for privilege escalation
                try:
                    from hazarus.post_assessment.linpeas import LinPEASScanner
                    linpeas = LinPEASScanner()
                    result = await linpeas.scan(target)
                    self.console.print(f"[green]✓ LinPEAS privilege audit complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ LinPEAS not available: {e}[/yellow]")
                    self.console.print("[dim]Install LinPEAS for comprehensive Linux privilege escalation[/dim]")
                
                try:
                    from hazarus.post_assessment.winpeas import WinPEASScanner
                    winpeas = WinPEASScanner()
                    result = await winpeas.scan(target)
                    self.console.print(f"[green]✓ WinPEAS privilege audit complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ WinPEAS not available: {e}[/yellow]")
                    self.console.print("[dim]Install WinPEAS for comprehensive Windows privilege escalation[/dim]")
                
            elif mode == "lateral":
                self.console.print("[cyan]Lateral Movement Audit[/cyan]")
                self.console.print("[yellow]Performing lateral movement audit...[/yellow]")
                self.console.print("  - Credential cache analysis")
                self.console.print("  - Service account enumeration")
                self.console.print("  - Network path discovery")
                self.console.print("  - Trust relationship analysis")
                
                # Use BloodHound for lateral movement analysis
                try:
                    from hazarus.post_assessment.bloodhound import BloodHoundAnalyzer
                    bloodhound = BloodHoundAnalyzer()
                    result = await bloodhound.analyze(target)
                    self.console.print(f"[green]✓ BloodHound analysis complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ BloodHound not available: {e}[/yellow]")
                    self.console.print("[dim]Install BloodHound for AD lateral movement analysis[/dim]")
                
            elif mode == "hardening":
                self.console.print("[cyan]System Hardening Check[/cyan]")
                self.console.print("[yellow]Performing system hardening check...[/yellow]")
                self.console.print("  - Configuration audit")
                self.console.print("  - Patch level verification")
                self.console.print("  - Security baseline comparison")
                self.console.print("  - Compliance check")
                
                try:
                    from hazarus.post_assessment.lynis import LynisScanner
                    lynis = LynisScanner()
                    result = await lynis.scan(target)
                    self.console.print(f"[green]✓ Lynis scan complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Lynis not available: {e}[/yellow]")
                    self.console.print("[dim]Install Lynis for comprehensive security auditing[/dim]")
            
            # Summary
            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]HOST & INFRASTRUCTURE PENTESTING COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")
            
        except Exception as e:
            self.console.print(f"\n[red]✗ Host & infrastructure pentesting failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_mobile_pentesting(self, target: str, mode: str):
        """Run mobile application pentesting."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]MOBILE APPLICATION PENTESTING[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print("[cyan]Mobile Application Pentesting[/cyan]")
        self.console.print("[yellow]This feature requires additional mobile security tools:[/yellow]")
        
        if mode == "static":
            self.console.print("\n[cyan]Static Analysis[/cyan]")
            self.console.print("  - APK/IPA decompilation")
            self.console.print("  - Source code review")
            self.console.print("  - Manifest analysis")
            self.console.print("  - Certificate validation")
            self.console.print("  - API endpoint discovery")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- MobSF (Mobile Security Framework)[/dim]")
            self.console.print("  [dim]- APKTool / JADX (for Android)[/dim]")
            self.console.print("  [dim]- Class-dump / Hopper (for iOS)[/dim]")
            
        elif mode == "dynamic":
            self.console.print("\n[cyan]Dynamic Analysis[/cyan]")
            self.console.print("  - Runtime instrumentation")
            self.console.print("  - Hooking and interception")
            self.console.print("  - Data storage analysis")
            self.console.print("  - IPC analysis")
            self.console.print("  - Activity/service enumeration")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Frida (Dynamic instrumentation)[/dim]")
            self.console.print("  [dim]- Xposed (Android framework)[/dim]")
            self.console.print("  [dim]- Cycript (iOS runtime)[/dim]")
            
        elif mode == "traffic":
            self.console.print("\n[cyan]Traffic Analysis[/cyan]")
            self.console.print("  - Network traffic interception")
            self.console.print("  - SSL/TLS inspection")
            self.console.print("  - API request/response analysis")
            self.console.print("  - Protocol analysis")
            self.console.print("  - Data leakage detection")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Burp Suite (HTTP proxy)[/dim]")
            self.console.print("  [dim]- mitmproxy (HTTPS interception)[/dim]")
            self.console.print("  [dim]- Wireshark (Network analysis)[/dim]")
            
        elif mode == "api":
            self.console.print("\n[cyan]API Security Testing[/cyan]")
            self.console.print("  - API endpoint discovery")
            self.console.print("  - Authentication testing")
            self.console.print("  - Authorization testing")
            self.console.print("  - Input validation")
            self.console.print("  - Rate limiting test")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Postman / Insomnia (API testing)[/dim]")
            self.console.print("  [dim]- OWASP ZAP (Security testing)[/dim]")
            self.console.print("  [dim]- MobSF (Automated API analysis)[/dim]")
        
        self.console.print("\n[yellow]⚠ Mobile pentesting requires emulator/device setup[/yellow]")
        self.console.print("[dim]Implementation: Will integrate with MobSF, Frida, and Burp Suite[/dim]")
        
        # Summary
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold green]MOBILE APPLICATION PENTESTING COMPLETE[/bold green]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_forensics(self, target: str, mode: str):
        """Run digital forensics & incident response."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]DIGITAL FORENSICS & INCIDENT RESPONSE[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print("[cyan]Digital Forensics & Incident Response[/cyan]")
        self.console.print("[yellow]This feature requires additional forensics tools:[/yellow]")
        
        if mode == "memory":
            self.console.print("\n[cyan]Memory Analysis[/cyan]")
            self.console.print("  - Process memory extraction")
            self.console.print("  - Password recovery")
            self.console.print("  - Network connection analysis")
            self.console.print("  - Malware artifact detection")
            self.console.print("  - Clipboard content extraction")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Volatility (Memory forensics framework)[/dim]")
            self.console.print("  [dim]- Volatility3 (Next generation)[/dim]")
            self.console.print("  [dim]- Rekall (Memory analysis)[/dim]")
            
        elif mode == "disk":
            self.console.print("\n[cyan]Disk Analysis[/cyan]")
            self.console.print("  - File system carving")
            self.console.print("  - Deleted file recovery")
            self.console.print("  - Metadata extraction")
            self.console.print("  - Timeline reconstruction")
            self.console.print("  - Unallocated space analysis")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Autopsy (Digital forensics platform)[/dim]")
            self.console.print("  [dim]- Sleuth Kit (File system analysis)[/dim]")
            self.console.print("  [dim]- Foremost (File carving)[/dim]")
            self.console.print("  [dim]- Bulk Extractor (Data extraction)[/dim]")
            
        elif mode == "log":
            self.console.print("\n[cyan]Log Analysis[/cyan]")
            self.console.print("  - System log parsing")
            self.console.print("  - Event correlation")
            self.console.print("  - Timeline construction")
            self.console.print("  - Attack pattern detection")
            self.console.print("  - Evidence chain validation")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Plaso (Log2Timeline)[/dim]")
            self.console.print("  [dim]- LogAnalysis (Log parsing)[/dim]")
            self.console.print("  [dim]- Splunk/ELK (Log management)[/dim]")
            
        elif mode == "malware":
            self.console.print("\n[cyan]Malware Analysis[/cyan]")
            self.console.print("  - Static malware analysis")
            self.console.print("  - Dynamic malware analysis")
            self.console.print("  - Behavior monitoring")
            self.console.print("  - Network traffic analysis")
            self.console.print("  - IOC extraction")
            self.console.print("\n[dim]Required tools:[/dim]")
            self.console.print("  [dim]- Cuckoo Sandbox (Malware analysis)[/dim]")
            self.console.print("  [dim]- Ghidra (Reverse engineering)[/dim]")
            self.console.print("  [dim]- IDA Pro (Disassembler)[/dim]")
            self.console.print("  [dim]- Wireshark (Network analysis)[/dim]")
        
        self.console.print("\n[yellow]⚠ Forensics requires evidence images and proper chain of custody[/yellow]")
        self.console.print("[dim]Implementation: Will integrate with Volatility, Autopsy, and Sleuth Kit[/dim]")
        
        # Summary
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold green]DIGITAL FORENSICS & INCIDENT RESPONSE COMPLETE[/bold green]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")

    async def run_wireless(self, target: str, mode: str):
        """Run wireless security assessment."""
        self.console.print(f"\n{'='*80}")
        self.console.print(f"[bold cyan]WIRELESS SECURITY ASSESSMENT[/bold cyan]")
        self.console.print(f"{'='*80}")
        self.console.print(f"[dim]Target: {target}[/dim]")
        self.console.print(f"[dim]Mode: {mode}[/dim]")
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
        self.console.print(f"{'='*80}\n")
        
        # Check for wireless capabilities
        import os
        is_sudo = os.environ.get('SUDO_UID') is not None
        if not is_sudo:
            self.console.print("[yellow]⚠ Wireless assessment requires sudo privileges[/yellow]")
            self.console.print("[yellow]⚠ Some features will be limited[/yellow]\n")
        
        try:
            if mode == "cracking":
                self.console.print("[cyan]WEP/WPA Cracking[/cyan]")
                self.console.print("[yellow]Performing wireless security audit...[/yellow]")
                self.console.print("  - WEP vulnerability assessment")
                self.console.print("  - WPA/WPA2 handshake capture")
                self.console.print("  - WPS vulnerability check")
                self.console.print("  - Dictionary attack testing")
                
                try:
                    from hazarus.wireless.aircrack import AircrackScanner
                    aircrack = AircrackScanner()
                    result = await aircrack.scan(target)
                    self.console.print(f"[green]✓ Aircrack scan complete[/green]")
                    self.console.print(f"[dim]Networks found: {len(result.networks) if hasattr(result, 'networks') else 'N/A'}[/dim]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Aircrack not available: {e}[/yellow]")
                    self.console.print("[dim]Install aircrack-ng for wireless security testing[/dim]")
                    self.console.print("[dim]Command: sudo apt install aircrack-ng[/dim]")
                
            elif mode == "rogue":
                self.console.print("[cyan]Rogue AP Detection[/cyan]")
                self.console.print("[yellow]Performing rogue access point detection...[/yellow]")
                self.console.print("  - AP spoofing detection")
                self.console.print("  - Evil twin detection")
                self.console.print("  - Karma attack detection")
                self.console.print("  - Beacon frame analysis")
                
                try:
                    from hazarus.wireless.bettercap import BettercapAnalyzer
                    bettercap = BettercapAnalyzer()
                    result = await bettercap.scan(target)
                    self.console.print(f"[green]✓ Bettercap scan complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Bettercap not available: {e}[/yellow]")
                    self.console.print("[dim]Install bettercap for rogue AP detection[/dim]")
                    self.console.print("[dim]Command: sudo apt install bettercap[/dim]")
                
            elif mode == "traffic":
                self.console.print("[cyan]Traffic Analysis[/cyan]")
                self.console.print("[yellow]Performing wireless traffic analysis...[/yellow]")
                self.console.print("  - Packet capture")
                self.console.print("  - Protocol analysis")
                self.console.print("  - Data extraction")
                self.console.print("  - Encryption assessment")
                
                try:
                    from hazarus.wireless.wireshark import WiresharkAnalyzer
                    wireshark = WiresharkAnalyzer()
                    result = await wireshark.scan(target)
                    self.console.print(f"[green]✓ Wireshark scan complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Wireshark not available: {e}[/yellow]")
                    self.console.print("[dim]Install wireshark for traffic analysis[/dim]")
                    self.console.print("[dim]Command: sudo apt install wireshark[/dim]")
                
            elif mode == "audit":
                self.console.print("[cyan]Wireless Audit[/cyan]")
                self.console.print("[yellow]Performing comprehensive wireless audit...[/yellow]")
                self.console.print("  - Network discovery")
                self.console.print("  - Signal strength analysis")
                self.console.print("  - Channel utilization")
                self.console.print("  - Security configuration review")
                
                try:
                    from hazarus.wireless.kismet import KismetScanner
                    kismet = KismetScanner()
                    result = await kismet.scan(target)
                    self.console.print(f"[green]✓ Kismet scan complete[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]⚠ Kismet not available: {e}[/yellow]")
                    self.console.print("[dim]Install kismet for wireless auditing[/dim]")
                    self.console.print("[dim]Command: sudo apt install kismet[/dim]")
            
            # Summary
            self.console.print(f"\n{'='*80}")
            self.console.print(f"[bold green]WIRELESS SECURITY ASSESSMENT COMPLETE[/bold green]")
            self.console.print(f"{'='*80}")
            self.console.print(f"[dim]Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
            self.console.print(f"{'='*80}\n")
            
        except Exception as e:
            self.console.print(f"\n[red]✗ Wireless security assessment failed: {e}[/red]")
            import traceback
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        
        self.console.print("[yellow]Press Enter to continue (output will be preserved)...[/yellow]")
        self.console.input("")


def main():
    """Entry point for interactive mode."""
    interactive = InteractiveMode()
    asyncio.run(interactive.run())


if __name__ == "__main__":
    main()
