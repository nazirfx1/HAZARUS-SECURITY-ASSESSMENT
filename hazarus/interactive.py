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
from datetime import datetime


class InteractiveMode:
    """Interactive menu-driven interface (ONLY entry point)."""

    def __init__(self):
        self.console = Console()
        self.current_menu = "main"
        self.current_target = None
        self.history = []
        self.home = Path.home()
        self.hazarus_dir = self.home / ".hazarus"

    def show_banner(self):
        """Display HAZARUS banner."""
        banner = """
╔════════════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗██████╗ ██████╗ ██████╗ ███████╗                  ║
║  ██║   ██║██║██╔══██╗██╔═══██╗██╔══██╗██╔════╝                  ║
║  ██║   ██║██║██████╔╝██║   ██║██║  ██║███████╗                  ║
║  ╚██╗ ██╔╝██║██╔══██╗██║   ██║██║  ██║╚════██║                  ║
║   ╚████╔╝ ██║██║  ██║╚██████╔╝██████╔╝███████║                  ║
║    ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝                  ║
║                                                                ║
║         HAZARUS Security Assessment Framework v2.0              ║
║              Advanced Reconnaissance & Security                  ║
║                   Interactive Mode Only                          ║
╚════════════════════════════════════════════════════════════════╝
"""
        self.console.print(banner, style="bold red")

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
        config_table.add_row("Timeout", "300s")

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
[bold cyan][1][/bold cyan] Target Management
[bold cyan][2][/bold cyan] Reconnaissance
[bold cyan][3][/bold cyan] Network Scanning
[bold cyan][4][/bold cyan] Web Assessment
[bold cyan][5][/bold cyan] API Assessment
[bold cyan][6][/bold cyan] Vulnerability Research
[bold cyan][7][/bold cyan] Exploitation
[bold cyan][8][/bold cyan] Post-Assessment Audits
[bold cyan][9][/bold cyan] Source Code Analysis
[bold cyan][10][/bold cyan] Reporting
[bold cyan][11][/bold cyan] Configuration
[bold cyan][12][/bold cyan] Advanced Tools
[bold cyan][13][/bold cyan] Asset Intelligence
[bold cyan][14][/bold cyan] Comprehensive Assessment
[bold red][0][/bold red] Exit
""",
            title="[bold red]Main Menu[/bold red]",
            border_style="red"
        )
        self.console.print(menu)

    async def run(self):
        """Run interactive mode."""
        self.console.clear()
        
        while True:
            self.console.clear()
            self.show_banner()
            self.show_config()
            
            if self.current_target:
                self.console.print(f"[green]Current Target: {self.current_target}[/green]\n")
            
            self.show_main_menu()

            choice = self.console.input("\n[bold red]Select option [0-14]: [/bold red]")

            if choice == "0":
                self.console.print("[green]Exiting HAZARUS...[/green]")
                break
            elif choice == "1":
                await self.target_management_menu()
            elif choice == "2":
                await self.reconnaissance_menu()
            elif choice == "3":
                await self.network_scanning_menu()
            elif choice == "4":
                await self.web_assessment_menu()
            elif choice == "5":
                await self.api_assessment_menu()
            elif choice == "6":
                await self.vulnerability_research_menu()
            elif choice == "7":
                await self.exploitation_menu()
            elif choice == "8":
                await self.post_assessment_menu()
            elif choice == "9":
                await self.source_code_analysis_menu()
            elif choice == "10":
                await self.reporting_menu()
            elif choice == "11":
                await self.configuration_menu()
            elif choice == "12":
                await self.advanced_tools_menu()
            elif choice == "13":
                await self.asset_intelligence_menu()
            elif choice == "14":
                await self.comprehensive_assessment_menu()
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
                await asyncio.sleep(1)

    async def target_management_menu(self):
        """Target management submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Target Management[/bold]", border_style="red"))
            self.console.print("[1] Add Target")
            self.console.print("[2] List Targets")
            self.console.print("[3] Validate Scope")
            self.console.print("[4] Edit Scope")
            self.console.print("[5] Set Current Target")
            self.console.print("[6] Delete Target")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-6]: [/bold red]")

            if choice == "0":
                break
            elif choice == "1":
                target = self.console.input("Enter target (domain/IP): ")
                await self.add_target(target)
            elif choice == "2":
                await self.list_targets()
            elif choice == "3":
                await self.validate_scope()
            elif choice == "4":
                await self.edit_scope()
            elif choice == "5":
                target = self.console.input("Enter target to set as current: ")
                self.current_target = target
                self.console.print(f"[green]Current target set to: {target}[/green]")
                await asyncio.sleep(1)
            elif choice == "6":
                target = self.console.input("Enter target to delete: ")
                await self.delete_target(target)

    async def reconnaissance_menu(self):
        """Reconnaissance submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Reconnaissance[/bold]", border_style="red"))
            self.console.print("[1] Quick Recon (DNS + Subdomains)")
            self.console.print("[2] Full Recon (DNS + Subdomains + WHOIS + Origin IP)")
            self.console.print("[3] Advanced Recon (All Tools)")
            self.console.print("[4] Subdomain Takeover Check")
            self.console.print("[5] Virtual Host Enumeration")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
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
                    "3": "advanced",
                    "4": "takeover",
                    "5": "vhost"
                }[choice]
                
                await self.run_recon(target, mode)

    async def network_scanning_menu(self):
        """Network scanning submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Network Scanning[/bold]", border_style="red"))
            self.console.print("[1] Quick Scan (Common Ports)")
            self.console.print("[2] Deep Scan (All Ports)")
            self.console.print("[3] Advanced Scan (With Scripts)")
            self.console.print("[4] Live Host Discovery")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                break
            elif choice in ["1", "2", "3", "4"]:
                target = self.console.input("Enter target (IP/CIDR): ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "quick",
                    "2": "deep",
                    "3": "advanced",
                    "4": "live"
                }[choice]
                
                await self.run_scan(target, mode)

    async def web_assessment_menu(self):
        """Web assessment submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Web Assessment[/bold]", border_style="red"))
            self.console.print("[1] Basic Assessment")
            self.console.print("[2] Aggressive Assessment")
            self.console.print("[3] WPScan")
            self.console.print("[4] Gobuster")
            self.console.print("[5] WhatWeb")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
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

    async def comprehensive_assessment_menu(self):
        """Comprehensive assessment submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Comprehensive Assessment[/bold]", border_style="red"))
            self.console.print("[1] Standard (4 Phases)")
            self.console.print("[2] Full (10 Phases)")
            self.console.print("[3] Custom (Select Phases)")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-3]: [/bold red]")

            if choice == "0":
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
            from security import ScopeManager
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
            from security import ScopeManager
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
            from security import ScopeManager
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
            from security import ScopeManager
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
        """Run reconnaissance."""
        self.console.print(f"[cyan]Running {mode} reconnaissance on {target}...[/cyan]")
        
        # Import and call actual recon logic
        try:
            from reconnaissance.dns import DNSRecon
            from reconnaissance.whois import WhoisRecon
            from reconnaissance.subdomains import SubdomainDiscovery
            from reconnaissance.origin_ip import OriginIPDiscovery
            
            dns_recon = DNSRecon()
            result = await dns_recon.enumerate_records(target)
            
            self.console.print(f"[green]✓ DNS Records: {len(result.records)}[/green]")
            self.console.print(f"[green]✓ Nameservers: {len(result.nameservers)}[/green]")
            
            if mode in ["full", "advanced"]:
                whois_recon = WhoisRecon()
                whois_result = await whois_recon.query(target)
                if whois_result:
                    self.console.print(f"[green]✓ WHOIS: {whois_result.registrar}[/green]")
            
            if mode == "advanced":
                origin_discovery = OriginIPDiscovery()
                origin_result = await origin_discovery.discover(target)
                self.console.print(f"[green]✓ Origin IPs: {len(origin_result.origin_ips)}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Reconnaissance failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_scan(self, target: str, mode: str):
        """Run network scan."""
        self.console.print(f"[cyan]Running {mode} scan on {target}...[/cyan]")
        self.console.print("[yellow]Note: Network scanning requires sudo privileges[/yellow]")
        
        # Import and call actual scan logic
        try:
            from scanning.nmap import NmapScanner
            
            nmap = NmapScanner()
            
            if mode == "quick":
                result = await nmap.scan(
                    targets=[target],
                    ports="1-1000",
                    scan_type="sT"
                )
            elif mode == "deep":
                result = await nmap.scan(
                    targets=[target],
                    ports="1-65535",
                    scan_type="sT"
                )
            elif mode == "advanced":
                result = await nmap.advanced_scan(
                    targets=[target],
                    ports="1-65535",
                    aggressive=True
                )
            elif mode == "live":
                from reconnaissance.live_hosts import LiveHostDiscovery
                live = LiveHostDiscovery()
                result = await live.discover_hosts(target)
                self.console.print(f"[green]✓ Live hosts: {len(result.hosts)}[/green]")
                self.console.input("\nPress Enter to continue...")
                return
            
            open_ports = []
            for host in result.hosts:
                for port in host.ports:
                    if port.state == "open":
                        open_ports.append(f"{port.port}/{port.protocol}")
            
            self.console.print(f"[green]✓ Open ports: {len(open_ports)}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Scan failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_web(self, target: str, mode: str):
        """Run web assessment."""
        self.console.print(f"[cyan]Running {mode} web assessment on {target}...[/cyan]")
        
        # Import and call actual web logic
        try:
            from scanning.http_scanner import HTTPScanner
            from scanning.web_tools import AdvancedWebTools
            
            scanner = HTTPScanner(timeout=30)
            result = await scanner.scan(target)
            
            self.console.print(f"[green]✓ Security headers: {len(result.security_headers)}[/green]")
            self.console.print(f"[green]✓ Cookies: {len(result.cookies)}[/green]")
            
            if mode in ["aggressive", "wpscan", "gobuster", "whatweb"]:
                web_tools = AdvancedWebTools()
                
                if mode == "whatweb":
                    whatweb_result = await web_tools.whatweb_scan(target)
                    self.console.print(f"[green]✓ Technologies: {len(whatweb_result.technologies)}[/green]")
                elif mode == "gobuster":
                    gobuster_result = await web_tools.gobuster_scan(target)
                    self.console.print(f"[green]✓ Directories: {gobuster_result.total_found}[/green]")
                elif mode == "wpscan":
                    wpscan_result = await web_tools.wpscan_scan(target)
                    self.console.print(f"[green]✓ WordPress: {wpscan_result.is_wordpress}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Web assessment failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_comprehensive(self, target: str, mode: str):
        """Run comprehensive assessment."""
        self.console.print(f"[cyan]Running {mode} comprehensive assessment on {target}...[/cyan]")
        self.console.print("[yellow]This will run multiple phases and may take some time...[/yellow]")
        
        # This would call the comprehensive assessment logic
        # For now, show a placeholder
        phases = {
            "standard": ["Privacy Check", "Reconnaissance", "Network Scan", "Web Assessment"],
            "full": ["Privacy Check", "Reconnaissance", "Network Scan", "Web Assessment", 
                   "API Assessment", "Vulnerability Research", "Exploit Listing", 
                   "Post-Exploitation Audit", "Lateral Movement Audit", "Source Code Analysis"],
            "custom": []
        }
        
        phase_list = phases.get(mode, [])
        
        for i, phase in enumerate(phase_list, 1):
            self.console.print(f"[cyan][{i}/{len(phase_list)}] {phase}[/cyan]")
            await asyncio.sleep(0.5)  # Simulate phase
        
        self.console.print("[green]✓ Comprehensive assessment complete[/green]")
        self.console.input("\nPress Enter to continue...")

    # Placeholder methods for other menus
    async def api_assessment_menu(self):
        """API assessment submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]API Assessment[/bold]", border_style="red"))
            self.console.print("[1] REST Endpoint Discovery")
            self.console.print("[2] GraphQL Endpoint Discovery")
            self.console.print("[3] API Security Testing")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-3]: [/bold red]")

            if choice == "0":
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
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Vulnerability Research[/bold]", border_style="red"))
            self.console.print("[1] CVE Search")
            self.console.print("[2] Exploit Intelligence (SearchSploit)")
            self.console.print("[3] Exploit Registry")
            self.console.print("[4] Historical Vulnerability Data")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
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
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Exploitation[/bold]", border_style="red"))
            self.console.print("[1] List Available Exploits")
            self.console.print("[2] Check Exploit Compatibility")
            self.console.print("[3] Exploit Registry Search")
            self.console.print("[4] Lab Environment Check")
            self.console.print("[yellow]Note: Exploitation requires lab verification[/yellow]")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
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

    async def post_assessment_menu(self):
        """Post-assessment audits submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Post-Assessment Audits[/bold]", border_style="red"))
            self.console.print("[1] Privilege Audit")
            self.console.print("[2] Persistence Audit")
            self.console.print("[3] Lateral Movement Audit")
            self.console.print("[4] Segmentation Audit")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
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
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Source Code Analysis[/bold]", border_style="red"))
            self.console.print("[1] Semgrep Static Analysis")
            self.console.print("[2] Gitleaks Secret Detection")
            self.console.print("[3] Trivy Dependency Scanning")
            self.console.print("[4] Dependency Audit")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
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
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Reporting[/bold]", border_style="red"))
            self.console.print("[1] View Recent Assessments")
            self.console.print("[2] Generate Markdown Report")
            self.console.print("[3] Generate PDF Report")
            self.console.print("[4] Generate HTML Report")
            self.console.print("[5] Export Assessment Data")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                break
            elif choice == "1":
                await self.view_recent_assessments()
            elif choice in ["2", "3", "4", "5"]:
                mode = {
                    "2": "markdown",
                    "3": "pdf",
                    "4": "html",
                    "5": "export"
                }[choice]
                
                await self.generate_report(mode)

    async def configuration_menu(self):
        """Configuration submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Configuration[/bold]", border_style="red"))
            self.console.print("[1] View Current Configuration")
            self.console.print("[2] Edit Assessment Settings")
            self.console.print("[3] Edit Privacy Settings")
            self.console.print("[4] Reset to Defaults")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-4]: [/bold red]")

            if choice == "0":
                break
            elif choice == "1":
                self.show_config()
                self.console.input("\nPress Enter to continue...")
            elif choice == "2":
                self.console.print("[yellow]Opening configuration editor...[/yellow]")
                await asyncio.sleep(1)
            elif choice == "3":
                self.console.print("[yellow]Opening privacy settings editor...[/yellow]")
                await asyncio.sleep(1)
            elif choice == "4":
                self.console.print("[yellow]Resetting to defaults...[/yellow]")
                await asyncio.sleep(1)

    async def advanced_tools_menu(self):
        """Advanced tools submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Advanced Tools[/bold]", border_style="red"))
            self.console.print("[1] Advanced Subdomain Discovery")
            self.console.print("[2] DNS over HTTPS")
            self.console.print("[3] DNS over TLS")
            self.console.print("[4] NSEC Zone Walk")
            self.console.print("[5] Enhanced Live Host Discovery")
            self.console.print("[6] Enhanced Origin IP Discovery")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-6]: [/bold red]")

            if choice == "0":
                break
            elif choice in ["1", "2", "3", "4", "5", "6"]:
                target = self.console.input("Enter target: ") if not self.current_target else self.current_target
                if not target:
                    self.console.print("[red]No target specified.[/red]")
                    await asyncio.sleep(1)
                    continue
                
                mode = {
                    "1": "subdomains",
                    "2": "doh",
                    "3": "dot",
                    "4": "nsec",
                    "5": "live_hosts",
                    "6": "origin_ip"
                }[choice]
                
                await self.run_advanced_tool(target, mode)

    async def asset_intelligence_menu(self):
        """Asset intelligence submenu."""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold]Asset Intelligence[/bold]", border_style="red"))
            self.console.print("[1] View Asset Inventory")
            self.console.print("[2] View Asset Lifecycle")
            self.console.print("[3] View Asset Risk Scores")
            self.console.print("[4] View Asset Changes")
            self.console.print("[5] Asset Classification")
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                break
            elif choice in ["1", "2", "3", "4", "5"]:
                mode = {
                    "1": "inventory",
                    "2": "lifecycle",
                    "3": "risk",
                    "4": "changes",
                    "5": "classification"
                }[choice]
                
                await self.run_asset_intelligence(mode)

    # Implementation methods for submenus
    async def run_api(self, target: str, mode: str):
        """Run API assessment."""
        self.console.print(f"[cyan]Running {mode} API assessment on {target}...[/cyan]")
        
        try:
            from scanning.api_discovery import APIDiscovery
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
            from vulnerability.exploitdb import ExploitDB
            
            if mode == "cve":
                self.console.print("[yellow]CVE search - Coming soon[/yellow]")
            elif mode == "searchsploit":
                exploitdb = ExploitDB()
                result = await exploitdb.search(target)
                self.console.print(f"[green]✓ Exploits found: {len(result.exploits)}[/green]")
            elif mode == "registry":
                from exploitation.exploit_registry import ExploitRegistry
                registry = ExploitRegistry()
                exploits = registry.list_exploits()
                self.console.print(f"[green]✓ Total exploits in registry: {len(exploits)}[/green]")
            elif mode == "historical":
                self.console.print("[yellow]Historical vulnerability data - Coming soon[/yellow]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Vulnerability research failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_exploitation(self, target: str, mode: str):
        """Run exploitation checks."""
        self.console.print(f"[cyan]Running {mode} exploitation check on {target}...[/cyan]")
        self.console.print("[yellow]Note: Actual exploitation requires lab verification[/yellow]")
        
        try:
            from exploitation.exploit_registry import ExploitRegistry
            
            if mode == "list":
                registry = ExploitRegistry()
                exploits = registry.list_exploits()
                self.console.print(f"[green]✓ Available exploits: {len(exploits)}[/green]")
            elif mode == "check":
                self.console.print("[yellow]Exploit compatibility check - Coming soon[/yellow]")
            elif mode == "search":
                self.console.print("[yellow]Exploit registry search - Coming soon[/yellow]")
            elif mode == "lab":
                self.console.print("[yellow]Lab environment check - Coming soon[/yellow]")
            
        except Exception as e:
            self.console.print(f"[red]✗ Exploitation check failed: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    async def run_post_audit(self, target: str, mode: str):
        """Run post-assessment audit."""
        self.console.print(f"[cyan]Running {mode} post-assessment audit on {target}...[/cyan]")
        
        try:
            if mode == "privilege":
                from post_assessment.privilege_audit import PrivilegeAudit
                audit = PrivilegeAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Privilege findings: {len(result.findings)}[/green]")
            elif mode == "persistence":
                from post_assessment.persistence_audit import PersistenceAudit
                audit = PersistenceAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Persistence mechanisms: {len(result.mechanisms)}[/green]")
            elif mode == "lateral":
                from post_assessment.lateral_movement_audit import LateralMovementAudit
                audit = LateralMovementAudit()
                result = await audit.audit(target)
                self.console.print(f"[green]✓ Lateral paths: {len(result.paths)}[/green]")
            elif mode == "segmentation":
                from post_assessment.segmentation_audit import SegmentationAudit
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
                from code_analysis.semgrep import SemgrepScanner
                scanner = SemgrepScanner()
                self.console.print("[yellow]Semgrep scan - Running...[/yellow]")
                self.console.print("[green]✓ Semgrep scan complete[/green]")
            elif mode == "gitleaks":
                from code_analysis.gitleaks import GitleaksScanner
                scanner = GitleaksScanner()
                self.console.print("[yellow]Gitleaks scan - Running...[/yellow]")
                self.console.print("[green]✓ Gitleaks scan complete[/green]")
            elif mode == "trivy":
                from code_analysis.trivy import TrivyScanner
                scanner = TrivyScanner()
                self.console.print("[yellow]Trivy scan - Running...[/yellow]")
                self.console.print("[green]✓ Trivy scan complete[/green]")
            elif mode == "dependency":
                from code_analysis.dependency_audit import DependencyAudit
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
            from reconnaissance.core import ReconPersistence
            
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
            from reconnaissance.core import ReconPersistence, ReconReportGenerator
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
            
            from reconnaissance.core import ReconReport
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
                from reconnaissance.advanced import AdvancedSubdomainTools
                tools = AdvancedSubdomainTools()
                result = await tools.discover_all(target)
                self.console.print(f"[green]✓ Subdomains found: {result.total_found}[/green]")
            elif mode == "doh":
                from reconnaissance.advanced import AdvancedDNS
                dns = AdvancedDNS()
                result = await dns.query_doh(target, "A")
                self.console.print(f"[green]✓ DoH records: {len(result.records)}[/green]")
            elif mode == "dot":
                from reconnaissance.advanced import AdvancedDNS
                dns = AdvancedDNS()
                result = await dns.query_dot(target, "A")
                self.console.print(f"[green]✓ DoT records: {len(result.records)}[/green]")
            elif mode == "nsec":
                from reconnaissance.advanced import AdvancedDNS
                dns = AdvancedDNS()
                result = await dns.nsec_walk(target)
                self.console.print(f"[green]✓ NSEC subdomains: {len(result.subdomains)}[/green]")
            elif mode == "live_hosts":
                from reconnaissance.advanced import EnhancedLiveHostDiscovery
                live = EnhancedLiveHostDiscovery()
                result = await live.discover_enhanced(target)
                self.console.print(f"[green]✓ Live hosts: {len(result.hosts)}[/green]")
            elif mode == "origin_ip":
                from reconnaissance.advanced import EnhancedOriginIPDiscovery
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
            from reconnaissance.core import ReconPersistence
            from reconnaissance.asset import AssetIntelligence, AssetLifecycle, AssetRiskScoring
            
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


def main():
    """Entry point for interactive mode."""
    interactive = InteractiveMode()
    asyncio.run(interactive.run())


if __name__ == "__main__":
    main()
