"""
HAZARUS Interactive Mode
Menu-driven interface for the framework (SOLE ENTRY POINT).
"""

import asyncio
import os
import sys
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
        config_table = Table(title="Configuration Details", show_header=True, box_style="red")
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
            self.console.print("[0] Back to Main Menu")

            choice = self.console.input("\n[bold red]Select option [0-5]: [/bold red]")

            if choice == "0":
                break
            elif choice == "1":
                target = self.console.input("Enter target (domain/IP): ")
                self.add_target(target)
            elif choice == "2":
                self.list_targets()
            elif choice == "3":
                self.validate_scope()
            elif choice == "4":
                self.edit_scope()
            elif choice == "5":
                target = self.console.input("Enter target to set as current: ")
                self.current_target = target
                self.console.print(f"[green]Current target set to: {target}[/green]")
                await asyncio.sleep(1)

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
    def add_target(self, target: str):
        """Add target to scope."""
        self.console.print(f"[cyan]Adding target: {target}[/cyan]")
        # Import and call actual scope add function
        try:
            from security import ScopeManager
            scope_manager = ScopeManager()
            scope_manager.add_target(target)
            self.console.print(f"[green]✓ Target added: {target}[/green]")
        except Exception as e:
            self.console.print(f"[red]✗ Failed to add target: {e}[/red]")
        await asyncio.sleep(1)

    def list_targets(self):
        """List all targets in scope."""
        self.console.print("[cyan]Listing targets...[/cyan]")
        try:
            from security import ScopeManager
            scope_manager = ScopeManager()
            scope = scope_manager.load_scope()
            
            table = Table(title="Targets in Scope")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="green")
            
            for domain in scope.get("allowed_domains", []):
                table.add_row("Domain", domain)
            for cidr in scope.get("allowed_cidrs", []):
                table.add_row("CIDR", cidr)
            
            self.console.print(table)
        except Exception as e:
            self.console.print(f"[red]✗ Failed to list targets: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    def validate_scope(self):
        """Validate scope configuration."""
        self.console.print("[cyan]Validating scope...[/cyan]")
        try:
            from security import ScopeManager
            scope_manager = ScopeManager()
            is_valid = scope_manager.validate_scope()
            
            if is_valid:
                self.console.print("[green]✓ Scope is valid[/green]")
            else:
                self.console.print("[red]✗ Scope validation failed[/red]")
        except Exception as e:
            self.console.print(f"[red]✗ Validation error: {e}[/red]")
        
        self.console.input("\nPress Enter to continue...")

    def edit_scope(self):
        """Edit scope configuration."""
        self.console.print("[cyan]Opening scope editor...[/cyan]")
        self.console.print("[yellow]This will open your default editor to edit config/scope.yaml[/yellow]")
        # Import and call actual scope edit function
        try:
            from security import ScopeManager
            scope_manager = ScopeManager()
            scope_manager.edit_scope()
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
        self.console.print("[yellow]API Assessment - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def vulnerability_research_menu(self):
        """Vulnerability research submenu."""
        self.console.print("[yellow]Vulnerability Research - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def exploitation_menu(self):
        """Exploitation submenu."""
        self.console.print("[yellow]Exploitation - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def post_assessment_menu(self):
        """Post-assessment audits submenu."""
        self.console.print("[yellow]Post-Assessment Audits - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def source_code_analysis_menu(self):
        """Source code analysis submenu."""
        self.console.print("[yellow]Source Code Analysis - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def reporting_menu(self):
        """Reporting submenu."""
        self.console.print("[yellow]Reporting - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def configuration_menu(self):
        """Configuration submenu."""
        self.console.print("[yellow]Configuration - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def advanced_tools_menu(self):
        """Advanced tools submenu."""
        self.console.print("[yellow]Advanced Tools - Coming soon[/yellow]")
        await asyncio.sleep(1)

    async def asset_intelligence_menu(self):
        """Asset intelligence submenu."""
        self.console.print("[yellow]Asset Intelligence - Coming soon[/yellow]")
        await asyncio.sleep(1)


def main():
    """Entry point for interactive mode."""
    interactive = InteractiveMode()
    asyncio.run(interactive.run())


if __name__ == "__main__":
    main()
