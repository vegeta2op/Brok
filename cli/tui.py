"""Interactive TUI using Rich - Similar to Claude Code's interface"""

import asyncio
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.tree import Tree
from datetime import datetime
from typing import Optional, List, Dict, Any
import sys

from backend.agent import PentestAgent
from backend.models import ScanRequest, ScanMode, ScanStatus, Vulnerability, SeverityLevel
from backend.auth import AuthorizationManager
from backend.auth.session_manager import SessionManager
from backend.scan_results_manager import ScanResultsManager


class InteractiveTUI:
    """Interactive Terminal User Interface for JimCrow"""
    
    def __init__(self):
        self.console = Console()
        self.agent = PentestAgent(
            log_callback=self._add_log_message  # Pass callback for logging
        )
        self.auth_manager = AuthorizationManager()
        self.session_manager = SessionManager()
        self.results_manager = ScanResultsManager()
        
        # State
        self.current_scan = None
        self.current_scan_session = None  # Scan session from results manager
        self.vulnerabilities: List[Vulnerability] = []
        self.scan_progress = {
            'phase': 'idle',
            'urls_scanned': 0,
            'urls_total': 0,
            'vulns_found': 0,
            'current_action': ''
        }
        self.messages: List[Dict[str, str]] = []
        self.plan_messages: List[str] = []  # Planner agent messages
        self.executor_messages: List[str] = []  # Executor agent messages
        self.current_request: str = ""  # Current HTTP request being made
        self.current_tool: str = ""  # Current tool being used
        self.recent_responses: List[str] = []  # Recent HTTP responses
        self.ai_requests: List[Dict[str, str]] = []  # AI model requests
        self.ai_responses: List[Dict[str, str]] = []  # AI model responses
        self.api_calls: List[Dict[str, Any]] = []  # API call monitoring
        self.tool_executions: List[Dict[str, Any]] = []  # Track actual tool executions (HTTP, curl, etc.)
        self.live = None
    
    async def run(self):
        """Main TUI loop"""
        # Clear screen and take over terminal like Claude Code
        self.console.clear()
        self._show_banner()
        
        while True:
            self.console.print("\n")
            choice = self._show_main_menu()
            
            if choice == "1":
                await self._scan_workflow()
            elif choice == "2":
                await self._view_history()
            elif choice == "3":
                await self._manage_targets()
            elif choice == "4":
                await self._knowledge_base()
            elif choice == "5":
                await self._settings()
            elif choice == "6":
                self.console.print("[yellow]Goodbye![/yellow]")
                break
            else:
                self.console.print("[red]Invalid choice[/red]")
    
    def _show_banner(self):
        """Show application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ░░░░░██╗██╗███╗░░░███╗░█████╗░██████╗░░█████╗░░██╗░░░██╗║
║     ░░░░░██║██║████╗░████║██╔══██╗██╔══██╗██╔══██╗░██║░░░██║║
║     ░░░░░██║██║██╔████╔██║██║░░╚═╝██████╔╝██║░░██║░╚██╗░██╔╝║
║     ██╗░░██║██║██║╚██╔╝██║██║░░██╗██╔══██╗██║░░██║░░╚████╔╝░║
║     ╚█████╔╝██║██║░╚═╝░██║╚█████╔╝██║░░██║╚█████╔╝░░░╚██╔╝░░║
║     ░╚════╝░╚═╝╚═╝░░░░░╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░░░░░╚═╝░░░║
║                                                              ║
║          Autonomous Penetration Testing Agent                ║
║                      v0.1.0                                  ║
╚══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")
        self.console.print("\n[dim]AI-Powered Security Testing with Safety First[/dim]\n")
    
    def _show_main_menu(self) -> str:
        """Show main menu and get user choice"""
        menu = Table.grid(padding=1)
        menu.add_column(style="cyan", justify="right")
        menu.add_column(style="white")
        
        menu.add_row("1.", "🎯 Start New Scan")
        menu.add_row("2.", "📊 View Scan History")
        menu.add_row("3.", "🔐 Manage Authorized Targets")
        menu.add_row("4.", "📚 Knowledge Base")
        menu.add_row("5.", "⚙️  Settings")
        menu.add_row("6.", "🚪 Exit")
        
        panel = Panel(menu, title="[bold]Main Menu[/bold]", border_style="cyan")
        self.console.print(panel)
        
        return Prompt.ask("\n[cyan]Choose an option[/cyan]", choices=["1", "2", "3", "4", "5", "6"])
    
    def _reset_scan_state(self):
        """Reset all scan state for a new scan"""
        self.current_scan = None
        self.current_scan_session = None
        self.vulnerabilities = []
        self.scan_progress = {
            'phase': 'idle',
            'urls_scanned': 0,
            'urls_total': 0,
            'vulns_found': 0,
            'current_action': ''
        }
        self.messages = []
        self.plan_messages = []
        self.executor_messages = []
        self.current_request = ""
        self.current_tool = ""
        self.recent_responses = []
        self.ai_requests = []
        self.ai_responses = []
        self.api_calls = []
        self.tool_executions = []
    
    async def _scan_workflow(self):
        """Interactive scan workflow"""
        # Reset state from previous scan
        self._reset_scan_state()
        
        self.console.clear()
        self.console.print(Panel("[bold cyan]New Scan[/bold cyan]", border_style="cyan"))
        
        # Get target URL
        target_url = Prompt.ask("\n[cyan]Enter target URL[/cyan]")
        
        # Parse domain for checks
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc
        
        # Check authorization
        if not self.auth_manager.is_authorized(target_url):
            self.console.print(f"\n[red]⚠️  Target {target_url} is not authorized![/red]")
            
            if Confirm.ask("[yellow]Do you want to authorize it now?[/yellow]"):
                # Add to authorized targets
                self.auth_manager.add_authorized_target(domain)
                self.console.print(f"[green]✓ Added {domain} to authorized targets[/green]")
                
                # Reload auth manager to ensure it's persisted
                self.auth_manager._load_config()
                
                # Also reload agent's auth manager
                self.agent.auth_manager._load_config()
                
                # Verify it was added
                if not self.auth_manager.is_authorized(target_url):
                    self.console.print(f"[red]Error: Failed to authorize {domain}. Please try again.[/red]")
                    return
            else:
                return
        
        # Check if authentication is required
        needs_auth = Confirm.ask(
            f"\n[yellow]Does {domain} require login?[/yellow]",
            default=False
        )
        
        if needs_auth:
            # Check if session exists
            if not self.session_manager.has_session(domain):
                self.console.print(f"\n[cyan]🔐 Setting up authentication for {domain}...[/cyan]\n")
                
                # Get login details
                login_url = Prompt.ask(
                    "Login page URL",
                    default=f"https://{domain}/login"
                )
                username = Prompt.ask("Username/Email")
                from getpass import getpass
                password = getpass("Password: ")
                
                # Optional: field selectors
                self.console.print("\n[dim]Optional: CSS selectors for form fields (press Enter to use defaults)[/dim]")
                username_field = Prompt.ask(
                    "Username field name/selector",
                    default="username"
                )
                password_field = Prompt.ask(
                    "Password field name/selector",
                    default="password"
                )
                
                # Save session
                credentials = {
                    "username": username,
                    "password": password,
                    "login_url": login_url,
                    "username_field": username_field,
                    "password_field": password_field
                }
                self.session_manager.add_session(domain, credentials)
                
                self.console.print(f"\n[green]✓ Authentication session saved for {domain}[/green]")
            else:
                self.console.print(f"\n[green]✓ Using existing authentication session for {domain}[/green]")
        
        # Use autonomous scan mode (no need to ask user)
        scan_mode = ScanMode.AUTONOMOUS
        
        self.console.print(f"\n[green]🤖 Starting autonomous AI scan of {target_url}...[/green]\n")
        
        # Run the scan with live display
        await self.run_scan(target_url, scan_mode.value)
    
    async def run_scan(self, target_url: str, mode: str):
        """Run a scan with live TUI updates"""
        
        # Create scan request
        scan_request = ScanRequest(
            target_url=target_url,
            mode=ScanMode(mode)
        )
        
        # Setup approval callback
        self.agent.set_approval_callback(self._approval_callback)
        
        # Create layout
        layout = self._create_scan_layout()
        
        # Run scan with live display
        with Live(layout, refresh_per_second=4, console=self.console) as live:
            self.live = live
            
            # Update phase to running
            self.scan_progress['phase'] = 'running'
            
            try:
                # Start scan
                result = await self.agent.scan(scan_request)
                
                self.scan_progress['phase'] = 'completed'
                self.vulnerabilities = result.vulnerabilities
                
                # Save scan results
                if self.current_scan_session:
                    final_results = {
                        'target_url': target_url,
                        'vulnerabilities': [v.model_dump() if hasattr(v, 'model_dump') else v.__dict__ for v in result.vulnerabilities],
                        'scanned_urls': getattr(result, 'scanned_urls', []),
                        'scan_status': result.status.value if hasattr(result.status, 'value') else str(result.status),
                        'scan_mode': mode
                    }
                    
                    completed_path = self.results_manager.complete_scan(
                        scan_id=self.current_scan_session['scan_id'],
                        final_results=final_results
                    )
                    
                    self.console.print(f"\n[green]✓ Scan results saved to: {completed_path}[/green]")
                
                # Final update
                live.update(self._create_scan_layout())
                
            except Exception as e:
                # Save failed scan
                if self.current_scan_session:
                    self.results_manager.fail_scan(
                        scan_id=self.current_scan_session['scan_id'],
                        error=str(e)
                    )
                
                self.console.print(f"\n[red]Error during scan: {str(e)}[/red]")
                self.scan_progress['phase'] = 'error'
                return
        
        # Show results
        await self._show_scan_results()
    
    def _create_scan_layout(self) -> Layout:
        """Create the scan display layout with separate plan and execution areas"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="monitoring", size=12),
            Layout(name="footer", size=3)
        )
        
        # Split main area into agents and findings
        layout["main"].split_row(
            Layout(name="agents", ratio=3),
            Layout(name="findings", ratio=1)
        )
        
        # Split agents area into planner, executor, and tool info
        layout["agents"].split_column(
            Layout(name="planner", ratio=1),
            Layout(name="executor", ratio=1),
            Layout(name="toolinfo", ratio=1)
        )
        
        # Header - show actual phase from agent context
        phase = self.scan_progress.get('phase', 'running')
        if phase == 'idle':
            phase = 'running'  # Don't show idle during active scan
        header_text = f"[bold cyan]🤖 Multi-Agent Pentest System - Phase: {phase.upper()}[/bold cyan]"
        layout["header"].update(Panel(header_text, border_style="cyan"))
        
        # Planner Agent panel
        planner_display = self._create_planner_display()
        layout["planner"].update(Panel(
            planner_display, 
            title="[bold cyan]📋 PLANNER AGENT[/bold cyan]",
            subtitle="Strategic Analysis & Planning",
            border_style="cyan"
        ))
        
        # Executor Agent panel
        executor_display = self._create_executor_display()
        layout["executor"].update(Panel(
            executor_display,
            title="[bold magenta]⚙️  EXECUTOR AGENT[/bold magenta]",
            subtitle="Tool Execution & Commands",
            border_style="magenta"
        ))
        
        # Tool Info panel (shows current request/response)
        toolinfo_display = self._create_toolinfo_display()
        layout["toolinfo"].update(Panel(
            toolinfo_display,
            title="[bold green]🔧 CURRENT TOOL & REQUEST[/bold green]",
            subtitle="Live HTTP Traffic",
            border_style="green"
        ))
        
        # Findings panel
        vuln_display = self._create_vulnerability_display()
        layout["findings"].update(Panel(
            vuln_display,
            title="[bold yellow]🔍 FINDINGS[/bold yellow]",
            border_style="yellow"
        ))
        
        # Split monitoring area into API health and verbose conversation
        layout["monitoring"].split_row(
            Layout(name="api_monitor", ratio=1),
            Layout(name="verbose", ratio=1)
        )
        
        # API Monitoring panel
        api_display = self._create_api_monitor_display()
        layout["api_monitor"].update(Panel(
            api_display,
            title="[bold blue]📡 API HEALTH[/bold blue]",
            subtitle=f"{self._get_model_name()} | 15/min",
            border_style="blue"
        ))
        
        # Verbose AI Conversation panel
        verbose_display = self._create_verbose_display()
        layout["verbose"].update(Panel(
            verbose_display,
            title="[bold magenta]💭 AI THINKING (VERBOSE)[/bold magenta]",
            subtitle="Live Agent Reasoning",
            border_style="magenta"
        ))
        
        # Footer - System status
        stats_display = self._create_stats_display()
        layout["footer"].update(Panel(stats_display, border_style="blue"))
        
        return layout
    
    def _create_progress_display(self) -> Group:
        """Create progress display"""
        phase = self.scan_progress.get('phase', 'idle')
        urls_scanned = self.scan_progress.get('urls_scanned', 0)
        urls_total = self.scan_progress.get('urls_total', 1)
        current_action = self.scan_progress.get('current_action', 'Initializing...')
        
        # Progress bar
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        )
        
        task = progress.add_task(f"[cyan]{phase}", total=urls_total, completed=urls_scanned)
        
        # Current action
        action_text = Text()
        action_text.append("Current: ", style="dim")
        action_text.append(current_action, style="bold white")
        
        # Stats
        stats = Table.grid(padding=(0, 2))
        stats.add_column(style="cyan")
        stats.add_column(style="white")
        
        stats.add_row("URLs Scanned:", f"{urls_scanned}/{urls_total}")
        stats.add_row("Vulnerabilities:", str(len(self.vulnerabilities)))
        
        return Group(
            progress,
            Text(),
            action_text,
            Text(),
            stats
        )
    
    def _create_vulnerability_display(self) -> Group:
        """Create vulnerability summary display"""
        if not self.vulnerabilities:
            return Text("No vulnerabilities found yet...", style="dim")
        
        # Count by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Create severity display
        severity_table = Table.grid(padding=(0, 1))
        severity_table.add_column(style="bold")
        severity_table.add_column(justify="right")
        
        severity_styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim"
        }
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                style = severity_styles[sev]
                severity_table.add_row(
                    f"[{style}]● {sev.upper()}[/{style}]",
                    f"[{style}]{count}[/{style}]"
                )
        
        # Recent vulnerabilities
        recent = Text("\nRecent Findings:\n", style="bold")
        for vuln in self.vulnerabilities[-3:]:
            recent.append(f"\n• {vuln.title}", style="dim")
        
        return Group(severity_table, recent)
    
    def _create_log_display(self) -> Group:
        """Create activity log display"""
        if not self.messages:
            return Text("Waiting for activity...", style="dim")
        
        lines = []
        for msg in self.messages[-5:]:  # Show last 5 messages
            timestamp = msg.get('time', '')
            text = msg.get('text', '')
            level = msg.get('level', 'info')
            
            style_map = {
                'info': 'white',
                'success': 'green',
                'warning': 'yellow',
                'error': 'red'
            }
            
            style = style_map.get(level, 'white')
            line = Text()
            line.append(f"[{timestamp}] ", style="dim")
            line.append(text, style=style)
            lines.append(line)
        
        return Group(*lines)
    
    def _create_planner_display(self) -> Group:
        """Create display for planner agent messages"""
        if not self.plan_messages:
            return Text("🤔 Analyzing target...", style="dim cyan")
        
        lines = []
        for msg in self.plan_messages[-10:]:  # Show last 10 messages
            # Clean up the message
            clean_msg = msg.replace('[cyan]', '').replace('[/cyan]', '')
            lines.append(Text.from_markup(msg))
        
        # Add current phase indicator
        phase = self.scan_progress.get('phase', 'idle')
        if phase != 'idle':
            lines.insert(0, Text(f"Current Phase: {phase.upper()}", style="bold cyan"))
        
        return Group(*lines) if lines else Text("Initializing...", style="dim")
    
    def _create_executor_display(self) -> Group:
        """Create display for executor agent messages"""
        if not self.executor_messages:
            return Text("⏳ Ready to execute...", style="dim magenta")
        
        lines = []
        for msg in self.executor_messages[-15:]:  # Show last 15 messages
            lines.append(Text.from_markup(msg))
        
        # Add activity indicator
        if len(self.executor_messages) > 0:
            lines.insert(0, Text(f"Active | {len(self.executor_messages)} actions", style="dim magenta"))
        
        return Group(*lines) if lines else Text("Initializing...", style="dim")
    
    def _create_toolinfo_display(self) -> Group:
        """Create display for current tool and request info"""
        lines = []
        
        # Show current tool
        if self.current_tool:
            lines.append(Text(f"Tool: {self.current_tool}", style="bold green"))
            lines.append(Text(""))
        
        # Show current request
        if self.current_request:
            # Check if it's a raw command (starts with 💻 or has curl/nmap)
            if self.current_request.startswith("💻") or "curl" in self.current_request.lower() or "nmap" in self.current_request.lower():
                # It's a raw command - show it prominently
                lines.append(Text("🔥 Raw Command:", style="bold yellow"))
                
                # Split multiline commands
                cmd_lines = self.current_request.split('\n')
                for cmd_line in cmd_lines:
                    if cmd_line.strip():
                        lines.append(Text(cmd_line, style="bold cyan"))
            elif self.current_request.startswith("GET") or self.current_request.startswith("POST"):
                # HTTP request
                lines.append(Text("HTTP Request:", style="bold cyan"))
                lines.append(Text(self.current_request[:200], style="dim white"))
            else:
                lines.append(Text("Request:", style="bold cyan"))
                lines.append(Text(self.current_request[:200], style="dim white"))
            
            lines.append(Text(""))
        
        # Show recent responses
        if self.recent_responses:
            lines.append(Text("Recent Responses:", style="bold yellow"))
            for resp in self.recent_responses[-3:]:
                lines.append(Text(f"→ {resp}", style="dim white"))
        
        if not lines:
            return Text("⏳ Waiting for tool execution...", style="dim green")
        
        return Group(*lines)
    
    def _create_api_monitor_display(self) -> Group:
        """Create display for API monitoring and health"""
        lines = []
        
        # Show API health summary
        if self.api_calls:
            total_calls = len(self.api_calls)
            successful = sum(1 for c in self.api_calls if c.get('status') == 'success')
            failed = sum(1 for c in self.api_calls if c.get('status') == 'error')
            rate_limited = sum(1 for c in self.api_calls if c.get('status_code') == 429)
            
            # Summary line
            summary = Text()
            summary.append("API Health: ", style="bold white")
            summary.append(f"{successful} OK", style="green")
            summary.append(" | ", style="dim")
            summary.append(f"{failed} Failed", style="red" if failed > 0 else "dim")
            summary.append(" | ", style="dim")
            summary.append(f"{rate_limited} Rate Limited", style="yellow" if rate_limited > 0 else "dim")
            lines.append(summary)
            lines.append(Text(""))
            
            # Show recent API calls (last 3)
            recent_calls = self.api_calls[-3:]
            for call in recent_calls:
                time_str = call.get('time', '')
                agent = call.get('agent', 'Unknown')
                status = call.get('status', 'unknown')
                status_code = call.get('status_code', 0)
                latency = call.get('latency', 0)
                error = call.get('error', '')
                
                # Format status with color
                if status == 'success':
                    status_icon = "✓"
                    status_color = "green"
                elif status == 'rate_limited':
                    status_icon = "⏸"
                    status_color = "yellow"
                else:
                    status_icon = "✗"
                    status_color = "red"
                
                # Build line
                line = Text()
                line.append(f"[{time_str}] ", style="dim")
                line.append(f"{status_icon} ", style=status_color)
                line.append(f"{agent} ", style="bold white")
                
                if status == 'success':
                    line.append(f"→ HTTP {status_code} ", style="green")
                    line.append(f"({latency:.2f}s)", style="dim")
                elif status == 'rate_limited':
                    line.append(f"→ HTTP 429 Rate Limited ", style="yellow")
                    line.append("(waiting...)", style="dim yellow")
                else:
                    line.append(f"→ ERROR: {error[:50]}", style="red")
                
                lines.append(line)
        else:
            lines.append(Text("⏳ Waiting for API calls...", style="dim blue"))
        
        return Group(*lines)
    
    def _create_verbose_display(self) -> Group:
        """Create verbose AI conversation display"""
        lines = []
        
        # Show AI requests and responses in detail
        if self.ai_requests or self.ai_responses:
            # Interleave requests and responses
            max_items = 4  # Show last 4 exchanges (2 req + 2 resp)
            
            # Get recent items
            recent_reqs = self.ai_requests[-2:] if self.ai_requests else []
            recent_resps = self.ai_responses[-2:] if self.ai_responses else []
            
            # Show in chronological order
            for i in range(max(len(recent_reqs), len(recent_resps))):
                if i > 0:
                    lines.append(Text(""))
                
                # Show request
                if i < len(recent_reqs):
                    req = recent_reqs[i]
                    time_str = req.get('time', '')
                    prompt = req.get('prompt', '')
                    
                    lines.append(Text(f"[{time_str}] → PROMPT:", style="bold cyan"))
                    
                    # Show full prompt (no truncation)
                    prompt_lines = prompt.split('\n')
                    for line in prompt_lines[:10]:  # Show first 10 lines
                        if line.strip():
                            lines.append(Text(f"  {line}", style="dim cyan"))
                    if len(prompt_lines) > 10:
                        lines.append(Text(f"  ... ({len(prompt_lines) - 10} more lines)", style="dim cyan"))
                
                # Show response
                if i < len(recent_resps):
                    resp = recent_resps[i]
                    time_str = resp.get('time', '')
                    response = resp.get('response', '')
                    
                    lines.append(Text(f"[{time_str}] ← RESPONSE:", style="bold green"))
                    
                    # Show full response (no truncation)
                    resp_lines = response.split('\n')
                    for line in resp_lines[:10]:  # Show first 10 lines
                        if line.strip():
                            lines.append(Text(f"  {line}", style="dim green"))
                    if len(resp_lines) > 10:
                        lines.append(Text(f"  ... ({len(resp_lines) - 10} more lines)", style="dim green"))
        else:
            lines.append(Text("⏳ Waiting for AI conversation...", style="dim magenta"))
        
        return Group(*lines)
    
    def _get_model_name(self) -> str:
        """Get the current AI model name"""
        from backend.config import settings
        return f"{settings.llm_provider}/{settings.llm_model}"
    
    def _create_stats_display(self) -> Text:
        """Create statistics display for footer"""
        # Count actual scanned URLs from agent
        if hasattr(self, 'agent') and hasattr(self.agent, 'graph'):
            urls_scanned = len(self.executor_messages) // 3  # Rough estimate from executor activity
        else:
            urls_scanned = self.scan_progress.get('urls_scanned', 0)
        
        vulns_found = len(self.vulnerabilities)
        phase = self.scan_progress.get('phase', 'idle')
        
        stats = Text()
        stats.append("Phase: ", style="dim")
        stats.append(phase.upper(), style="bold cyan")
        stats.append(" │ ", style="dim")
        stats.append("Activity: ", style="dim")
        stats.append(str(len(self.executor_messages)), style="bold white")
        stats.append(" actions", style="dim")
        stats.append(" │ ", style="dim")
        stats.append("Findings: ", style="dim")
        
        if vulns_found > 0:
            stats.append(str(vulns_found), style="bold red")
        else:
            stats.append("0", style="dim")
        
        return stats
    
    def _add_ai_request(self, prompt: str):
        """Track AI model request"""
        self.ai_requests.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'prompt': prompt
        })
        if len(self.ai_requests) > 10:
            self.ai_requests = self.ai_requests[-10:]
    
    def _add_ai_response(self, response: str):
        """Track AI model response"""
        self.ai_responses.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'response': response
        })
        if len(self.ai_responses) > 10:
            self.ai_responses = self.ai_responses[-10:]
    
    def _add_api_call(self, agent: str, status: str, status_code: int = 0, latency: float = 0, error: str = ""):
        """Track API call status"""
        self.api_calls.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'agent': agent,
            'status': status,
            'status_code': status_code,
            'latency': latency,
            'error': error
        })
        if len(self.api_calls) > 20:
            self.api_calls = self.api_calls[-20:]
    
    def _add_tool_execution(self, tool: str, url: str, req_type: str, data: str):
        """Track tool execution (requests/responses)"""
        self.tool_executions.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'tool': tool,
            'url': url,
            'type': req_type,  # 'request' or 'response'
            'data': data
        })
        if len(self.tool_executions) > 10:
            self.tool_executions = self.tool_executions[-10:]
    
    def _add_log_message(self, text: str, level: str = 'info'):
        """Add a message to the appropriate log based on level"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Capture verbose AI conversation
        if level == 'verbose_request':
            self._add_ai_request(text)
            if hasattr(self, 'live') and self.live:
                self.live.update(self._create_scan_layout())
            return
        elif level == 'verbose_response':
            self._add_ai_response(text)
            if hasattr(self, 'live') and self.live:
                self.live.update(self._create_scan_layout())
            return
        
        # Capture tool execution verbose logs
        if level == 'tool_request':
            # Format: "tool_name|url|method|headers|body"
            parts = text.split('|')
            if len(parts) >= 2:
                self._add_tool_execution(parts[0], parts[1], 'request', text)
            return
        elif level == 'tool_response':
            # Format: "tool_name|url|status|headers|body"
            parts = text.split('|')
            if len(parts) >= 3:
                self._add_tool_execution(parts[0], parts[1], 'response', text)
            return
        elif level == 'raw_command':
            # Raw CLI command being executed - show prominently
            self.executor_messages.append(f"[{timestamp}] {text}")
            if len(self.executor_messages) > 30:
                self.executor_messages = self.executor_messages[-30:]
            
            # ALSO show in the Tool Info box
            self.current_request = text
            
            # Update the live display
            if hasattr(self, 'live') and self.live:
                self.live.update(self._create_scan_layout())
            return
        
        # Capture API monitoring
        if level == 'api_success':
            # Parse: "agent|latency"
            parts = text.split('|')
            if len(parts) >= 2:
                self._add_api_call(parts[0], 'success', 200, float(parts[1]))
            return
        elif level == 'api_error':
            # Parse: "agent|error"
            parts = text.split('|', 1)
            if len(parts) >= 2:
                self._add_api_call(parts[0], 'error', 0, 0, parts[1])
            return
        elif level == 'api_rate_limited':
            # Parse: "agent"
            self._add_api_call(text, 'rate_limited', 429)
            return
        
        # Legacy AI conversation tracking
        if level == 'ai_request':
            self._add_ai_request(text)
            return
        elif level == 'ai_response':
            self._add_ai_response(text)
            return
        
        # Extract tool and request info from executor messages
        if level == 'executor':
            # Check if this is a tool execution message
            if '→' in text and '(' in text:
                # Extract tool name and URL
                parts = text.split('→')[1].strip() if '→' in text else text
                if '(' in parts:
                    tool_name = parts.split('(')[0].strip()
                    url = parts.split('(')[1].split(')')[0].strip()
                    self.current_tool = tool_name
                    self.current_request = f"GET {url}"
            
            # Check if this is a response message
            if '✓' in text or '✗' in text:
                self.recent_responses.append(text)
                if len(self.recent_responses) > 5:
                    self.recent_responses = self.recent_responses[-5:]
        
        # Skip duplicate consecutive messages
        if level == 'plan' and self.plan_messages:
            if text in self.plan_messages[-1]:
                return
        elif level == 'executor' and self.executor_messages:
            if text in self.executor_messages[-1]:
                return
        
        # Color based on level
        color_map = {
            'info': 'white',
            'success': 'green',
            'warning': 'yellow',
            'error': 'red',
            'plan': 'cyan',
            'executor': 'magenta'
        }
        
        color = color_map.get(level, 'white')
        formatted_msg = f"[{color}]{text}[/{color}]"
        
        # Route to appropriate log
        if level == 'plan':
            self.plan_messages.append(formatted_msg)
            if len(self.plan_messages) > 12:
                self.plan_messages = self.plan_messages[-12:]
        elif level == 'executor':
            self.executor_messages.append(formatted_msg)
            if len(self.executor_messages) > 20:
                self.executor_messages = self.executor_messages[-20:]
        else:
            # General messages
            self.messages.append({
                'time': timestamp,
                'text': text,
                'level': level
            })
            if len(self.messages) > 20:
                self.messages = self.messages[-20:]
        
        # Update scan progress stats
        if "scanned" in text.lower():
            self.scan_progress['urls_scanned'] = self.scan_progress.get('urls_scanned', 0) + 1
        
        # Update live display if active (less frequently to reduce flicker)
        if hasattr(self, 'live') and self.live:
            self.live.update(self._create_scan_layout())
    
    async def _approval_callback(self, approval_request: Dict[str, Any]) -> bool:
        """Handle approval requests from agent"""
        self.console.print("\n")
        
        action = approval_request.get('action', {})
        rationale = approval_request.get('rationale', '')
        
        # Show approval request panel
        details = f"""
[yellow]Action Type:[/yellow] {action.get('action_type', 'Unknown')}
[yellow]Risk Level:[/yellow] {action.get('risk_level', 'Unknown')}
[yellow]Target:[/yellow] {action.get('target_url', 'Unknown')}

[yellow]Description:[/yellow]
{action.get('description', 'No description')}

[yellow]Rationale:[/yellow]
{rationale}
        """
        
        panel = Panel(
            details,
            title="[bold red]⚠️  Approval Required[/bold red]",
            border_style="red"
        )
        
        self.console.print(panel)
        
        approved = Confirm.ask("[cyan]Proceed with this action?[/cyan]", default=False)
        
        if approved:
            self._add_log_message(f"✓ Approved: {action.get('action_type')}", 'success')
        else:
            self._add_log_message(f"✗ Denied: {action.get('action_type')}", 'warning')
        
        return approved
    
    async def _show_scan_results(self):
        """Show detailed scan results"""
        self.console.print("\n")
        self.console.print(Panel("[bold green]Scan Complete![/bold green]", border_style="green"))
        
        if not self.vulnerabilities:
            self.console.print("\n[green]✓ No vulnerabilities found![/green]")
            return
        
        # Summary table
        summary = Table(title="Vulnerability Summary", show_header=True, header_style="bold cyan")
        summary.add_column("Severity", style="bold")
        summary.add_column("Type", style="cyan")
        summary.add_column("Title")
        summary.add_column("URL", style="dim")
        
        for vuln in self.vulnerabilities:
            severity_style = {
                SeverityLevel.CRITICAL: "bold red",
                SeverityLevel.HIGH: "red",
                SeverityLevel.MEDIUM: "yellow",
                SeverityLevel.LOW: "blue",
                SeverityLevel.INFO: "dim"
            }.get(vuln.severity, "white")
            
            summary.add_row(
                f"[{severity_style}]{vuln.severity.value.upper()}[/{severity_style}]",
                vuln.vuln_type.value,
                vuln.title,  # Full title, no truncation
                vuln.affected_url  # Full URL, no truncation
            )
        
        self.console.print(summary)
        
        # Detailed view option
        if Confirm.ask("\n[cyan]View detailed vulnerability information?[/cyan]"):
            for i, vuln in enumerate(self.vulnerabilities, 1):
                self._show_vulnerability_details(vuln, i)
    
    def _show_vulnerability_details(self, vuln: Vulnerability, index: int):
        """Show detailed vulnerability information"""
        severity_colors = {
            SeverityLevel.CRITICAL: "red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "cyan"
        }
        
        color = severity_colors.get(vuln.severity, "white")
        
        details = f"""
[bold]Type:[/bold] {vuln.vuln_type.value}
[bold]Severity:[/bold] [{color}]{vuln.severity.value.upper()}[/{color}]
[bold]URL:[/bold] {vuln.affected_url}
[bold]CWE:[/bold] {vuln.cwe_id or 'N/A'}
[bold]CVSS:[/bold] {vuln.cvss_score or 'N/A'}

[bold yellow]Description:[/bold yellow]
{vuln.description}

[bold yellow]Evidence:[/bold yellow]
{vuln.evidence}

[bold yellow]Remediation:[/bold yellow]
{vuln.remediation}
        """
        
        panel = Panel(
            details,
            title=f"[bold]{index}. {vuln.title}[/bold]",
            border_style=color
        )
        
        self.console.print("\n")
        self.console.print(panel)
        
        if len(vuln.reproduction_steps) > 0:
            steps = "\n".join(f"{i}. {step}" for i, step in enumerate(vuln.reproduction_steps, 1))
            self.console.print(f"\n[bold]Reproduction Steps:[/bold]\n{steps}")
        
        self.console.print("\n" + "─" * 80)
    
    async def _view_history(self):
        """View scan history"""
        self.console.clear()
        self.console.print(Panel("[bold cyan]Scan History[/bold cyan]", border_style="cyan"))
        
        from backend.rag import ScanHistory
        history = ScanHistory()
        
        scans = await history.get_recent_scans(limit=10)
        
        if not scans:
            self.console.print("\n[yellow]No scan history found[/yellow]")
            return
        
        # Display scans
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Date", style="dim")
        table.add_column("Target")
        table.add_column("Mode")
        table.add_column("Status")
        table.add_column("Vulns", justify="right")
        
        for scan in scans:
            table.add_row(
                scan['start_time'][:19],
                scan['target_url'][:40],
                scan['mode'],
                scan['status'],
                str(len(scan['vulnerabilities']))
            )
        
        self.console.print(table)
        
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
    
    async def _manage_targets(self):
        """Manage authorized targets"""
        self.console.clear()
        self.console.print(Panel("[bold cyan]Authorized Targets[/bold cyan]", border_style="cyan"))
        
        targets = self.auth_manager.get_authorized_targets()
        
        if targets:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Domain")
            table.add_column("Scope Patterns")
            table.add_column("Notes")
            
            for target in targets:
                table.add_row(
                    target['domain'],
                    ", ".join(target.get('scope_patterns', [])[:2]),
                    target.get('notes', '')[:30]
                )
            
            self.console.print(table)
        else:
            self.console.print("\n[yellow]No authorized targets[/yellow]")
        
        # Options
        choice = Prompt.ask(
            "\n[cyan]Options[/cyan]: (a)dd, (r)emove, (b)ack",
            choices=["a", "r", "b"],
            default="b"
        )
        
        if choice == "a":
            domain = Prompt.ask("[cyan]Enter domain to authorize[/cyan]")
            notes = Prompt.ask("[cyan]Notes (optional)[/cyan]", default="")
            self.auth_manager.add_authorized_target(domain, notes=notes)
            self.console.print(f"[green]✓ Added {domain}[/green]")
        elif choice == "r":
            domain = Prompt.ask("[cyan]Enter domain to remove[/cyan]")
            if self.auth_manager.remove_authorized_target(domain):
                self.console.print(f"[green]✓ Removed {domain}[/green]")
            else:
                self.console.print(f"[red]Domain not found[/red]")
    
    async def _knowledge_base(self):
        """Knowledge base operations"""
        self.console.clear()
        self.console.print(Panel("[bold cyan]Knowledge Base[/bold cyan]", border_style="cyan"))
        
        query = Prompt.ask("\n[cyan]Search knowledge base[/cyan]")
        
        from backend.rag import KnowledgeBase
        kb = KnowledgeBase()
        
        results = await kb.search(query, limit=5)
        
        if not results:
            self.console.print("\n[yellow]No results found[/yellow]")
            return
        
        for i, result in enumerate(results, 1):
            self.console.print(f"\n[bold cyan]{i}. {result.get('title', 'Untitled')}[/bold cyan]")
            self.console.print(f"[dim]Category: {result.get('category', 'N/A')}[/dim]")
            self.console.print(f"\n{result.get('content', '')[:200]}...")
        
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
    
    async def _settings(self):
        """Settings management"""
        while True:
            self.console.clear()
            self.console.print(Panel("[bold cyan]Settings[/bold cyan]", border_style="cyan"))
            
            from backend.config import settings
            
            # Current configuration
            self.console.print("\n[bold]Current Configuration:[/bold]\n")
            settings_table = Table.grid(padding=(0, 2))
            settings_table.add_column(style="cyan")
            settings_table.add_column(style="white")
            
            settings_table.add_row("LLM Provider:", f"[green]{settings.llm_provider}[/green]")
            settings_table.add_row("LLM Model:", f"[green]{settings.llm_model}[/green]")
            
            # Show which API keys are configured
            has_openai = bool(settings.openai_api_key and len(settings.openai_api_key) > 10)
            has_openrouter = bool(settings.openrouter_api_key and len(settings.openrouter_api_key) > 10)
            has_gemini = bool(settings.gemini_api_key and len(settings.gemini_api_key) > 10)
            
            openai_status = "[green]✓ Configured[/green]" if has_openai else "[dim]Not configured[/dim]"
            openrouter_status = "[green]✓ Configured[/green]" if has_openrouter else "[dim]Not configured[/dim]"
            gemini_status = "[green]✓ Configured[/green]" if has_gemini else "[dim]Not configured[/dim]"
            
            settings_table.add_row("OpenAI API Key:", openai_status)
            settings_table.add_row("OpenRouter API Key:", openrouter_status)
            settings_table.add_row("Gemini API Key:", gemini_status)
            settings_table.add_row("", "")
            settings_table.add_row("Max Concurrent Scans:", str(settings.max_concurrent_scans))
            settings_table.add_row("Request Timeout:", f"{settings.request_timeout}s")
            settings_table.add_row("Rate Limit:", f"{settings.rate_limit_per_second}/s")
            
            self.console.print(settings_table)
            
            # Settings menu
            self.console.print("\n[bold]Options:[/bold]\n")
            menu = Table.grid(padding=1)
            menu.add_column(style="cyan", justify="right")
            menu.add_column(style="white")
            
            menu.add_row("1.", "🔑 Reconfigure API Keys")
            menu.add_row("2.", "🔄 Change LLM Provider/Model")
            menu.add_row("3.", "📁 Show Config File Location")
            menu.add_row("4.", "🔙 Back to Main Menu")
            
            self.console.print(menu)
            
            choice = Prompt.ask("\n[cyan]Choose an option[/cyan]", choices=["1", "2", "3", "4"])
            
            if choice == "1":
                await self._reconfigure_api_keys()
            elif choice == "2":
                await self._change_provider_model()
            elif choice == "3":
                self._show_config_location()
            elif choice == "4":
                break
    
    async def _reconfigure_api_keys(self):
        """Reconfigure API keys"""
        self.console.clear()
        self.console.print(Panel("[bold cyan]Reconfigure API Keys[/bold cyan]", border_style="cyan"))
        
        self.console.print("\n[yellow]⚠️  This will update your API keys in the configuration file.[/yellow]\n")
        
        from pathlib import Path
        
        # Use Rich Prompt instead of questionary to avoid event loop conflicts
        self.console.print("[bold]Which API key do you want to configure?[/bold]\n")
        self.console.print("1. OpenAI")
        self.console.print("2. OpenRouter")
        self.console.print("3. Google Gemini")
        self.console.print("4. Cancel\n")
        
        choice = Prompt.ask("[cyan]Choose option[/cyan]", choices=["1", "2", "3", "4"])
        
        if choice == "4":
            return
        
        # Map choice to provider
        provider_map = {"1": "openai", "2": "openrouter", "3": "gemini"}
        provider_choice = provider_map[choice]
        
        # Get new API key
        if provider_choice == "openai":
            self.console.print("\n[dim]Get your key from: https://platform.openai.com/api-keys[/dim]")
            new_key = Prompt.ask("Enter new OpenAI API key", password=True)
            key_name = "OPENAI_API_KEY"
        elif provider_choice == "openrouter":
            self.console.print("\n[dim]Get your key from: https://openrouter.ai/keys[/dim]")
            new_key = Prompt.ask("Enter new OpenRouter API key", password=True)
            key_name = "OPENROUTER_API_KEY"
        else:  # gemini
            self.console.print("\n[dim]Get your key from: https://makersuite.google.com/app/apikey[/dim]")
            new_key = Prompt.ask("Enter new Gemini API key", password=True)
            key_name = "GEMINI_API_KEY"
        
        if not new_key or len(new_key) < 10:
            self.console.print("\n[red]Invalid API key. Configuration not updated.[/red]")
            Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
            return
        
        # Update .env file
        user_env = Path.home() / ".jimcrow" / ".env"
        project_env = Path(".env")
        
        # Try to update both locations
        updated = False
        for env_file in [user_env, project_env]:
            if env_file.exists():
                try:
                    content = env_file.read_text()
                    lines = content.split('\n')
                    
                    # Find and update the key
                    key_found = False
                    for i, line in enumerate(lines):
                        if line.startswith(f"{key_name}="):
                            lines[i] = f"{key_name}={new_key}"
                            key_found = True
                            break
                    
                    # If key not found, add it
                    if not key_found:
                        lines.append(f"{key_name}={new_key}")
                    
                    env_file.write_text('\n'.join(lines))
                    self.console.print(f"\n[green]✓ Updated {env_file}[/green]")
                    updated = True
                except Exception as e:
                    self.console.print(f"\n[red]Error updating {env_file}: {e}[/red]")
        
        if updated:
            self.console.print("\n[green]✓ API key updated successfully![/green]")
            self.console.print("[yellow]Note: Restart jim for changes to take effect.[/yellow]")
        else:
            self.console.print("\n[red]Could not update configuration files.[/red]")
        
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
    
    async def _change_provider_model(self):
        """Change LLM provider and model"""
        self.console.clear()
        self.console.print(Panel("[bold cyan]Change Provider/Model[/bold cyan]", border_style="cyan"))
        
        from pathlib import Path
        
        # Choose provider
        self.console.print("\n[bold]Select LLM provider:[/bold]\n")
        self.console.print("1. OpenAI")
        self.console.print("2. OpenRouter")
        self.console.print("3. Google Gemini")
        self.console.print("4. Cancel\n")
        
        provider_choice = Prompt.ask("[cyan]Choose option[/cyan]", choices=["1", "2", "3", "4"])
        
        if provider_choice == "4":
            return
        
        provider_map = {"1": "openai", "2": "openrouter", "3": "gemini"}
        provider = provider_map[provider_choice]
        
        # Choose model based on provider
        if provider == "openai":
            self.console.print("\n[bold]Select OpenAI model:[/bold]\n")
            self.console.print("1. gpt-4o")
            self.console.print("2. gpt-4o-mini")
            self.console.print("3. o1-preview")
            self.console.print("4. o1-mini")
            self.console.print("5. gpt-4-turbo\n")
            
            model_choice = Prompt.ask("[cyan]Choose option[/cyan]", choices=["1", "2", "3", "4", "5"])
            model_map = {"1": "gpt-4o", "2": "gpt-4o-mini", "3": "o1-preview", "4": "o1-mini", "5": "gpt-4-turbo"}
            model = model_map[model_choice]
            
        elif provider == "openrouter":
            model = Prompt.ask(
                "\n[cyan]Enter model name[/cyan]",
                default="anthropic/claude-3.5-sonnet"
            )
        else:  # gemini
            self.console.print("\n[bold]Select Gemini model:[/bold]\n")
            self.console.print("1. gemini-2.5-flash (Recommended)")
            self.console.print("2. gemini-2.5-pro")
            self.console.print("3. gemini-2.0-flash")
            self.console.print("4. gemini-2.0-flash-lite\n")
            
            model_choice = Prompt.ask("[cyan]Choose option[/cyan]", choices=["1", "2", "3", "4"])
            model_map = {"1": "gemini-2.5-flash", "2": "gemini-2.5-pro", "3": "gemini-2.0-flash", "4": "gemini-2.0-flash-lite"}
            model = model_map[model_choice]
        
        # Update configuration
        user_env = Path.home() / ".jimcrow" / ".env"
        project_env = Path(".env")
        
        updated = False
        for env_file in [user_env, project_env]:
            if env_file.exists():
                try:
                    content = env_file.read_text()
                    lines = content.split('\n')
                    
                    # Update provider and model
                    provider_found = False
                    model_found = False
                    
                    for i, line in enumerate(lines):
                        if line.startswith("LLM_PROVIDER="):
                            lines[i] = f"LLM_PROVIDER={provider}"
                            provider_found = True
                        elif line.startswith("LLM_MODEL="):
                            lines[i] = f"LLM_MODEL={model}"
                            model_found = True
                    
                    if not provider_found:
                        lines.append(f"LLM_PROVIDER={provider}")
                    if not model_found:
                        lines.append(f"LLM_MODEL={model}")
                    
                    env_file.write_text('\n'.join(lines))
                    self.console.print(f"\n[green]✓ Updated {env_file}[/green]")
                    updated = True
                except Exception as e:
                    self.console.print(f"\n[red]Error: {e}[/red]")
        
        if updated:
            self.console.print(f"\n[green]✓ Provider changed to: {provider}[/green]")
            self.console.print(f"[green]✓ Model changed to: {model}[/green]")
            self.console.print("\n[yellow]Note: Restart jim for changes to take effect.[/yellow]")
        
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
    
    def _show_config_location(self):
        """Show where config files are located"""
        from pathlib import Path
        
        self.console.clear()
        self.console.print(Panel("[bold cyan]Configuration File Locations[/bold cyan]", border_style="cyan"))
        
        user_env = Path.home() / ".jimcrow" / ".env"
        project_env = Path(".env")
        
        self.console.print("\n[bold]Config file locations:[/bold]\n")
        
        locations = Table.grid(padding=(0, 2))
        locations.add_column(style="cyan")
        locations.add_column(style="white")
        
        if user_env.exists():
            locations.add_row("User config:", f"[green]✓[/green] {user_env}")
        else:
            locations.add_row("User config:", f"[dim]✗ {user_env}[/dim]")
        
        if project_env.exists():
            locations.add_row("Project config:", f"[green]✓[/green] {project_env}")
        else:
            locations.add_row("Project config:", f"[dim]✗ {project_env}[/dim]")
        
        self.console.print(locations)
        
        self.console.print("\n[dim]You can manually edit these files to change configuration.[/dim]")
        self.console.print("[dim]Or use the reconfigure option in the Settings menu.[/dim]")
        
        Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

