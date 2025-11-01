"""Scan command implementation"""

import asyncio
from rich.console import Console
from backend.agent import PentestAgent
from backend.models import ScanRequest, ScanMode


console = Console()


async def run_scan_headless(target: str, mode: str = "autonomous"):
    """Run scan without interactive TUI"""
    console.print(f"[cyan]🤖 Starting autonomous AI scan of {target}...[/cyan]")
    
    agent = PentestAgent()
    
    scan_request = ScanRequest(
        target_url=target,
        mode=ScanMode.AUTONOMOUS
    )
    
    try:
        result = await agent.scan(scan_request)
        
        console.print(f"\n[green]Scan completed![/green]")
        console.print(f"Scan ID: {result.scan_id}")
        console.print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
        
        for vuln in result.vulnerabilities:
            console.print(f"\n[yellow]{vuln.severity.value.upper()}[/yellow]: {vuln.title}")
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

