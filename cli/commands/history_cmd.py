"""History and reporting commands"""

import asyncio
from rich.console import Console
from rich.table import Table
from backend.rag import ScanHistory

console = Console()


async def show_history(limit: int = 10, scan_id: str = None):
    """Show scan history"""
    history = ScanHistory()
    
    if scan_id:
        scan = await history.get_scan(scan_id)
        if scan:
            console.print(f"\n[bold]Scan ID:[/bold] {scan['id']}")
            console.print(f"[bold]Target:[/bold] {scan['target_url']}")
            console.print(f"[bold]Status:[/bold] {scan['status']}")
            console.print(f"[bold]Vulnerabilities:[/bold] {len(scan['vulnerabilities'])}")
        else:
            console.print(f"[red]Scan {scan_id} not found[/red]")
        return
    
    scans = await history.get_recent_scans(limit=limit)
    
    if not scans:
        console.print("[yellow]No scan history[/yellow]")
        return
    
    table = Table(title=f"Recent Scans (Last {limit})", show_header=True, header_style="bold cyan")
    table.add_column("Date", style="dim")
    table.add_column("Target")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Vulns", justify="right")
    
    for scan in scans:
        table.add_row(
            scan['start_time'][:19],
            scan['target_url'][:50],
            scan['mode'],
            scan['status'],
            str(len(scan['vulnerabilities']))
        )
    
    console.print(table)


async def generate_report(scan_id: str, format: str, output: str = None):
    """Generate a report"""
    history = ScanHistory()
    scan = await history.get_scan(scan_id)
    
    if not scan:
        console.print(f"[red]Scan {scan_id} not found[/red]")
        return
    
    # Generate report based on format
    if format == "json":
        import json
        report_data = json.dumps(scan, indent=2, default=str)
        
        if output:
            with open(output, 'w') as f:
                f.write(report_data)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(report_data)
    
    elif format == "html":
        html_report = _generate_html_report(scan)
        output_file = output or f"report_{scan_id}.html"
        
        with open(output_file, 'w') as f:
            f.write(html_report)
        
        console.print(f"[green]HTML report saved to {output_file}[/green]")
    
    else:
        console.print(f"[yellow]Format {format} not yet implemented[/yellow]")


def _generate_html_report(scan: dict) -> str:
    """Generate HTML report"""
    vulnerabilities = scan.get('vulnerabilities', [])
    
    vuln_rows = ""
    for vuln in vulnerabilities:
        severity = vuln['severity']
        color = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#f59e0b',
            'low': '#3b82f6',
            'info': '#6b7280'
        }.get(severity, '#6b7280')
        
        vuln_rows += f"""
        <tr>
            <td><span style="color: {color}; font-weight: bold;">{severity.upper()}</span></td>
            <td>{vuln['vuln_type']}</td>
            <td>{vuln['title']}</td>
            <td style="font-size: 0.875rem; color: #6b7280;">{vuln['affected_url'][:50]}...</td>
        </tr>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>JimCrow Scan Report - {scan['id']}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                   margin: 2rem; background: #f9fafb; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; 
                         padding: 2rem; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            h1 {{ color: #1f2937; }}
            .meta {{ color: #6b7280; margin-bottom: 2rem; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
            th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
            th {{ background: #f3f4f6; font-weight: 600; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 JimCrow Penetration Test Report</h1>
            <div class="meta">
                <p><strong>Scan ID:</strong> {scan['id']}</p>
                <p><strong>Target:</strong> {scan['target_url']}</p>
                <p><strong>Mode:</strong> {scan['mode']}</p>
                <p><strong>Status:</strong> {scan['status']}</p>
                <p><strong>Date:</strong> {scan['start_time']}</p>
            </div>
            
            <h2>Vulnerabilities Found: {len(vulnerabilities)}</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Title</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    return html

