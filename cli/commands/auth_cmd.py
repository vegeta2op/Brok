"""Authorization management commands"""

import typer
from rich.console import Console
from rich.table import Table
from backend.auth import AuthorizationManager

app = typer.Typer()
console = Console()


@app.command("add")
def add_target(
    domain: str = typer.Argument(..., help="Domain to authorize"),
    notes: str = typer.Option("", help="Optional notes")
):
    """Add an authorized target"""
    auth_manager = AuthorizationManager()
    
    if auth_manager.add_authorized_target(domain, notes=notes):
        console.print(f"[green]✓ Added {domain} to authorized targets[/green]")
    else:
        console.print(f"[yellow]Domain {domain} already authorized[/yellow]")


@app.command("remove")
def remove_target(domain: str = typer.Argument(..., help="Domain to remove")):
    """Remove an authorized target"""
    auth_manager = AuthorizationManager()
    
    if auth_manager.remove_authorized_target(domain):
        console.print(f"[green]✓ Removed {domain} from authorized targets[/green]")
    else:
        console.print(f"[red]Domain {domain} not found[/red]")


@app.command("list")
def list_targets():
    """List all authorized targets"""
    auth_manager = AuthorizationManager()
    targets = auth_manager.get_authorized_targets()
    
    if not targets:
        console.print("[yellow]No authorized targets[/yellow]")
        return
    
    table = Table(title="Authorized Targets", show_header=True, header_style="bold cyan")
    table.add_column("Domain", style="cyan")
    table.add_column("Scope Patterns")
    table.add_column("Notes")
    
    for target in targets:
        table.add_row(
            target['domain'],
            ", ".join(target.get('scope_patterns', [])[:2]),
            target.get('notes', '')
        )
    
    console.print(table)

