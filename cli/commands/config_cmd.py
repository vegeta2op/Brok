"""Configuration commands"""

import typer
from rich.console import Console
from rich.table import Table
from backend.config import settings

app = typer.Typer()
console = Console()


@app.command("show")
def show_config():
    """Show current configuration"""
    table = Table(title="Current Configuration", show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    
    table.add_row("LLM Provider", settings.llm_provider)
    table.add_row("LLM Model", settings.llm_model)
    table.add_row("Max Concurrent Scans", str(settings.max_concurrent_scans))
    table.add_row("Request Timeout", f"{settings.request_timeout}s")
    table.add_row("Rate Limit", f"{settings.rate_limit_per_second}/s")
    table.add_row("Log Level", settings.log_level)
    
    console.print(table)


@app.command("set")
def set_config(
    key: str = typer.Argument(..., help="Configuration key"),
    value: str = typer.Argument(..., help="Configuration value")
):
    """Set a configuration value"""
    console.print(f"[yellow]Note: Configuration changes require editing .env file[/yellow]")
    console.print(f"Set {key}={value} in your .env file")

