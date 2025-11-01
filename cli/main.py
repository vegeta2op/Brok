"""Main CLI entry point - Claude-style interactive by default"""

import typer
import asyncio
from pathlib import Path
from typing import Optional
import sys
from rich.console import Console
from rich.panel import Panel

from .tui import InteractiveTUI
from .commands import scan_cmd, auth_cmd, history_cmd, config_cmd, kb_cmd, session_cmd

console = Console()

app = typer.Typer(
    name="brok",
    help="Brok - AI-Powered Autonomous Pentesting Agent",
    add_completion=False,
    no_args_is_help=False,  # Allow running without args
    invoke_without_command=True
)

# Add command groups
app.add_typer(auth_cmd.app, name="auth", help="Manage authorized targets")
app.add_typer(config_cmd.app, name="config", help="Manage configuration")
app.add_typer(kb_cmd.app, name="kb", help="Knowledge base operations")
app.add_typer(session_cmd.app, name="session", help="Authentication session management")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    JimCrow - AI-Powered Autonomous Pentesting Agent
    
    Just type 'jim' to launch the interactive interface!
    
    Use subcommands for specific actions (jim --help to see all commands)
    """
    # If a subcommand was invoked, don't launch interactive mode
    if ctx.invoked_subcommand is not None:
        return
    
    # Clear the terminal like Claude Code does
    console.clear()
    
    # Welcome message
    console.print("""
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ____  ____  ____  _  __                                      ║
║ /  __\/  __\/  _ \/ |/ /                                      ║
║ | | //|  \/|| / \||   /                                       ║
║ | |_\\|    /| \_/||   \                                       ║
║ \____/\_/\_\\____/\_|\_\                                      ║
║                                                              ║
║            AI-Powered Autonomous Pentesting Agent             ║
║                        v0.1.0                                ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]
""")
    
    # Show capability warning
    show_capability_warning()
    
    # Check if setup is needed
    if needs_setup():
        console.print("\n[yellow]⚡ First-time setup required![/yellow]\n")
        run_interactive_setup()
    else:
        # Show current configuration
        try:
            from backend.config import settings
            console.print("\n[dim]Configuration loaded:[/dim]")
            console.print(f"[dim]  Provider: {settings.llm_provider} | Model: {settings.llm_model}[/dim]")
        except:
            pass
    
    # Launch interactive TUI
    import time
    console.print("\n[cyan]🚀 Launching...[/cyan]")
    time.sleep(0.3)  # Brief pause
    console.clear()  # Clear before TUI takes over
    tui = InteractiveTUI()
    asyncio.run(tui.run())


def show_capability_warning():
    """Show warning about tool capabilities"""
    import questionary
    
    warning = """[bold yellow]⚠️  IMPORTANT - PLEASE READ CAREFULLY[/bold yellow]

[bold]JimCrow is an AI pentesting agent with powerful capabilities:[/bold]

[yellow]• Read & Write Files[/yellow] - Can read/write files on your system
[yellow]• Network Access[/yellow] - Makes HTTP requests to targets
[yellow]• Execute Security Tests[/yellow] - Tests for SQL injection, XSS, etc.
[yellow]• AI Decision Making[/yellow] - Uses AI to plan and execute tests

[bold red]⚖️  LEGAL WARNING:[/bold red]
[red]Unauthorized pentesting is ILLEGAL and may result in:[/red]
• Criminal charges and prosecution
• Civil lawsuits and financial penalties
• Loss of employment
• Permanent criminal record

[bold green]✅ ONLY test systems where you have:[/bold green]
• Explicit written permission from the owner
• Clear scope and authorization
• Legal right to perform security testing

[bold cyan]🛡️  Built-in Safety Features:[/bold cyan]
✓ Requires explicit target authorization
✓ Prompts before risky actions
✓ Complete audit logging
✓ Scope enforcement

[dim]By continuing, you accept full legal responsibility for your use of JimCrow.[/dim]
"""
    
    console.print(Panel(warning, border_style="red", expand=False))
    
    confirmed = questionary.confirm(
        "\nDo you understand and agree to use JimCrow legally and ethically?",
        default=False
    ).ask()
    
    if not confirmed:
        console.print("\n[red]❌ You must agree to responsible use to continue.[/red]")
        console.print("[dim]JimCrow has been terminated.[/dim]\n")
        sys.exit(0)
    
    console.print("\n[green]✓ Acknowledged. Proceeding...[/green]")


def needs_setup() -> bool:
    """Check if initial setup is needed"""
    # Check both project .env and user .env
    project_env = Path(".env")
    user_env = Path.home() / ".jimcrow" / ".env"
    
    # If neither exists, definitely need setup
    if not project_env.exists() and not user_env.exists():
        return True
    
    # If either exists, validate the configuration
    try:
        from backend.config import settings
        
        # Check if any API key is configured
        has_openai = bool(settings.openai_api_key and len(settings.openai_api_key) > 10)
        has_openrouter = bool(settings.openrouter_api_key and len(settings.openrouter_api_key) > 10)
        has_gemini = bool(settings.gemini_api_key and len(settings.gemini_api_key) > 10)
        
        has_any_key = has_openai or has_openrouter or has_gemini
        
        if not has_any_key:
            return True
        
        # Check if provider is set correctly
        provider = settings.llm_provider
        if provider not in ["openai", "openrouter", "gemini"]:
            return True
        
        # Check if the selected provider has a key
        if provider == "openai" and not has_openai:
            return True
        if provider == "openrouter" and not has_openrouter:
            return True
        if provider == "gemini" and not has_gemini:
            return True
        
        # Check if model is set
        if not settings.llm_model or len(settings.llm_model) < 3:
            return True
        
        # All checks passed
        return False
        
    except Exception as e:
        # If there's any error loading config, need setup
        console.print(f"[yellow]Configuration error: {e}[/yellow]")
        return True


def run_interactive_setup():
    """Interactive setup wizard - Claude style"""
    import questionary
    
    console.print("[bold cyan]🔧 Setup Wizard[/bold cyan]")
    console.print("[dim]Let's get you configured in 3 simple steps...[/dim]\n")
    
    # Step 1: Choose LLM provider
    console.print("[bold]Step 1/3: Choose your AI provider[/bold]")
    provider_choice = questionary.select(
        "Which LLM provider do you want to use?",
        choices=[
            questionary.Choice("OpenAI (GPT-4, GPT-3.5, GPT-4o)", value="openai"),
            questionary.Choice("OpenRouter (Access multiple models)", value="openrouter"),
            questionary.Choice("Google Gemini", value="gemini"),
        ]
    ).ask()
    
    # Step 2: Get API key
    console.print(f"\n[bold]Step 2/3: Enter your API key[/bold]")
    
    if provider_choice == "openai":
        console.print("[dim]Get your key from: https://platform.openai.com/api-keys[/dim]")
    elif provider_choice == "openrouter":
        console.print("[dim]Get your key from: https://openrouter.ai/keys[/dim]")
    else:
        console.print("[dim]Get your key from: https://makersuite.google.com/app/apikey[/dim]")
    
    api_key = questionary.password(
        f"Enter your API key:",
        validate=lambda x: len(x) > 10 or "API key seems too short"
    ).ask()
    
    # Step 3: Choose model
    console.print(f"\n[bold]Step 3/3: Select model[/bold]")
    
    if provider_choice == "openai":
        model = questionary.select(
            "Which OpenAI model?",
            choices=[
                "gpt-4o",
                "gpt-4o-mini", 
                "o1-preview",
                "o1-mini",
                "gpt-4-turbo",
                "gpt-3.5-turbo"
            ],
            default="gpt-4o-mini"
        ).ask()
    elif provider_choice == "openrouter":
        model = questionary.text(
            "Enter model name:",
            default="anthropic/claude-3.5-sonnet",
            instruction="Examples: anthropic/claude-3.5-sonnet, openai/gpt-4, google/gemini-pro"
        ).ask()
    else:
        model = questionary.select(
            "Which Gemini model?",
            choices=[
                "gemini-2.5-flash",           # Latest: Fast & intelligent (recommended)
                "gemini-2.5-pro",             # Most advanced: complex reasoning
                "gemini-2.0-flash",           # Previous gen: stable & reliable
                "gemini-2.0-flash-lite",      # Cost-efficient & low latency
                "gemini-1.5-pro",             # Legacy: stable
                "gemini-1.5-flash",           # Legacy: fast
            ],
            default="gemini-2.5-flash",
            instruction="Latest: Gemini 2.5 models (June 2025) | Legacy: 1.5 models"
        ).ask()
    
    # Optional: Supabase
    console.print(f"\n[bold]Optional: Supabase for RAG[/bold]")
    console.print("[dim]RAG enables the AI to learn from past scans and use a knowledge base.[/dim]")
    
    add_supabase = questionary.confirm(
        "Configure Supabase now?",
        default=False
    ).ask()
    
    supabase_url = ""
    supabase_key = ""
    
    if add_supabase:
        console.print("[dim]Get your credentials from: https://app.supabase.com[/dim]")
        supabase_url = questionary.text("Supabase Project URL:").ask()
        supabase_key = questionary.password("Supabase API Key:").ask()
    
    # Save configuration
    console.print("\n[cyan]💾 Saving configuration...[/cyan]")
    
    env_content = f"""# JimCrow Configuration
# Auto-generated by setup wizard

# LLM Provider
LLM_PROVIDER={provider_choice}
LLM_MODEL={model}

# API Keys
"""
    
    if provider_choice == "openai":
        env_content += f"OPENAI_API_KEY={api_key}\n"
    elif provider_choice == "openrouter":
        env_content += f"OPENROUTER_API_KEY={api_key}\n"
    else:
        env_content += f"GEMINI_API_KEY={api_key}\n"
    
    if supabase_url:
        env_content += f"\n# Supabase Configuration\n"
        env_content += f"SUPABASE_URL={supabase_url}\n"
        env_content += f"SUPABASE_KEY={supabase_key}\n"
    
    env_content += """
# Application Settings
FASTAPI_HOST=0.0.0.0
FASTAPI_PORT=8000
LOG_LEVEL=INFO

# Security Settings
MAX_CONCURRENT_SCANS=3
REQUEST_TIMEOUT=30
RATE_LIMIT_PER_SECOND=10
"""
    
    # Save to user directory
    user_env = Path.home() / ".jimcrow" / ".env"
    user_env.parent.mkdir(exist_ok=True)
    user_env.write_text(env_content)
    
    # Also save to project directory if possible
    try:
        project_env = Path(".env")
        project_env.write_text(env_content)
        console.print(f"[green]✓ Saved to: {project_env}[/green]")
    except:
        pass
    
    console.print(f"[green]✓ Saved to: {user_env}[/green]")
    
    console.print("\n[bold green]🎉 Setup complete![/bold green]")
    
    # Show what was configured
    console.print("\n[bold]Configuration Summary:[/bold]")
    console.print(f"  • Provider: [cyan]{provider_choice}[/cyan]")
    console.print(f"  • Model: [cyan]{model}[/cyan]")
    console.print(f"  • API Key: [green]✓ Configured[/green]")
    if supabase_url:
        console.print(f"  • Supabase: [green]✓ Configured[/green]")
    else:
        console.print(f"  • Supabase: [dim]Not configured[/dim]")
    
    console.print("\n[bold]Quick Start:[/bold]")
    console.print("  [cyan]1.[/cyan] Authorize a target: [yellow]jim auth add localhost[/yellow]")
    console.print("  [cyan]2.[/cyan] The interactive interface will launch next!")
    console.print()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    interactive: bool = typer.Option(True, help="Use interactive TUI"),
):
    """Start an autonomous AI penetration test scan"""
    mode = "autonomous"  # Single autonomous mode
    if interactive:
        tui = InteractiveTUI()
        asyncio.run(tui.run_scan(target, mode))
    else:
        asyncio.run(scan_cmd.run_scan_headless(target, mode))


@app.command()
def tui():
    """Launch the interactive TUI (also the default when running 'jim')"""
    console.print("\n[cyan]🚀 Launching interactive interface...[/cyan]\n")
    tui = InteractiveTUI()
    asyncio.run(tui.run())


@app.command()
def history(
    limit: int = typer.Option(10, help="Number of recent scans to show"),
    scan_id: Optional[str] = typer.Option(None, help="Show specific scan by ID")
):
    """View scan history"""
    asyncio.run(history_cmd.show_history(limit=limit, scan_id=scan_id))


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to generate report for"),
    format: str = typer.Option("html", help="Report format: html, json, pdf"),
    output: Optional[str] = typer.Option(None, help="Output file path")
):
    """Generate a report for a scan"""
    asyncio.run(history_cmd.generate_report(scan_id, format, output))


@app.command()
def version():
    """Show version information"""
    from . import __version__
    typer.echo(f"JimCrow v{__version__}")


@app.command()
def setup():
    """Re-run the interactive setup wizard"""
    run_interactive_setup()


if __name__ == "__main__":
    app()
