"""CLI commands for managing authentication sessions"""

import typer
from rich.console import Console
from rich.table import Table
from getpass import getpass
from urllib.parse import urlparse

from backend.auth.session_manager import SessionManager

app = typer.Typer(help="Manage authentication sessions for scanning")
console = Console()


@app.command("add")
def add_session(
    domain: str = typer.Argument(..., help="Domain to add session for (e.g., example.com)"),
    username: str = typer.Option(None, "--username", "-u", help="Username or email"),
    password: str = typer.Option(None, "--password", "-p", help="Password (will prompt if not provided)"),
    login_url: str = typer.Option(None, "--login-url", "-l", help="Login page URL"),
    username_field: str = typer.Option("username", "--username-field", help="Username field name/selector"),
    password_field: str = typer.Option("password", "--password-field", help="Password field name/selector"),
):
    """Add authentication session for a domain"""
    
    session_manager = SessionManager()
    
    # Parse domain if full URL provided
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    
    # Prompt for credentials if not provided
    if not username:
        username = typer.prompt("Username/Email")
    
    if not password:
        password = getpass("Password: ")
    
    # Default login URL
    if not login_url:
        login_url = f"https://{domain}/login"
    
    # Store session
    credentials = {
        "username": username,
        "password": password,
        "login_url": login_url,
        "username_field": username_field,
        "password_field": password_field
    }
    
    session_manager.add_session(domain, credentials)
    
    console.print(f"[green]✓[/green] Session added for {domain}")
    console.print(f"  Login URL: {login_url}")
    console.print(f"  Username: {username}")


@app.command("list")
def list_sessions():
    """List all stored authentication sessions"""
    
    session_manager = SessionManager()
    sessions = session_manager.get_all_sessions()
    
    if not sessions:
        console.print("[yellow]No sessions stored[/yellow]")
        return
    
    table = Table(title="Stored Authentication Sessions")
    table.add_column("Domain", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("Login URL", style="blue")
    
    for domain, session in sessions.items():
        username = session.get("credentials", {}).get("username", "N/A")
        login_url = session.get("credentials", {}).get("login_url", "N/A")
        table.add_row(domain, username, login_url)
    
    console.print(table)


@app.command("remove")
def remove_session(
    domain: str = typer.Argument(..., help="Domain to remove session for")
):
    """Remove authentication session for a domain"""
    
    session_manager = SessionManager()
    
    # Parse domain if full URL provided
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    
    if session_manager.remove_session(domain):
        console.print(f"[green]✓[/green] Session removed for {domain}")
    else:
        console.print(f"[yellow]No session found for {domain}[/yellow]")


@app.command("test")
def test_session(
    domain: str = typer.Argument(..., help="Domain to test session for"),
    headless: bool = typer.Option(False, "--headless", help="Run in headless mode")
):
    """Test authentication session (opens browser)"""
    
    import asyncio
    from backend.auth.session_manager import SessionManager
    from backend.mcp_servers.chrome_devtools_client import get_chrome_client
    
    session_manager = SessionManager()
    
    # Parse domain if full URL provided
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    
    session = session_manager.get_session(domain)
    if not session:
        console.print(f"[red]No session found for {domain}[/red]")
        console.print(f"Add one with: [cyan]jim session add {domain}[/cyan]")
        return
    
    async def test_login():
        chrome = get_chrome_client(headless=headless)
        console.print("Starting Chrome browser...")
        await chrome.start()
        
        credentials = session["credentials"]
        console.print(f"Navigating to {credentials['login_url']}...")
        
        result = await chrome.login(
            url=credentials["login_url"],
            username=credentials["username"],
            password=credentials["password"],
            username_selector=f"input[name='{session['username_field']}']",
            password_selector=f"input[name='{session['password_field']}']"
        )
        
        if result["success"]:
            console.print("[green]✓[/green] Login successful!")
        else:
            console.print(f"[red]✗[/red] Login failed: {result.get('error')}")
        
        if not headless:
            console.print("\n[yellow]Browser will stay open for inspection. Press Ctrl+C to close.[/yellow]")
            try:
                await asyncio.sleep(3600)  # Keep open for 1 hour
            except KeyboardInterrupt:
                pass
        
        await chrome.stop()
    
    asyncio.run(test_login())


if __name__ == "__main__":
    app()

