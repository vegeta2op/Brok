"""Knowledge base commands"""

import typer
import asyncio
from rich.console import Console
from rich.markdown import Markdown
from backend.rag import KnowledgeBase

app = typer.Typer()
console = Console()


@app.command("search")
def search(query: str = typer.Argument(..., help="Search query")):
    """Search the knowledge base"""
    asyncio.run(_search(query))


async def _search(query: str):
    """Async search implementation"""
    kb = KnowledgeBase()
    results = await kb.search(query, limit=5)
    
    if not results:
        console.print("[yellow]No results found[/yellow]")
        return
    
    for i, result in enumerate(results, 1):
        console.print(f"\n[bold cyan]{i}. {result.get('title', 'Untitled')}[/bold cyan]")
        console.print(f"[dim]Category: {result.get('category', 'N/A')}[/dim]")
        console.print(f"\n{result.get('content', '')[:300]}...")
        console.print("─" * 80)


@app.command("init")
def initialize():
    """Initialize knowledge base with default content"""
    asyncio.run(_initialize())


async def _initialize():
    """Async initialize implementation"""
    kb = KnowledgeBase()
    
    console.print("[cyan]Populating knowledge base with default content...[/cyan]")
    await kb.populate_default_knowledge()
    console.print("[green]✓ Knowledge base initialized[/green]")

