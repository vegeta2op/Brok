"""Proper MCP Client Implementation using stdio transport
Based on Model Context Protocol specification
"""

import asyncio
import json
from typing import Any, Dict, Optional, List
import subprocess
import sys


class MCPClient:
    """Client for communicating with MCP servers via stdio transport"""
    
    def __init__(self, server_command: List[str]):
        """
        Initialize MCP client
        
        Args:
            server_command: Command to start MCP server (e.g., ['npx', 'chrome-devtools-mcp@latest'])
        """
        self.server_command = server_command
        self.process: Optional[subprocess.Popen] = None
        self.request_id = 0
        self.initialized = False
    
    async def start(self) -> bool:
        """Start the MCP server process"""
        try:
            # Start server with stdio pipes
            self.process = subprocess.Popen(
                self.server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Wait a moment for server to start
            await asyncio.sleep(1)
            
            # Initialize the MCP connection
            await self._initialize()
            
            return True
            
        except Exception as e:
            print(f"Failed to start MCP server: {e}", file=sys.stderr)
            return False
    
    async def _initialize(self) -> Dict[str, Any]:
        """Send initialize request to MCP server"""
        response = await self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {
                        "listChanged": False
                    },
                    "sampling": {}
                },
                "clientInfo": {
                    "name": "jimcrow-pentest",
                    "version": "2.0.0"
                }
            }
        )
        
        if response and not response.get("error"):
            self.initialized = True
            
            # Send initialized notification
            await self._send_notification("notifications/initialized")
            
        return response
    
    async def _send_request(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Send JSON-RPC request to MCP server
        
        Args:
            method: JSON-RPC method name
            params: Method parameters
            
        Returns:
            JSON-RPC response
        """
        if not self.process or not self.process.stdin:
            raise RuntimeError("MCP server not started")
        
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params or {}
        }
        
        # Send request via stdin
        request_json = json.dumps(request) + "\n"
        self.process.stdin.write(request_json)
        self.process.stdin.flush()
        
        # Read response from stdout
        response_line = await asyncio.to_thread(self.process.stdout.readline)
        
        if not response_line:
            raise RuntimeError("No response from MCP server")
        
        response = json.loads(response_line)
        
        if "error" in response:
            error = response["error"]
            raise RuntimeError(f"MCP error: {error.get('message', 'Unknown error')}")
        
        return response.get("result", {})
    
    async def _send_notification(self, method: str, params: Optional[Dict] = None):
        """Send JSON-RPC notification (no response expected)"""
        if not self.process or not self.process.stdin:
            return
        
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {}
        }
        
        notification_json = json.dumps(notification) + "\n"
        self.process.stdin.write(notification_json)
        self.process.stdin.flush()
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from MCP server"""
        if not self.initialized:
            raise RuntimeError("MCP client not initialized")
        
        response = await self._send_request("tools/list")
        return response.get("tools", [])
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool on the MCP server
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            
        Returns:
            Tool execution result
        """
        if not self.initialized:
            raise RuntimeError("MCP client not initialized")
        
        result = await self._send_request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments
            }
        )
        
        return result
    
    async def stop(self):
        """Stop the MCP server process"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
            self.initialized = False


class ChromeDevToolsMCPClient:
    """High-level client for Chrome DevTools MCP server"""
    
    def __init__(self, headless: bool = True):
        """
        Initialize Chrome DevTools MCP client
        
        Args:
            headless: Whether to run Chrome in headless mode
        """
        self.headless = headless
        
        # Build server command
        server_command = ["npx", "-y", "chrome-devtools-mcp@latest"]
        if headless:
            server_command.append("--headless=true")
        server_command.append("--isolated=true")
        
        self.client = MCPClient(server_command)
        self.current_page_id: Optional[str] = None
    
    async def start(self) -> bool:
        """Start the Chrome DevTools MCP server"""
        return await self.client.start()
    
    async def list_available_tools(self) -> List[str]:
        """List all available tools"""
        tools = await self.client.list_tools()
        return [tool["name"] for tool in tools]
    
    async def navigate(self, url: str) -> Dict[str, Any]:
        """
        Navigate to a URL
        
        Args:
            url: URL to navigate to
            
        Returns:
            Navigation result
        """
        # If no page exists, create one
        if not self.current_page_id:
            result = await self.client.call_tool("new_page", {})
            if result.get("content"):
                # Parse page ID from result
                content = result["content"][0]
                if content.get("type") == "text":
                    # Extract page ID from response
                    text = content.get("text", "")
                    if "Page ID:" in text:
                        self.current_page_id = text.split("Page ID:")[1].strip().split()[0]
        
        # Navigate to URL
        result = await self.client.call_tool(
            "navigate_page",
            {
                "url": url,
                "pageId": self.current_page_id
            }
        )
        
        return result
    
    async def click(self, selector: str) -> Dict[str, Any]:
        """
        Click an element
        
        Args:
            selector: CSS selector for element to click
            
        Returns:
            Click result
        """
        return await self.client.call_tool(
            "click",
            {
                "selector": selector,
                "pageId": self.current_page_id
            }
        )
    
    async def fill(self, selector: str, value: str) -> Dict[str, Any]:
        """
        Fill a form field
        
        Args:
            selector: CSS selector for input field
            value: Value to fill
            
        Returns:
            Fill result
        """
        return await self.client.call_tool(
            "fill",
            {
                "selector": selector,
                "value": value,
                "pageId": self.current_page_id
            }
        )
    
    async def screenshot(self, path: str = "screenshot.png") -> Dict[str, Any]:
        """
        Take screenshot
        
        Args:
            path: Path to save screenshot
            
        Returns:
            Screenshot result
        """
        return await self.client.call_tool(
            "take_screenshot",
            {
                "path": path,
                "pageId": self.current_page_id
            }
        )
    
    async def evaluate_script(self, script: str) -> Dict[str, Any]:
        """
        Execute JavaScript in page context
        
        Args:
            script: JavaScript code to execute
            
        Returns:
            Script execution result
        """
        return await self.client.call_tool(
            "evaluate_script",
            {
                "script": script,
                "pageId": self.current_page_id
            }
        )
    
    async def get_page_content(self) -> str:
        """Get current page HTML content"""
        result = await self.evaluate_script("document.documentElement.outerHTML")
        
        if result.get("content"):
            content = result["content"][0]
            if content.get("type") == "text":
                return content.get("text", "")
        
        return ""
    
    async def stop(self):
        """Stop the Chrome DevTools MCP server"""
        await self.client.stop()


# Singleton instance
_chrome_mcp_client: Optional[ChromeDevToolsMCPClient] = None


def get_chrome_mcp_client(headless: bool = True) -> ChromeDevToolsMCPClient:
    """Get or create Chrome MCP client singleton"""
    global _chrome_mcp_client
    
    if _chrome_mcp_client is None:
        _chrome_mcp_client = ChromeDevToolsMCPClient(headless=headless)
    
    return _chrome_mcp_client

