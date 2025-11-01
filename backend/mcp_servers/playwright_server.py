"""Playwright MCP Server for browser automation"""

import asyncio
from typing import Dict, Any, List
from playwright.async_api import async_playwright, Browser, Page, BrowserContext


class PlaywrightMCPServer:
    """MCP Server for Playwright browser automation"""
    
    def __init__(self):
        self.playwright = None
        self.browser: Browser = None
        self.context: BrowserContext = None
        self.pages: Dict[str, Page] = {}
    
    async def initialize(self):
        """Initialize Playwright and browser"""
        if not self.playwright:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
            self.context = await self.browser.new_context(
                user_agent="JimCrow-PenTest-Agent/0.1.0",
                viewport={"width": 1920, "height": 1080}
            )
    
    async def shutdown(self):
        """Shutdown Playwright and browser"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def navigate(self, url: str, page_id: str = "default") -> Dict[str, Any]:
        """Navigate to a URL"""
        await self.initialize()
        
        if page_id not in self.pages:
            self.pages[page_id] = await self.context.new_page()
        
        page = self.pages[page_id]
        
        try:
            response = await page.goto(url, wait_until="networkidle")
            
            return {
                "success": True,
                "url": page.url,
                "status": response.status if response else None,
                "title": await page.title()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_content(self, page_id: str = "default") -> str:
        """Get page HTML content"""
        if page_id not in self.pages:
            return ""
        
        page = self.pages[page_id]
        return await page.content()
    
    async def screenshot(self, page_id: str = "default", path: str = None) -> bytes:
        """Take a screenshot"""
        if page_id not in self.pages:
            return b""
        
        page = self.pages[page_id]
        return await page.screenshot(path=path, full_page=True)
    
    async def fill_form(self, page_id: str, selector: str, value: str) -> bool:
        """Fill a form field"""
        if page_id not in self.pages:
            return False
        
        page = self.pages[page_id]
        
        try:
            await page.fill(selector, value)
            return True
        except:
            return False
    
    async def click(self, page_id: str, selector: str) -> bool:
        """Click an element"""
        if page_id not in self.pages:
            return False
        
        page = self.pages[page_id]
        
        try:
            await page.click(selector)
            return True
        except:
            return False
    
    async def evaluate(self, page_id: str, script: str) -> Any:
        """Execute JavaScript on the page"""
        if page_id not in self.pages:
            return None
        
        page = self.pages[page_id]
        
        try:
            return await page.evaluate(script)
        except Exception as e:
            return {"error": str(e)}
    
    async def get_cookies(self, page_id: str = "default") -> List[Dict[str, Any]]:
        """Get page cookies"""
        if page_id not in self.pages:
            return []
        
        return await self.context.cookies()
    
    async def set_cookie(self, cookie: Dict[str, Any]):
        """Set a cookie"""
        await self.initialize()
        await self.context.add_cookies([cookie])
    
    async def intercept_requests(self, page_id: str, callback):
        """Intercept and modify requests"""
        if page_id not in self.pages:
            return
        
        page = self.pages[page_id]
        await page.route("**/*", callback)
    
    async def wait_for_selector(self, page_id: str, selector: str, timeout: int = 30000) -> bool:
        """Wait for a selector to appear"""
        if page_id not in self.pages:
            return False
        
        page = self.pages[page_id]
        
        try:
            await page.wait_for_selector(selector, timeout=timeout)
            return True
        except:
            return False
    
    async def get_local_storage(self, page_id: str = "default") -> Dict[str, str]:
        """Get localStorage data"""
        if page_id not in self.pages:
            return {}
        
        page = self.pages[page_id]
        
        return await page.evaluate("() => Object.assign({}, window.localStorage)")
    
    async def get_session_storage(self, page_id: str = "default") -> Dict[str, str]:
        """Get sessionStorage data"""
        if page_id not in self.pages:
            return {}
        
        page = self.pages[page_id]
        
        return await page.evaluate("() => Object.assign({}, window.sessionStorage)")

