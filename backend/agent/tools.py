"""LangChain tools for the pentesting agent"""

from typing import List, Dict, Any, Optional
from langchain.tools import Tool
from langchain_core.tools import tool
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings

# Suppress XML parsing warning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
import httpx
from urllib.parse import urljoin, urlparse
import asyncio
import subprocess
import shlex
import os

# Import page fingerprinting for catch-all detection
from .page_fingerprinting import get_fingerprinter

# Chrome MCP integration (optional, falls back to httpx if not available)
_chrome_client = None
_chrome_client_started = False

async def get_chrome_client():
    """Get or create Chrome MCP client if enabled"""
    global _chrome_client, _chrome_client_started
    
    # Check if Chrome MCP is enabled in config
    chrome_enabled = os.getenv("CHROME_MCP_ENABLED", "false").lower() == "true"
    
    if not chrome_enabled:
        return None
    
    if _chrome_client is None:
        try:
            from ..mcp_servers.mcp_client import get_chrome_mcp_client
            _chrome_client = get_chrome_mcp_client(headless=True)
        except Exception as e:
            # Chrome MCP not available, will fall back to httpx
            print(f"Chrome MCP not available: {e}")
            return None
    
    # Start the client if not already started
    if _chrome_client and not _chrome_client_started:
        try:
            success = await _chrome_client.start()
            if success:
                _chrome_client_started = True
                print("✓ Chrome MCP started successfully")
            else:
                print("✗ Chrome MCP failed to start")
                _chrome_client = None
                return None
        except Exception as e:
            print(f"✗ Error starting Chrome MCP: {e}")
            _chrome_client = None
            return None
    
    return _chrome_client


@tool
async def fetch_page(url: str, log_callback=None) -> str:
    """Fetch and analyze a web page using Chrome browser automation or HTTP client.
    
    Automatically uses Chrome MCP for:
    - JavaScript-heavy sites (SPAs, React, Angular, Vue)
    - Pages requiring authentication
    - Dynamic content rendering
    
    Falls back to HTTP client for simple static pages.
    
    Use this to:
    - Understand what the page is (login, admin, API, etc.)
    - Detect technology stack
    - Find clues about potential vulnerabilities
    - Identify forms and inputs
    
    Args:
        url: The URL to fetch
        
    Returns:
        Detailed page information including headers, status, and analyzed content
    """
    chrome = await get_chrome_client()
    
    # Try Chrome MCP first if available
    if chrome:
        try:
            # Navigate to page
            nav_result = await chrome.navigate(url)
            
            # Get page content after JavaScript execution
            content = await chrome.get_page_content()
            
            # Build analysis
            analysis = []
            analysis.append(f"🌐 Fetched via Chrome Browser (JavaScript executed)")
            analysis.append(f"URL: {url}")
            
            # Analyze the rendered content
            analysis.append(f"\nContent Length: {len(content)} bytes")
            
            # Detect technology from rendered content
            tech_indicators = []
            if 'react' in content.lower() or 'data-react' in content.lower():
                tech_indicators.append("React")
            if 'vue' in content.lower() or 'data-v-' in content.lower():
                tech_indicators.append("Vue.js")
            if 'angular' in content.lower() or 'ng-' in content.lower():
                tech_indicators.append("Angular")
            if 'django' in content.lower() or 'csrfmiddlewaretoken' in content.lower():
                tech_indicators.append("Django")
            
            if tech_indicators:
                analysis.append(f"Technology Detected: {', '.join(tech_indicators)}")
            
            # Find interesting patterns in rendered content
            if '<form' in content:
                form_count = content.count('<form')
                analysis.append(f"Found {form_count} form(s) after JS execution")
            
            if 'admin' in content.lower():
                analysis.append("⚠️ Contains 'admin' text - possible admin interface")
            
            if 'error' in content.lower() or 'exception' in content.lower():
                analysis.append("⚠️ Contains error/exception text - possible information disclosure")
            
            if 'login' in content.lower() or 'sign in' in content.lower():
                analysis.append("\n🔐 Page contains login elements")
            
            # Include sample of rendered content
            analysis.append(f"\nRendered Content Sample (first 3000 chars):\n{content[:3000]}")
            
            return "\n".join(analysis)
            
        except Exception as e:
            # Fall back to HTTP client
            print(f"Chrome MCP failed, falling back to HTTP: {e}")
            pass
    
    # HTTP client fallback (original implementation)
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            
            # Analyze the response for AI
            analysis = []
            analysis.append(f"💻 RAW REQUEST: GET {url}")
            analysis.append(f"   ├─ User-Agent: JimCrow-PenTest-Agent/0.1.0")
            analysis.append(f"   ├─ Follow-Redirects: True")
            analysis.append(f"   └─ Verify-SSL: False")
            analysis.append(f"")
            analysis.append(f"📄 Fetched via HTTP (no JavaScript execution)")
            analysis.append(f"Status Code: {response.status_code}")
            analysis.append(f"Final URL: {response.url} (after redirects)")
            
            # Important headers
            important_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Set-Cookie']
            headers_found = []
            for header in important_headers:
                if header in response.headers:
                    headers_found.append(f"{header}: {response.headers[header]}")
            if headers_found:
                analysis.append(f"\nKey Headers:\n" + "\n".join(headers_found))
            
            # Content analysis
            content = response.text
            analysis.append(f"\nContent Length: {len(content)} bytes")
            
            # CATCH-ALL PAGE DETECTION
            fingerprinter = get_fingerprinter()
            domain = urlparse(url).netloc
            
            # If this is the first page from this domain, learn it as homepage
            if domain not in fingerprinter.fingerprints and urlparse(url).path in ['/', '']:
                fingerprinter.learn_homepage(domain, content)
                analysis.append("\n📌 Learned homepage fingerprint for catch-all detection")
            
            # Check if this is a catch-all page
            page_analysis = fingerprinter.analyze_response(domain, url, content, response.status_code)
            
            if page_analysis['is_catchall']:
                analysis.append(f"\n⚠️ CATCH-ALL PAGE DETECTED!")
                analysis.append(f"❌ This URL returns the SAME content as homepage")
                analysis.append(f"Reason: {page_analysis['reason']}")
                analysis.append(f"🔍 This is NOT a real endpoint - likely SPA client-side routing")
                analysis.append(f"\n💡 AI: Don't waste time testing this - it's not a real page!")
                return "\n".join(analysis)
            else:
                analysis.append(f"\n✅ UNIQUE PAGE DETECTED - This is a real endpoint!")
                analysis.append(f"Reason: {page_analysis['reason']}")
            
            # Detect technology
            tech_indicators = []
            if 'php' in content.lower() or '.php' in str(response.url):
                tech_indicators.append("PHP")
            if 'wordpress' in content.lower():
                tech_indicators.append("WordPress")
            if 'react' in content.lower() or 'data-react' in content.lower():
                tech_indicators.append("React")
                analysis.append("\n💡 Tip: This is a React app - Chrome browser mode recommended for full testing")
            if 'vue' in content.lower() or 'data-v-' in content.lower():
                tech_indicators.append("Vue.js")
                analysis.append("\n💡 Tip: This is a Vue.js app - Chrome browser mode recommended")
            if 'angular' in content.lower() or 'ng-' in content.lower():
                tech_indicators.append("Angular")
                analysis.append("\n💡 Tip: This is an Angular app - Chrome browser mode recommended")
            if 'django' in content.lower() or 'csrfmiddlewaretoken' in content.lower():
                tech_indicators.append("Django")
            
            if tech_indicators:
                analysis.append(f"Technology Detected: {', '.join(tech_indicators)}")
            
            # Find interesting patterns
            if '<form' in content:
                form_count = content.count('<form')
                analysis.append(f"Found {form_count} form(s) - potential input vectors")
            
            if 'admin' in content.lower():
                analysis.append("⚠️ Contains 'admin' text - possible admin interface")
            
            if 'error' in content.lower() or 'exception' in content.lower():
                analysis.append("⚠️ Contains error/exception text - possible information disclosure")
            
            # Check if login might be required
            if 'login' in content.lower() or 'sign in' in content.lower():
                analysis.append("\n🔐 Page contains login elements - authentication may be required")
            
            # Include sample of content for AI to read
            analysis.append(f"\nContent Sample (first 3000 chars):\n{content[:3000]}")
            
            return "\n".join(analysis)
            
    except Exception as e:
        return f"Error fetching page: {str(e)}"


@tool
async def extract_forms(url: str, html_content: str) -> str:
    """Extract all forms from HTML content.
    
    Args:
        url: The base URL for resolving relative URLs
        html_content: HTML content to parse
        
    Returns:
        JSON-formatted string of discovered forms
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return str(forms)
    except Exception as e:
        return f"Error extracting forms: {str(e)}"


@tool
async def extract_links(url: str, html_content: str) -> str:
    """Extract all links from HTML content.
    
    Args:
        url: The base URL for resolving relative URLs
        html_content: HTML content to parse
        
    Returns:
        List of discovered URLs
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = set()
        
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(url, link['href'])
            # Only include links from the same domain
            if urlparse(absolute_url).netloc == urlparse(url).netloc:
                links.add(absolute_url)
        
        return "\n".join(list(links)[:50])  # Limit to 50 links
    except Exception as e:
        return f"Error extracting links: {str(e)}"


@tool
async def test_sql_injection(url: str, parameter: str) -> str:
    """Test a URL parameter for SQL injection vulnerability.
    
    Args:
        url: The URL to test
        parameter: The parameter name to test
        
    Returns:
        Result of the SQL injection test
    """
    # This would use the SQL injection module
    return f"SQL injection test for {parameter} at {url} - This is a placeholder. Real implementation uses SQLInjectionModule."


@tool
async def test_xss(url: str, parameter: str) -> str:
    """Test a URL parameter for XSS vulnerability.
    
    Args:
        url: The URL to test
        parameter: The parameter name to test
        
    Returns:
        Result of the XSS test
    """
    # This would use the XSS module
    return f"XSS test for {parameter} at {url} - This is a placeholder. Real implementation uses XSSModule."


@tool
async def analyze_security_headers(url: str) -> str:
    """Analyze HTTP security headers for a URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Security header analysis
    """
    try:
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            response = await client.get(url)
            
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'MISSING'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'MISSING'),
                'X-Frame-Options': response.headers.get('X-Frame-Options', 'MISSING'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'MISSING'),
                'Referrer-Policy': response.headers.get('Referrer-Policy', 'MISSING')
            }
            
            result = "Security Headers Analysis:\n"
            for header, value in security_headers.items():
                result += f"  {header}: {value}\n"
            
            return result
    except Exception as e:
        return f"Error analyzing headers: {str(e)}"


@tool
async def check_robots_txt(url: str) -> str:
    """Check robots.txt for information disclosure.
    
    Args:
        url: The base URL to check
        
    Returns:
        Contents of robots.txt or error message
    """
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            response = await client.get(robots_url)
            
            if response.status_code == 200:
                return f"robots.txt found:\n{response.text}"
            else:
                return f"robots.txt not found (Status: {response.status_code})"
    except Exception as e:
        return f"Error checking robots.txt: {str(e)}"


@tool
async def execute_curl(url: str, options: str = "") -> str:
    """Execute a curl command to test HTTP requests with specific options.
    
    Args:
        url: Target URL
        options: Additional curl options (e.g., "-H 'User-Agent: test' -X POST")
        
    Returns:
        Curl command output
        
    Example:
        execute_curl("https://example.com/api", "-H 'Content-Type: application/json' -X GET")
    """
    try:
        # Build safe curl command
        cmd = ["curl", "-s", "-i", "-L"]
        
        # Parse and add safe options
        if options:
            # Only allow safe curl options
            safe_options = ["-H", "-X", "-d", "--data", "--user-agent", "-A", "-b", "--cookie"]
            parts = shlex.split(options)
            i = 0
            while i < len(parts):
                if parts[i] in safe_options and i + 1 < len(parts):
                    cmd.append(parts[i])
                    cmd.append(parts[i + 1])
                    i += 2
                else:
                    i += 1
        
        cmd.append(url)
        
        # Execute with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = f"COMMAND: {' '.join(cmd)}\n\n"
        output += f"OUTPUT:\n{result.stdout[:2000]}"
        
        if result.stderr:
            output += f"\n\nERROR:\n{result.stderr[:500]}"
            
        return output
        
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds"
    except Exception as e:
        return f"Error executing curl: {str(e)}"


@tool
async def execute_grep(pattern: str, text: str) -> str:
    """Search for patterns in text using grep-like functionality.
    
    Args:
        pattern: Regular expression pattern to search for
        text: Text content to search in
        
    Returns:
        Matching lines
        
    Example:
        execute_grep("Content-Type", "HTTP headers text")
    """
    try:
        import re
        
        lines = text.split('\n')
        matches = []
        
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                matches.append(f"{i}: {line}")
        
        if matches:
            return f"Found {len(matches)} matches:\n" + '\n'.join(matches[:50])
        else:
            return f"No matches found for pattern: {pattern}"
            
    except Exception as e:
        return f"Error executing grep: {str(e)}"


@tool
async def execute_nmap_scan(target: str, scan_type: str = "basic") -> str:
    """Execute a basic nmap scan (limited to safe options).
    
    Args:
        target: Target host/IP
        scan_type: Type of scan - "basic" (ports), "service" (service detection)
        
    Returns:
        Nmap scan results
        
    Note: Only safe, non-intrusive scans are allowed
    """
    try:
        # Build safe nmap command
        if scan_type == "service":
            cmd = ["nmap", "-sV", "--top-ports", "10", target]
        else:
            cmd = ["nmap", "-p", "80,443,8080,8443", target]
        
        # Execute with timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = f"COMMAND: {' '.join(cmd)}\n\n"
        output += f"OUTPUT:\n{result.stdout[:2000]}"
        
        return output
        
    except subprocess.TimeoutExpired:
        return "Error: Nmap scan timed out"
    except FileNotFoundError:
        return "Error: nmap not installed on system"
    except Exception as e:
        return f"Error executing nmap: {str(e)}"


def get_pentest_tools() -> List[Tool]:
    """Get all pentesting tools for the agent"""
    return [
        fetch_page,
        extract_forms,
        extract_links,
        test_sql_injection,
        test_xss,
        analyze_security_headers,
        check_robots_txt,
        execute_curl,
        execute_grep,
        execute_nmap_scan
    ]

