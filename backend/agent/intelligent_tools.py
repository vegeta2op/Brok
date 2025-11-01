"""Intelligent AI-driven pentesting tools that adapt and reason"""

from langchain.tools import tool
from typing import Dict, Any
import httpx
import asyncio
import os
from urllib.parse import urljoin, urlparse

# Import page fingerprinting for catch-all detection
from .page_fingerprinting import get_fingerprinter

# Import fuzzing engine
from .fuzzing import FuzzingEngine, get_default_wordlists


@tool
async def intelligent_sql_test(url: str, parameter: str, context: str) -> str:
    """AI-driven SQL injection testing that adapts based on context.
    
    The AI analyzes the target and crafts intelligent test payloads.
    
    Args:
        url: Target URL
        parameter: Parameter to test
        context: What you learned about the target (database type, error messages, etc.)
        
    Returns:
        Detailed results for AI to analyze
    """
    results = []
    results.append(f"Testing parameter '{parameter}' at {url}")
    results.append(f"Context: {context}")
    
    # Intelligent payload selection based on context
    payloads = _select_intelligent_payloads(context)
    
    results.append(f"\nUsing {len(payloads)} context-aware payloads")
    
    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        for i, payload in enumerate(payloads[:5], 1):  # Limit for safety
            try:
                # Build test URL
                test_url = f"{url}?{parameter}={payload}"
                
                response = await client.get(test_url)
                
                # Analyze response intelligently
                analysis = _analyze_sql_response(response, payload)
                
                results.append(f"\n[Test {i}] Payload: {payload[:50]}...")
                results.append(f"Status: {response.status_code}")
                results.append(f"Analysis: {analysis}")
                
                # If we find something interesting, note it
                if "SQL" in response.text or "error" in response.text.lower():
                    results.append("⚠️ POTENTIAL VULNERABILITY: SQL error detected!")
                    results.append(f"Error snippet: {response.text[:200]}")
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                results.append(f"[Test {i}] Error: {str(e)}")
    
    return "\n".join(results)


def _select_intelligent_payloads(context: str) -> list:
    """Select payloads based on what AI learned about target"""
    context_lower = context.lower()
    
    payloads = []
    
    # Basic detection payloads
    payloads.extend([
        "'",
        "\"",
        "' OR '1'='1",
    ])
    
    # If we detected MySQL
    if "mysql" in context_lower or "php" in context_lower:
        payloads.extend([
            "' OR 1=1 -- ",
            "' UNION SELECT NULL,NULL -- ",
            "' AND SLEEP(5) -- ",
        ])
    
    # If we detected PostgreSQL
    if "postgres" in context_lower or "postgresql" in context_lower:
        payloads.extend([
            "' OR 1=1--",
            "'; SELECT pg_sleep(5)--",
        ])
    
    # If we detected MSSQL
    if "mssql" in context_lower or "sqlserver" in context_lower:
        payloads.extend([
            "' OR 1=1--",
            "'; WAITFOR DELAY '00:00:05'--",
        ])
    
    # If we saw error messages, try more specific exploitation
    if "error" in context_lower:
        payloads.extend([
            "' UNION SELECT NULL--",
            "1' AND '1'='2",
        ])
    
    return payloads


def _analyze_sql_response(response: httpx.Response, payload: str) -> str:
    """Intelligently analyze the response"""
    analysis = []
    
    content = response.text.lower()
    
    # Check for SQL errors
    sql_errors = [
        "sql syntax", "mysql", "postgresql", "oracle", "mssql",
        "sqlite", "syntax error", "unterminated", "unexpected"
    ]
    
    for error_type in sql_errors:
        if error_type in content:
            analysis.append(f"Detected {error_type} error")
    
    # Check for successful injection indicators
    if response.status_code != 200:
        analysis.append(f"Status changed to {response.status_code}")
    
    # Check for response length anomalies
    if len(response.text) > 10000 or len(response.text) < 100:
        analysis.append("Response length anomaly detected")
    
    if not analysis:
        analysis.append("No obvious vulnerability indicators")
    
    return ", ".join(analysis)


@tool
async def intelligent_xss_test(url: str, parameter: str, reflection_info: str) -> str:
    """AI-driven XSS testing that adapts to WAF and filters.
    
    Args:
        url: Target URL
        parameter: Parameter to test  
        reflection_info: Info about how input is reflected (if at all)
        
    Returns:
        Test results for AI analysis
    """
    results = []
    results.append(f"Testing XSS in parameter '{parameter}'")
    results.append(f"Reflection info: {reflection_info}")
    
    # Generate intelligent payloads
    payloads = _generate_xss_payloads(reflection_info)
    
    results.append(f"\nTesting {len(payloads)} context-aware XSS payloads")
    
    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        for i, payload in enumerate(payloads[:5], 1):
            try:
                test_url = f"{url}?{parameter}={payload}"
                response = await client.get(test_url)
                
                # Check if payload is reflected without encoding
                if payload in response.text or payload.replace(' ', '') in response.text.replace(' ', ''):
                    results.append(f"\n[Test {i}] ⚠️ POTENTIAL XSS!")
                    results.append(f"Payload: {payload}")
                    results.append(f"Payload reflected without proper encoding!")
                else:
                    results.append(f"\n[Test {i}] Payload filtered or encoded")
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                results.append(f"[Test {i}] Error: {str(e)}")
    
    return "\n".join(results)


def _generate_xss_payloads(reflection_info: str) -> list:
    """Generate context-aware XSS payloads"""
    info_lower = reflection_info.lower()
    
    payloads = []
    
    # Basic detection
    payloads.append("<script>alert('XSS')</script>")
    
    # If input is in an attribute
    if "attribute" in info_lower:
        payloads.extend([
            "' onload='alert(1)",
            '" onfocus="alert(1)" autofocus="',
        ])
    
    # If there's a WAF
    if "filter" in info_lower or "waf" in info_lower:
        payloads.extend([
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
        ])
    
    # DOM-based
    payloads.extend([
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
    ])
    
    return payloads


async def _get_chrome_mcp():
    """Get Chrome MCP client if available"""
    chrome_enabled = os.getenv("CHROME_MCP_ENABLED", "false").lower() == "true"
    if not chrome_enabled:
        return None
    
    try:
        from ..mcp_servers.mcp_client import get_chrome_mcp_client
        chrome = get_chrome_mcp_client(headless=True)
        
        # Start if not already running
        if not chrome.client.initialized:
            success = await chrome.start()
            if not success:
                return None
        
        return chrome
    except Exception as e:
        print(f"Chrome MCP not available: {e}")
        return None


@tool
async def intelligent_reconnaissance(url: str) -> str:
    """AGGRESSIVE AI-driven reconnaissance that discovers maximum attack surface.
    
    Performs deep analysis including:
    - Technology stack detection (via Chrome MCP if available)
    - ALL possible entry points and endpoints
    - Hidden directories and files
    - API endpoints
    - Authentication mechanisms
    - JavaScript-rendered content (via Chrome MCP)
    - Client-side vulnerabilities
    - Potential vulnerabilities
    - Attack vectors
    - Security misconfigurations
    
    Automatically uses Chrome MCP for JavaScript execution when available,
    falls back to HTTP for speed.
    
    Args:
        url: Target URL to reconnoiter
        
    Returns:
        Comprehensive intelligence report with discovered attack surface
    """
    report = []
    report.append(f"=== DEEP RECONNAISSANCE: {url} ===\n")
    
    # Try Chrome MCP first for JavaScript-heavy sites
    chrome = await _get_chrome_mcp()
    
    if chrome:
        try:
            report.append("🌐 Using Chrome Browser (JavaScript execution enabled)")
            
            # Navigate with Chrome
            await chrome.navigate(url)
            
            # Get rendered content
            content = await chrome.get_page_content()
            
            # Get page title
            title_result = await chrome.evaluate_script("document.title")
            if title_result.get("content"):
                title = title_result["content"][0].get("text", "Unknown")
                report.append(f"Title: {title}")
            
            # Detect technology from rendered content
            tech = []
            if 'react' in content.lower() or 'data-react' in content.lower():
                tech.append("React (detected after JS execution)")
            if 'vue' in content.lower() or 'data-v-' in content.lower():
                tech.append("Vue.js (detected after JS execution)")
            if 'angular' in content.lower() or 'ng-' in content.lower():
                tech.append("Angular (detected after JS execution)")
            if 'next' in content.lower():
                tech.append("Next.js")
            
            if tech:
                report.append(f"🔍 Technology (JS executed): {', '.join(tech)}")
            
            # Find forms in rendered DOM
            form_result = await chrome.evaluate_script("""
                Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.querySelectorAll('input')).map(i => i.name)
                }))
            """)
            
            if form_result.get("content"):
                forms_text = form_result["content"][0].get("text", "")
                if "action" in forms_text:
                    report.append(f"📝 Forms detected in rendered DOM: {forms_text[:200]}")
            
            # Extract all links from rendered page
            links_result = await chrome.evaluate_script("""
                Array.from(document.querySelectorAll('a'))
                    .map(a => a.href)
                    .filter(h => h && h.startsWith(window.location.origin))
                    .slice(0, 20)
                    .join('\\n')
            """)
            
            if links_result.get("content"):
                links = links_result["content"][0].get("text", "")
                if links:
                    link_list = links.split('\n')
                    report.append(f"\n🔗 Discovered {len(link_list)} internal links:")
                    for link in link_list[:10]:
                        if link:
                            report.append(f"  → {link}")
                    if len(link_list) > 10:
                        report.append(f"  ... and {len(link_list) - 10} more")
            
            # Check for API calls in network requests
            report.append("\n🌐 Monitoring for API endpoints...")
            
            # Check console for errors/warnings
            console_result = await chrome.client.call_tool("list_console_messages", {"pageId": chrome.current_page_id})
            if console_result.get("content"):
                report.append("📋 Console messages detected (may reveal vulnerabilities)")
            
            report.append("\n✓ Browser-based reconnaissance complete")
            
        except Exception as e:
            report.append(f"\n⚠️ Chrome MCP error: {e}")
            report.append("Falling back to HTTP reconnaissance...")
            chrome = None  # Fall back to HTTP
    
    # HTTP fallback or standard reconnaissance
    if not chrome:
        report.append("📄 Using HTTP (no JavaScript execution)")
    
    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        # Main page analysis
        try:
            response = await client.get(url)
            report.append(f"✓ Main page accessible: {response.status_code}")
            
            # Learn homepage fingerprint for catch-all detection
            fingerprinter = get_fingerprinter()
            domain = urlparse(url).netloc
            content = response.text
            
            if domain not in fingerprinter.fingerprints:
                fingerprinter.learn_homepage(domain, content)
                report.append(f"📌 Learned homepage fingerprint for catch-all detection")
            
            # Analyze headers for technology detection
            headers = dict(response.headers)
            if 'Server' in headers:
                report.append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                report.append(f"Powered by: {headers['X-Powered-By']}")
            
            # Technology detection
            tech = []
            if 'wp-content' in content or 'wordpress' in content.lower():
                tech.append("WordPress CMS")
            if 'django' in content.lower():
                tech.append("Django Framework")
            if 'react' in content.lower():
                tech.append("React Frontend")
            if '.php' in content or '<?php' in content:
                tech.append("PHP Backend")
            
            if tech:
                report.append(f"\n🔍 Technology Detected: {', '.join(tech)}")
            
            # Find forms
            form_count = content.count('<form')
            if form_count > 0:
                report.append(f"\n📝 Found {form_count} forms (potential input vectors)")
            
            # Find interesting endpoints
            interesting_keywords = ['admin', 'login', 'api', 'upload', 'search']
            found_keywords = [kw for kw in interesting_keywords if kw in content.lower()]
            if found_keywords:
                report.append(f"🎯 Interesting keywords: {', '.join(found_keywords)}")
            
        except Exception as e:
            report.append(f"✗ Error accessing main page: {str(e)}")
        
        # Check extensive common paths (aggressive discovery)
        common_paths = [
            # Standard paths
            '/robots.txt', '/sitemap.xml', '/admin', '/login', '/api', '/graphql',
            # Admin panels
            '/admin/', '/administrator', '/wp-admin', '/admin/login', '/admin.php',
            # Auth endpoints
            '/signin', '/signup', '/register', '/forgot-password', '/reset-password', '/logout',
            # User areas
            '/profile', '/account', '/dashboard', '/settings', '/user', '/my-account',
            # API endpoints
            '/api/v1', '/api/v2', '/rest', '/rest/api', '/api/users', '/api/auth',
            # Hidden/Debug
            '/.git/config', '/.env', '/debug', '/test', '/phpinfo.php', '/info.php',
            # Backup/Config
            '/backup', '/backups', '/config', '/configuration', '/.well-known',
            # Documentation
            '/swagger', '/swagger-ui', '/api-docs', '/docs', '/documentation',
            # Other common
            '/search', '/upload', '/uploads', '/files', '/download', '/static', '/assets'
        ]
        report.append(f"\n🔎 Checking {len(common_paths)} common paths (aggressive discovery)...")
        
        discovered_paths = []
        catchall_detected_count = 0
        for path in common_paths:
            try:
                test_url = urljoin(url, path)
                resp = await client.get(test_url, follow_redirects=False)
                
                if resp.status_code == 200:
                    # Check if this is a catch-all page
                    page_analysis = fingerprinter.analyze_response(domain, test_url, resp.text, resp.status_code)
                    
                    if page_analysis['is_catchall']:
                        catchall_detected_count += 1
                        # Don't report as discovered - it's fake!
                        if catchall_detected_count <= 3:  # Only show first 3 to avoid spam
                            report.append(f"  ❌ {path} - CATCH-ALL (returns homepage) - NOT A REAL PAGE!")
                    else:
                        report.append(f"  ✓ {path} - REAL ENDPOINT (200) - HIGH VALUE TARGET!")
                        discovered_paths.append(path)
                elif resp.status_code == 403:
                    report.append(f"  ⚠️  {path} - EXISTS but FORBIDDEN (403) - Try bypass!")
                    discovered_paths.append(path)
                elif resp.status_code in [301, 302]:
                    report.append(f"  → {path} - REDIRECTS ({resp.status_code}) - Follow redirect!")
                    discovered_paths.append(path)
                
                await asyncio.sleep(0.2)  # Faster but still polite
            except:
                pass
        
        if catchall_detected_count > 3:
            report.append(f"  ... and {catchall_detected_count - 3} more catch-all pages (skipped)")
        
        if discovered_paths:
            report.append(f"\n🎯 DISCOVERED {len(discovered_paths)} ACCESSIBLE PATHS - PRIORITY TARGETS FOR TESTING!")
            report.append(f"Paths: {', '.join(discovered_paths[:10])}")
            if len(discovered_paths) > 10:
                report.append(f"... and {len(discovered_paths) - 10} more")
        
        # If we have Chrome, check these discovered paths with browser
        if chrome and discovered_paths:
            report.append("\n🔍 Analyzing discovered paths with browser...")
            for path in discovered_paths[:5]:  # Check top 5 with browser
                try:
                    full_url = urljoin(url, path)
                    await chrome.navigate(full_url)
                    
                    # Check if it's a login page
                    has_password = await chrome.evaluate_script(
                        "document.querySelectorAll('input[type=password]').length > 0"
                    )
                    if has_password.get("content"):
                        is_login = has_password["content"][0].get("text", "")
                        if "true" in is_login.lower():
                            report.append(f"  🔐 {path} - LOGIN PAGE DETECTED (has password field)")
                    
                    await asyncio.sleep(0.3)
                except:
                    pass
    
    report.append(f"\n📊 Reconnaissance complete. Analyze findings to plan attack strategy.")
    
    return "\n".join(report)


from urllib.parse import urljoin

