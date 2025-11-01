"""LangChain tools for smart fuzzing"""

from langchain.tools import tool
from .fuzzing import FuzzingEngine, get_default_wordlists, COMMON_PATHS
import asyncio


@tool
async def smart_fuzz_discovery(url: str) -> str:
    """FAST directory/endpoint discovery using smart fuzzing with content-length analysis.
    
    This is MUCH faster than testing endpoints one by one!
    
    How it works:
    1. Tests 100+ paths concurrently (10 at a time)
    2. Groups responses by content length
    3. Identifies catch-all pages (most common length)
    4. Returns only UNIQUE endpoints (different lengths)
    5. Verifies with fingerprinting to avoid false positives
    
    Use this instead of manually testing /admin, /api, /login one by one!
    
    Args:
        url: Base URL to fuzz (e.g., https://example.com)
        
    Returns:
        Detailed report of discovered unique endpoints
    """
    engine = FuzzingEngine()
    wordlists = get_default_wordlists()
    
    # Start with common paths for speed
    results = await engine.fuzz_paths(
        url,
        COMMON_PATHS,
        max_concurrent=10,
        timeout=10.0
    )
    
    report = []
    report.append(f"=== SMART FUZZING RESULTS: {url} ===\n")
    report.append(f"⚡ Tested: {results['total_tested']} paths concurrently")
    report.append(f"🎯 Unique endpoints found: {results['unique_found']}")
    
    # Report catch-all detection
    if results['catch_all_detected']:
        baseline = results['baseline_length']
        report.append(f"\n⚠️  CATCH-ALL DETECTED!")
        report.append(f"Baseline length: {baseline} bytes")
        report.append(f"Most responses return same content - filtering them out...")
    
    # Report length distribution
    if results['length_clusters']:
        report.append(f"\n📊 Content Length Distribution:")
        for length, count in sorted(results['length_clusters'].items(), key=lambda x: int(x[0])):
            indicator = " ← CATCH-ALL" if int(length) == results.get('baseline_length') else ""
            report.append(f"  • {length} bytes: {count} responses{indicator}")
    
    # Report status codes
    if results['status_codes']:
        report.append(f"\n📡 Status Codes:")
        for status, count in results['status_codes'].most_common():
            report.append(f"  • {status}: {count} responses")
    
    # Report unique endpoints
    if results['unique_endpoints']:
        report.append(f"\n🎯 UNIQUE ENDPOINTS DISCOVERED:")
        for endpoint in results['unique_endpoints']:
            report.append(f"\n  ✓ {endpoint['path']}")
            report.append(f"    URL: {endpoint['url']}")
            report.append(f"    Status: {endpoint['status']}")
            report.append(f"    Length: {endpoint['length']} bytes")
            report.append(f"    Reason: {endpoint['reason']}")
    else:
        report.append(f"\n⚠️  No unique endpoints found - all paths return catch-all page")
        report.append(f"💡 Tip: This site likely uses client-side routing (SPA)")
        report.append(f"     Focus on API endpoints or use browser-based testing")
    
    report.append(f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    report.append(f"⚡ Fuzzing is {results['total_tested']}x faster than testing one-by-one!")
    
    return "\n".join(report)


@tool
async def targeted_fuzz(url: str, category: str) -> str:
    """Fuzz specific category of endpoints (admin, api, auth, sensitive).
    
    After using smart_fuzz_discovery, use this for targeted fuzzing.
    
    Categories:
    - 'admin': Admin panels, dashboards (/admin, /wp-admin, etc.)
    - 'api': API endpoints (/api, /graphql, /swagger, etc.)
    - 'auth': Authentication endpoints (/login, /oauth, /sso, etc.)
    - 'sensitive': Sensitive files (/.git, /.env, /backup, etc.)
    
    Args:
        url: Base URL
        category: Category to fuzz ('admin', 'api', 'auth', 'sensitive')
        
    Returns:
        Fuzzing results for that category
    """
    engine = FuzzingEngine()
    wordlists = get_default_wordlists()
    
    if category not in wordlists:
        return f"❌ Invalid category '{category}'. Use: admin, api, auth, or sensitive"
    
    results = await engine.fuzz_paths(
        url,
        wordlists[category],
        max_concurrent=10,
        timeout=10.0
    )
    
    report = []
    report.append(f"=== TARGETED FUZZING: {category.upper()} ===\n")
    report.append(f"Target: {url}")
    report.append(f"Tested: {results['total_tested']} {category} paths")
    report.append(f"Found: {results['unique_found']} unique endpoints")
    
    if results['unique_endpoints']:
        report.append(f"\n🎯 DISCOVERED {category.upper()} ENDPOINTS:")
        for endpoint in results['unique_endpoints']:
            report.append(f"\n  ✓ {endpoint['path']}")
            report.append(f"    Status: {endpoint['status']}")
            report.append(f"    Length: {endpoint['length']} bytes")
    else:
        report.append(f"\n⚠️  No unique {category} endpoints found")
    
    return "\n".join(report)


@tool
async def comprehensive_fuzz(url: str) -> str:
    """Comprehensive fuzzing across ALL categories (common, admin, api, auth, sensitive).
    
    This is the most thorough option - tests 200+ paths!
    Use when you want maximum coverage.
    
    Args:
        url: Base URL to fuzz comprehensively
        
    Returns:
        Complete fuzzing report across all categories
    """
    engine = FuzzingEngine()
    wordlists = get_default_wordlists()
    
    results = await engine.smart_fuzz(
        url,
        wordlists,
        max_concurrent=15  # Slightly more aggressive
    )
    
    report = []
    report.append(f"=== COMPREHENSIVE FUZZING: {url} ===\n")
    report.append(f"⚡ Total tested: {results['total_tested']} paths")
    report.append(f"🎯 Total unique found: {results['unique_found']} endpoints")
    
    # Report by category
    for category, cat_results in results['by_category'].items():
        report.append(f"\n📂 Category: {category.upper()}")
        report.append(f"  Tested: {cat_results['total_tested']}")
        report.append(f"  Found: {cat_results['unique_found']}")
        
        if cat_results.get('catch_all_detected'):
            report.append(f"  ⚠️  Catch-all detected: {cat_results['baseline_length']} bytes")
    
    # All unique endpoints
    if results['all_unique_endpoints']:
        report.append(f"\n🎯 ALL DISCOVERED ENDPOINTS ({len(results['all_unique_endpoints'])}):")
        for endpoint in results['all_unique_endpoints']:
            report.append(f"\n  ✓ {endpoint['path']}")
            report.append(f"    Status: {endpoint['status']}")
            report.append(f"    Length: {endpoint['length']} bytes")
    
    report.append(f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    report.append(f"✅ Comprehensive fuzzing complete!")
    report.append(f"⚡ Tested {results['total_tested']} paths in parallel")
    
    return "\n".join(report)

