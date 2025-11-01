"""LangChain tools for Nuclei integration"""

from langchain.tools import tool
from .nuclei_integration import (
    NucleiIntegration,
    generate_sqli_template,
    generate_xss_template,
    generate_path_traversal_template,
    generate_api_exposure_template
)
import json


# Global nuclei instance
_nuclei = None

def get_nuclei() -> NucleiIntegration:
    """Get or create Nuclei integration instance"""
    global _nuclei
    if _nuclei is None:
        _nuclei = NucleiIntegration()
    return _nuclei


@tool
async def nuclei_vulnerability_scan(url: str, severity: str = "high,critical") -> str:
    """Run Nuclei vulnerability scanner with 1000+ templates.
    
    Nuclei is a professional-grade scanner that tests for:
    - Known CVEs
    - Misconfigurations
    - Exposed panels
    - Default credentials
    - Technology-specific vulnerabilities
    
    This is MUCH more thorough than manual testing!
    
    Args:
        url: Target URL to scan
        severity: Comma-separated severity levels (critical, high, medium, low, info)
                 Default: "high,critical" for important findings only
        
    Returns:
        Scan results with discovered vulnerabilities
    """
    nuclei = get_nuclei()
    
    if not nuclei.is_installed():
        return nuclei.get_installation_instructions()
    
    # Parse severity
    severity_list = [s.strip() for s in severity.split(',')]
    
    # Run scan
    results = await nuclei.run_scan(
        target=url,
        severity=severity_list
    )
    
    if 'error' in results:
        return f"❌ Error: {results['message']}"
    
    # Format results (ensure executor can pick these up as vulnerabilities)
    report = []
    report.append(f"=== NUCLEI VULNERABILITY SCAN: {url} ===\n")
    report.append(f"Severity Filter: {severity}")
    report.append(f"Total Findings: {results['total_findings']}\n")
    
    if results['findings']:
        report.append("🚨 VULNERABILITIES DISCOVERED:\n")
        
        for finding in results['findings']:
            info = finding.get('info', {})
            severity_val = info.get('severity', 'unknown').upper()
            name_val = info.get('name', 'Unknown')
            matched_at = finding.get('matched-at', 'N/A')
            template_id = finding.get('template-id', 'N/A')
            
            # Mark so executor treats it as a vulnerability
            report.append(f"⚠️ POTENTIAL VULNERABILITY: [{severity_val}] {name_val}")
            report.append(f"  ID: {template_id}")
            report.append(f"  Matched: {matched_at}")
            description = info.get('description')
            if description:
                report.append(f"  Description: {description}")
            if finding.get('extracted-results'):
                report.append(f"  Evidence: {', '.join(finding['extracted-results'][:3])}")
            report.append("")
        
        report.append(f"💡 AI Recommendation: Investigate these findings and verify exploitability")
    else:
        report.append("✅ No high/critical vulnerabilities found with standard templates")
        report.append("💡 Consider using targeted scans or custom templates")
    
    # Include raw command for TUI raw command panel
    if results.get('command'):
        report.append(f"\nCOMMAND: {results['command']}")
    
    return "\n".join(report)


@tool
async def nuclei_targeted_scan(url: str, technology: str) -> str:
    """Run targeted Nuclei scan based on detected technology.
    
    Use this after identifying the technology stack to run specific tests.
    
    Supported technologies:
    - wordpress: WordPress CMS
    - joomla: Joomla CMS
    - drupal: Drupal CMS
    - laravel: Laravel framework
    - django: Django framework
    - spring: Spring Boot
    - api: API endpoints
    - graphql: GraphQL APIs
    
    Args:
        url: Target URL
        technology: Technology stack detected (e.g., 'wordpress', 'api', 'django')
        
    Returns:
        Technology-specific scan results
    """
    nuclei = get_nuclei()
    
    if not nuclei.is_installed():
        return nuclei.get_installation_instructions()
    
    tech_lower = technology.lower()
    
    # Map technology to template path (where available)
    tech_map_templates = {
        'wordpress': 'wordpress/',
        'joomla': 'joomla/',
        'drupal': 'drupal/',
        'laravel': 'laravel/',
        'django': 'django/',
        'spring': 'springboot/',
        'api': 'api/',
        'graphql': 'graphql/'
    }
    
    # Map SPA/frontend/backend frameworks to generic tags
    tech_map_tags = {
        'react': ['cves', 'exposures', 'misconfiguration'],
        'angular': ['cves', 'exposures', 'misconfiguration'],
        'vue': ['cves', 'exposures', 'misconfiguration'],
        'next': ['cves', 'exposures', 'misconfiguration'],
        'nuxt': ['cves', 'exposures', 'misconfiguration'],
        'svelte': ['cves', 'exposures', 'misconfiguration'],
        'node': ['node', 'express', 'cves', 'misconfiguration'],
        'express': ['express', 'node', 'cves', 'misconfiguration'],
        'rails': ['rails', 'ruby', 'cves', 'exposures'],
        'php': ['php', 'cves', 'exposures']
    }
    
    results = None
    used_descriptor = None
    
    if tech_lower in tech_map_templates:
        template_path = tech_map_templates[tech_lower]
        used_descriptor = f"Templates: {template_path}"
        results = await nuclei.run_scan(
            target=url,
            templates=[template_path]
        )
    else:
        # Fallback to tags for SPA/general frameworks
        tags = tech_map_tags.get(tech_lower, ['cves', 'exposures', 'misconfiguration'])
        used_descriptor = f"Tags: {', '.join(tags)}"
        results = await nuclei.run_scan(
            target=url,
            tags=tags
        )
    
    if 'error' in results:
        return f"❌ Error: {results['message']}"
    
    # Format results
    report = []
    report.append(f"=== TARGETED SCAN: {technology.upper()} ===\n")
    report.append(f"Target: {url}")
    report.append(used_descriptor)
    report.append(f"Findings: {results['total_findings']}\n")
    
    if results['findings']:
        report.append(f"🎯 RELEVANT VULNERABILITIES:\n")
        
        for finding in results['findings']:
            info = finding.get('info', {})
            sev = info.get('severity', '?').upper()
            name = info.get('name')
            matched = finding.get('matched-at', '')
            report.append(f"⚠️ POTENTIAL VULNERABILITY: [{sev}] {name}")
            if matched:
                report.append(f"  Matched: {matched}")
        
    else:
        report.append(f"✅ No relevant vulnerabilities found for {technology}")
    
    # Include raw command for TUI raw command panel
    if results.get('command'):
        report.append(f"\nCOMMAND: {results['command']}")
    
    return "\n".join(report)


@tool
async def nuclei_custom_template_scan(url: str, vuln_type: str, parameter: str = "") -> str:
    """Create and run AI-generated custom Nuclei template.
    
    The AI creates a custom template based on the vulnerability type and parameter.
    Use this when you want to test for specific issues not covered by standard templates.
    
    Vulnerability types:
    - sqli: SQL Injection
    - xss: Cross-Site Scripting
    - traversal: Path Traversal
    - api_exposure: API Documentation Exposure
    
    Args:
        url: Target URL
        vuln_type: Type of vulnerability to test (sqli, xss, traversal, api_exposure)
        parameter: Parameter to test (optional, for sqli/xss)
        
    Returns:
        Custom template scan results
    """
    nuclei = get_nuclei()
    
    if not nuclei.is_installed():
        return nuclei.get_installation_instructions()
    
    # Generate appropriate template
    if vuln_type == 'sqli':
        http_config = generate_sqli_template(url, parameter)
        template_name = f"AI-Generated SQL Injection Test"
        template_desc = f"Tests {parameter} parameter for SQL injection"
    elif vuln_type == 'xss':
        http_config = generate_xss_template(url, parameter)
        template_name = f"AI-Generated XSS Test"
        template_desc = f"Tests {parameter} parameter for XSS"
    elif vuln_type == 'traversal':
        http_config = generate_path_traversal_template(url)
        template_name = f"AI-Generated Path Traversal Test"
        template_desc = f"Tests for path traversal vulnerabilities"
    elif vuln_type == 'api_exposure':
        http_config = generate_api_exposure_template(url)
        template_name = f"AI-Generated API Exposure Check"
        template_desc = f"Checks for exposed API documentation"
    else:
        return f"❌ Unknown vulnerability type: {vuln_type}\nSupported: sqli, xss, traversal, api_exposure"
    
    # Create custom template
    template_id = f"jimcrow-ai-{vuln_type}-{hash(url + parameter) % 10000}"
    template_path = nuclei.create_custom_template(
        template_id=template_id,
        name=template_name,
        description=template_desc,
        severity='high',
        http_config=http_config
    )
    
    # Run custom template
    results = await nuclei.run_scan(
        target=url,
        custom_template_path=template_path
    )
    
    if 'error' in results:
        return f"❌ Error: {results['message']}"
    
    # Format results
    report = []
    report.append(f"=== AI-GENERATED CUSTOM TEMPLATE SCAN ===\n")
    report.append(f"Template: {template_name}")
    report.append(f"Type: {vuln_type}")
    report.append(f"Target: {url}")
    if parameter:
        report.append(f"Parameter: {parameter}")
    report.append(f"Template Path: {template_path}\n")
    
    if results['findings']:
        report.append(f"⚠️ POTENTIAL VULNERABILITY DETECTED!\n")
        
        for finding in results['findings']:
            info = finding.get('info', {})
            report.append(f"  Severity: {info.get('severity', 'high').upper()}")
            report.append(f"  Matched At: {finding.get('matched-at', 'N/A')}")
            
            if finding.get('extracted-results'):
                report.append(f"  Evidence: {finding['extracted-results']}")
        
        report.append(f"\n🔍 AI Analysis: This finding requires manual verification")
    else:
        report.append(f"✅ No vulnerability detected with custom template")
        report.append(f"💡 The AI-generated template did not find issues")
    
    return "\n".join(report)


@tool
def check_nuclei_installation() -> str:
    """Check if Nuclei is installed and show installation instructions if not.
    
    Use this first before running any Nuclei scans.
    
    Returns:
        Installation status and instructions if needed
    """
    nuclei = get_nuclei()
    
    if nuclei.is_installed():
        # Get template info
        template_info = nuclei.list_available_templates()
        
        report = []
        report.append("✅ Nuclei is installed!\n")
        report.append(f"Binary: {nuclei.nuclei_path}")
        
        if 'error' not in template_info:
            report.append(f"Templates Dir: {template_info['templates_dir']}")
            report.append(f"Total Templates: {template_info['total_templates']}")
            report.append(f"Categories: {template_info['total_categories']}\n")
            
            report.append("Top Categories:")
            for category, count in sorted(
                template_info['categories'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]:
                report.append(f"  • {category}: {count} templates")
        else:
            report.append(f"\n⚠️ {template_info['message']}")
        
        report.append(f"\n💡 Ready to scan! Use nuclei_vulnerability_scan(url)")
        
        return "\n".join(report)
    else:
        return nuclei.get_installation_instructions()

