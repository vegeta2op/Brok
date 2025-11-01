"""Nuclei integration with AI-driven template selection and creation"""

import subprocess
import shutil
import os
import json
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path
import yaml


class NucleiIntegration:
    """Integration with Nuclei vulnerability scanner"""
    
    def __init__(self):
        self.nuclei_path = self._find_nuclei()
        self.templates_dir = self._get_templates_dir()
        self.custom_templates_dir = Path.home() / ".jimcrow" / "nuclei-templates"
        self.custom_templates_dir.mkdir(parents=True, exist_ok=True)
        
    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary in PATH"""
        return shutil.which("nuclei")
    
    def is_installed(self) -> bool:
        """Check if nuclei is installed"""
        return self.nuclei_path is not None
    
    def _get_templates_dir(self) -> Optional[Path]:
        """Get nuclei templates directory"""
        if not self.nuclei_path:
            return None
        
        # Try common locations
        possible_dirs = [
            Path.home() / "nuclei-templates",
            Path("/usr/local/share/nuclei-templates"),
            Path("/opt/nuclei-templates")
        ]
        
        for dir_path in possible_dirs:
            if dir_path.exists():
                return dir_path
        
        return None
    
    def get_installation_instructions(self) -> str:
        """Get instructions to install nuclei"""
        return """
╔══════════════════════════════════════════════════════════════════╗
║                 Nuclei Installation Required                      ║
╚══════════════════════════════════════════════════════════════════╝

Nuclei is a fast vulnerability scanner with 1000+ templates.

INSTALLATION:

macOS (via Homebrew):
  brew install nuclei
  nuclei -update-templates

Linux:
  # Download from GitHub releases
  wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.2.0_linux_amd64.zip
  unzip nuclei_3.2.0_linux_amd64.zip
  sudo mv nuclei /usr/local/bin/
  nuclei -update-templates

Or via Go:
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  nuclei -update-templates

Docker:
  docker pull projectdiscovery/nuclei:latest
  docker run projectdiscovery/nuclei -u https://example.com

After installation, run: jimcrow scan <target> --use-nuclei

Documentation: https://docs.projectdiscovery.io/tools/nuclei/overview
"""
    
    async def run_scan(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_template_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run nuclei scan
        
        Args:
            target: Target URL
            templates: Specific templates to use
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (xss, sqli, rce, etc.)
            custom_template_path: Path to custom template
            
        Returns:
            Scan results
        """
        if not self.is_installed():
            return {
                'error': 'nuclei_not_installed',
                'message': self.get_installation_instructions()
            }
        
        # Build command
        cmd = [self.nuclei_path, '-u', target, '-json', '-silent']
        
        # Add template filters
        if custom_template_path:
            cmd.extend(['-t', custom_template_path])
        elif templates:
            for template in templates:
                cmd.extend(['-t', template])
        
        # Add severity filter
        if severity:
            cmd.extend(['-s', ','.join(severity)])
        
        # Add tags filter
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        try:
            # Run nuclei
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse JSON output
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            return {
                'success': True,
                'findings': findings,
                'total_findings': len(findings),
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {
                'error': 'timeout',
                'message': 'Nuclei scan timed out after 5 minutes'
            }
        except Exception as e:
            return {
                'error': 'execution_failed',
                'message': str(e)
            }
    
    def create_custom_template(
        self,
        template_id: str,
        name: str,
        description: str,
        severity: str,
        http_config: Dict[str, Any]
    ) -> str:
        """Create a custom nuclei template
        
        Args:
            template_id: Unique template ID
            name: Template name
            description: Template description
            severity: Severity level (critical, high, medium, low, info)
            http_config: HTTP request configuration
            
        Returns:
            Path to created template
        """
        template = {
            'id': template_id,
            'info': {
                'name': name,
                'author': 'jimcrow-ai',
                'severity': severity,
                'description': description,
                'tags': ['custom', 'ai-generated']
            },
            'http': [http_config]
        }
        
        # Save template
        template_path = self.custom_templates_dir / f"{template_id}.yaml"
        with open(template_path, 'w') as f:
            yaml.dump(template, f, default_flow_style=False)
        
        return str(template_path)
    
    def get_suggested_templates(self, context: str) -> List[str]:
        """Suggest nuclei templates based on context
        
        Args:
            context: Context about the target (tech stack, findings, etc.)
            
        Returns:
            List of suggested template paths/tags
        """
        suggestions = []
        context_lower = context.lower()
        
        # Technology-specific templates
        if 'wordpress' in context_lower or 'wp-' in context_lower:
            suggestions.append('wordpress/')
        
        if 'joomla' in context_lower:
            suggestions.append('joomla/')
        
        if 'drupal' in context_lower:
            suggestions.append('drupal/')
        
        if 'laravel' in context_lower:
            suggestions.append('laravel/')
        
        if 'django' in context_lower:
            suggestions.append('django/')
        
        if 'spring' in context_lower or 'java' in context_lower:
            suggestions.append('springboot/')
        
        # Vulnerability-specific
        if 'api' in context_lower or 'graphql' in context_lower:
            suggestions.extend(['graphql/', 'api/'])
        
        if 'admin' in context_lower or 'login' in context_lower:
            suggestions.extend(['default-logins/', 'exposed-panels/'])
        
        if 'upload' in context_lower:
            suggestions.append('file-upload/')
        
        # Always include common checks
        suggestions.extend([
            'cves/',  # Known CVEs
            'exposures/',  # Exposure checks
            'misconfiguration/',  # Misconfigurations
            'takeovers/',  # Subdomain takeovers
        ])
        
        return suggestions
    
    def list_available_templates(self) -> Dict[str, Any]:
        """List available nuclei templates"""
        if not self.templates_dir or not self.templates_dir.exists():
            return {
                'error': 'templates_not_found',
                'message': 'Nuclei templates directory not found. Run: nuclei -update-templates'
            }
        
        categories = {}
        
        # Scan templates directory
        for category_dir in self.templates_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith('.'):
                template_count = len(list(category_dir.glob('*.yaml')))
                categories[category_dir.name] = template_count
        
        return {
            'templates_dir': str(self.templates_dir),
            'categories': categories,
            'total_categories': len(categories),
            'total_templates': sum(categories.values())
        }


# Template generation helpers
def generate_sqli_template(url: str, parameter: str) -> Dict[str, Any]:
    """Generate SQL injection test template"""
    return {
        'method': 'GET',
        'path': [url],
        'matchers-condition': 'or',
        'matchers': [
            {
                'type': 'word',
                'words': ['SQL syntax', 'mysql_fetch', 'SQLite3::', 'Warning: mysql']
            },
            {
                'type': 'regex',
                'regex': ['SQL.*error', 'ODBC.*error']
            }
        ]
    }


def generate_xss_template(url: str, parameter: str) -> Dict[str, Any]:
    """Generate XSS test template"""
    return {
        'method': 'GET',
        'path': [f"{url}?{parameter}={{{{xss_payload}}}}"],
        'payloads': {
            'xss_payload': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
            ]
        },
        'matchers': [
            {
                'type': 'word',
                'part': 'body',
                'words': ['{{xss_payload}}']
            }
        ]
    }


def generate_path_traversal_template(url: str) -> Dict[str, Any]:
    """Generate path traversal test template"""
    return {
        'method': 'GET',
        'path': [
            f"{url}/../../../etc/passwd",
            f"{url}/..%2f..%2f..%2fetc%2fpasswd",
            f"{url}/....//....//....//etc/passwd"
        ],
        'matchers': [
            {
                'type': 'regex',
                'regex': ['root:[x*]:0:0:']
            }
        ]
    }


def generate_api_exposure_template(url: str) -> Dict[str, Any]:
    """Generate API exposure check template"""
    return {
        'method': 'GET',
        'path': [
            f"{url}/swagger.json",
            f"{url}/api-docs",
            f"{url}/openapi.json",
            f"{url}/graphql"
        ],
        'matchers': [
            {
                'type': 'word',
                'words': ['swagger', 'openapi', 'graphql', 'api']
            },
            {
                'type': 'status',
                'status': [200]
            }
        ]
    }

