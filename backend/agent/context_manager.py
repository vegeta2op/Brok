"""Advanced context management for AI agents with full context window utilization"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import json


class ContextManager:
    """Manages comprehensive context for AI agents with smart summarization"""
    
    def __init__(self, max_context_tokens: int = 100000):
        """Initialize context manager
        
        Args:
            max_context_tokens: Maximum tokens to maintain in context (default: 100k)
        """
        self.max_context_tokens = max_context_tokens
        
        # Full context storage
        self.full_tool_results = []  # Complete tool execution history
        self.discoveries = {}  # Key discoveries organized by category
        self.vulnerability_evidence = []  # Detailed vulnerability evidence
        self.endpoint_map = {}  # Discovered endpoints with metadata
        self.technology_stack = {}  # Detected technologies
        self.attack_surface = {}  # Attack surface analysis
        self.previous_attempts = {}  # Track what was already tried
        
    def add_tool_result(self, tool_name: str, args: Dict[str, Any], result: str, timestamp: str = None):
        """Add tool execution result to context
        
        Args:
            tool_name: Name of the tool executed
            args: Arguments passed to the tool
            result: Result returned by the tool
            timestamp: Execution timestamp
        """
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        tool_execution = {
            'timestamp': timestamp,
            'tool': tool_name,
            'args': args,
            'result': result,
            'result_length': len(result),
            'summary': self._summarize_tool_result(tool_name, result)
        }
        
        self.full_tool_results.append(tool_execution)
        
        # Extract structured information
        self._extract_discoveries(tool_name, result)
        self._update_attack_surface(tool_name, args, result)
        
    def _summarize_tool_result(self, tool_name: str, result: str) -> str:
        """Create concise summary of tool result
        
        Args:
            tool_name: Name of the tool
            result: Full result string
            
        Returns:
            Concise summary
        """
        # Extract key information based on tool type
        summary_parts = []
        
        if 'reconnaissance' in tool_name.lower():
            # Extract discovered endpoints
            if 'Discovered' in result and 'endpoints' in result:
                import re
                endpoints = re.findall(r'(https?://[^\s]+)', result)
                summary_parts.append(f"Found {len(endpoints)} endpoints")
            
            # Extract technology
            if 'Technology' in result:
                import re
                tech_match = re.search(r'Technology[:\s]+([^\n]+)', result)
                if tech_match:
                    summary_parts.append(f"Tech: {tech_match.group(1)[:50]}")
        
        elif 'fuzz' in tool_name.lower():
            # Extract fuzzing results
            if 'unique endpoints found' in result.lower():
                import re
                match = re.search(r'(\d+)\s+unique endpoints found', result, re.IGNORECASE)
                if match:
                    summary_parts.append(f"Found {match.group(1)} unique endpoints")
            
            if 'catch-all detected' in result.lower():
                summary_parts.append("Catch-all detected")
        
        elif 'nuclei' in tool_name.lower():
            # Extract vulnerability findings
            if 'Total Findings:' in result:
                import re
                match = re.search(r'Total Findings:\s*(\d+)', result)
                if match:
                    summary_parts.append(f"{match.group(1)} vulnerabilities")
        
        elif 'sql' in tool_name.lower() or 'xss' in tool_name.lower():
            # Check for vulnerability detection
            if 'VULNERABILITY' in result.upper() or 'POTENTIAL' in result.upper():
                summary_parts.append("⚠️ Vulnerability detected!")
            else:
                summary_parts.append("No vulnerability found")
        
        if not summary_parts:
            # Default summary - first 100 chars
            summary_parts.append(result[:100].replace('\n', ' '))
        
        return ' | '.join(summary_parts)
    
    def _extract_discoveries(self, tool_name: str, result: str):
        """Extract and categorize discoveries from tool results
        
        Args:
            tool_name: Name of the tool
            result: Tool result
        """
        import re
        
        # Extract URLs/endpoints
        if 'endpoints' not in self.discoveries:
            self.discoveries['endpoints'] = []
        
        urls = re.findall(r'(https?://[^\s\)]+)', result)
        for url in urls:
            if url not in self.discoveries['endpoints']:
                self.discoveries['endpoints'].append(url)
        
        # Extract technologies
        if 'technologies' not in self.discoveries:
            self.discoveries['technologies'] = []
        
        tech_keywords = ['WordPress', 'React', 'Vue', 'Angular', 'Django', 'Laravel', 'Spring', 'Node.js', 'PHP', 'MySQL', 'PostgreSQL', 'MongoDB']
        for tech in tech_keywords:
            if tech in result and tech not in self.discoveries['technologies']:
                self.discoveries['technologies'].append(tech)
        
        # Extract vulnerabilities
        if 'vulnerabilities' not in self.discoveries:
            self.discoveries['vulnerabilities'] = []
        
        if 'VULNERABILITY' in result.upper() or 'CVE-' in result:
            vuln_summary = result[:200]  # First 200 chars
            self.discoveries['vulnerabilities'].append({
                'tool': tool_name,
                'summary': vuln_summary,
                'timestamp': datetime.now().isoformat()
            })
    
    def _update_attack_surface(self, tool_name: str, args: Dict[str, Any], result: str):
        """Update attack surface map
        
        Args:
            tool_name: Name of the tool
            args: Tool arguments
            result: Tool result
        """
        url = args.get('url', args.get('target', ''))
        if url:
            if url not in self.attack_surface:
                self.attack_surface[url] = {
                    'tested_tools': [],
                    'findings': [],
                    'status': 'analyzed'
                }
            
            self.attack_surface[url]['tested_tools'].append(tool_name)
            
            if 'VULNERABILITY' in result.upper() or 'POTENTIAL' in result.upper():
                self.attack_surface[url]['findings'].append({
                    'tool': tool_name,
                    'summary': result[:150]
                })
    
    def get_comprehensive_context(self, include_full_results: bool = False) -> str:
        """Get comprehensive context for AI agent
        
        Args:
            include_full_results: Whether to include full tool results or just summaries
            
        Returns:
            Formatted context string
        """
        context_parts = []
        
        # 1. Executive Summary
        context_parts.append("═══════════════════════════════════════════════════════")
        context_parts.append("COMPREHENSIVE SCAN CONTEXT")
        context_parts.append("═══════════════════════════════════════════════════════\n")
        
        # 2. Key Discoveries Summary
        context_parts.append("📊 KEY DISCOVERIES:")
        context_parts.append(f"  • Endpoints: {len(self.discoveries.get('endpoints', []))}")
        context_parts.append(f"  • Technologies: {', '.join(self.discoveries.get('technologies', ['None detected']))}")
        context_parts.append(f"  • Vulnerabilities: {len(self.discoveries.get('vulnerabilities', []))}")
        context_parts.append(f"  • Attack Surface: {len(self.attack_surface)} URLs analyzed\n")
        
        # 3. Discovered Endpoints (Top 20)
        if self.discoveries.get('endpoints'):
            context_parts.append("🔗 DISCOVERED ENDPOINTS (Top 20):")
            for endpoint in self.discoveries['endpoints'][:20]:
                tested_tools = self.attack_surface.get(endpoint, {}).get('tested_tools', [])
                status = f"[Tested: {', '.join(tested_tools[:3])}]" if tested_tools else "[Not tested yet]"
                context_parts.append(f"  • {endpoint} {status}")
            if len(self.discoveries['endpoints']) > 20:
                context_parts.append(f"  ... and {len(self.discoveries['endpoints']) - 20} more")
            context_parts.append("")
        
        # 4. Technology Stack
        if self.discoveries.get('technologies'):
            context_parts.append("🔧 TECHNOLOGY STACK:")
            for tech in self.discoveries['technologies']:
                context_parts.append(f"  • {tech}")
            context_parts.append("")
        
        # 5. Vulnerabilities Found
        if self.discoveries.get('vulnerabilities'):
            context_parts.append("🚨 VULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.discoveries['vulnerabilities'][-10:], 1):
                context_parts.append(f"  {i}. [{vuln['tool']}] {vuln['summary'][:100]}")
            context_parts.append("")
        
        # 6. Tool Execution History
        context_parts.append(f"📜 TOOL EXECUTION HISTORY ({len(self.full_tool_results)} total executions):")
        
        if include_full_results:
            # Include last 10 full results
            for execution in self.full_tool_results[-10:]:
                context_parts.append(f"\n[{execution['timestamp']}] {execution['tool']}")
                context_parts.append(f"Args: {json.dumps(execution['args'], default=str)}")
                context_parts.append(f"Result ({execution['result_length']} chars):")
                context_parts.append(execution['result'][:500])  # First 500 chars
                if execution['result_length'] > 500:
                    context_parts.append(f"... [{execution['result_length'] - 500} more chars]")
        else:
            # Include summaries only
            for execution in self.full_tool_results[-20:]:
                context_parts.append(f"  • [{execution['timestamp'][-8:]}] {execution['tool']} → {execution['summary']}")
        
        context_parts.append("\n")
        
        # 7. Attack Surface Map
        if self.attack_surface:
            context_parts.append("🎯 ATTACK SURFACE MAP:")
            for url, data in list(self.attack_surface.items())[:15]:
                tools_used = ', '.join(data['tested_tools'][:3])
                findings = len(data['findings'])
                status = f"✓ {findings} findings" if findings > 0 else "Tested, no findings"
                context_parts.append(f"  • {url}")
                context_parts.append(f"    Tools: {tools_used} | Status: {status}")
            if len(self.attack_surface) > 15:
                context_parts.append(f"  ... and {len(self.attack_surface) - 15} more URLs")
            context_parts.append("")
        
        # 8. What to do next
        context_parts.append("💡 CONTEXT-AWARE RECOMMENDATIONS:")
        recommendations = self._generate_recommendations()
        for i, rec in enumerate(recommendations, 1):
            context_parts.append(f"  {i}. {rec}")
        
        context_parts.append("\n═══════════════════════════════════════════════════════")
        
        return "\n".join(context_parts)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate context-aware recommendations for next steps
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Check what's been done
        tools_used = set(e['tool'] for e in self.full_tool_results)
        endpoints_count = len(self.discoveries.get('endpoints', []))
        vulns_count = len(self.discoveries.get('vulnerabilities', []))
        
        # Recommendation logic
        if 'smart_fuzz_discovery' not in tools_used and 'comprehensive_fuzz' not in tools_used:
            recommendations.append("Run smart_fuzz_discovery for fast endpoint discovery (100+ paths in 30s)")
        
        if 'nuclei_vulnerability_scan' not in tools_used and endpoints_count > 0:
            recommendations.append("Run nuclei_vulnerability_scan for professional vulnerability testing (1000+ templates)")
        
        if self.discoveries.get('technologies'):
            tech = self.discoveries['technologies'][0]
            recommendations.append(f"Run nuclei_targeted_scan with technology='{tech.lower()}' for {tech}-specific tests")
        
        if endpoints_count > 5 and vulns_count == 0:
            recommendations.append("Test discovered endpoints with intelligent_sql_test and intelligent_xss_test")
        
        if not recommendations:
            recommendations.append("Continue systematic vulnerability testing on discovered endpoints")
        
        return recommendations
    
    def get_smart_summary_for_planner(self) -> str:
        """Get concise smart summary for planner agent
        
        Returns:
            Smart summary focusing on actionable intelligence
        """
        summary_parts = []
        
        # What we know
        summary_parts.append("🔍 CURRENT INTELLIGENCE:")
        summary_parts.append(f"  • Discovered: {len(self.discoveries.get('endpoints', []))} endpoints")
        summary_parts.append(f"  • Technologies: {', '.join(self.discoveries.get('technologies', ['Unknown']))}")
        summary_parts.append(f"  • Vulnerabilities: {len(self.discoveries.get('vulnerabilities', []))}")
        
        # What we've tested
        tools_used = set(e['tool'] for e in self.full_tool_results)
        summary_parts.append(f"\n🔧 TOOLS USED ({len(self.full_tool_results)} executions):")
        for tool in list(tools_used)[-5:]:
            count = len([e for e in self.full_tool_results if e['tool'] == tool])
            summary_parts.append(f"  • {tool} (x{count})")
        
        # What we should do next
        recommendations = self._generate_recommendations()
        if recommendations:
            summary_parts.append(f"\n💡 NEXT STEPS (AI: Choose ONE):")
            for rec in recommendations[:3]:
                summary_parts.append(f"  • {rec}")
        
        return "\n".join(summary_parts)
    
    def mark_action_attempted(self, action: str):
        """Mark an action as attempted to avoid repetition
        
        Args:
            action: Action signature (e.g., "nuclei_scan:https://example.com")
        """
        if action not in self.previous_attempts:
            self.previous_attempts[action] = {
                'count': 0,
                'first_attempt': datetime.now().isoformat()
            }
        
        self.previous_attempts[action]['count'] += 1
        self.previous_attempts[action]['last_attempt'] = datetime.now().isoformat()
    
    def was_attempted(self, action: str) -> bool:
        """Check if action was already attempted
        
        Args:
            action: Action signature
            
        Returns:
            True if action was attempted
        """
        return action in self.previous_attempts
    
    def get_attempt_count(self, action: str) -> int:
        """Get number of times action was attempted
        
        Args:
            action: Action signature
            
        Returns:
            Attempt count
        """
        return self.previous_attempts.get(action, {}).get('count', 0)

