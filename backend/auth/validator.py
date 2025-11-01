"""Target validation and risk assessment"""

from typing import Tuple
from urllib.parse import urlparse
from ..models import RiskLevel, PentestAction


class TargetValidator:
    """Validates targets and assesses action risk levels"""
    
    # Actions that are considered risky
    RISKY_ACTIONS = {
        "sql_injection_test",
        "command_injection_test",
        "file_upload_test",
        "authentication_bypass",
        "privilege_escalation_test",
        "dos_test",
        "brute_force"
    }
    
    # Actions that are moderately risky
    MODERATE_ACTIONS = {
        "xss_test",
        "csrf_test",
        "session_manipulation",
        "parameter_tampering",
        "directory_traversal_test",
        "ssrf_test"
    }
    
    def __init__(self):
        self.validated_urls = set()
    
    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate URL format and basic checks"""
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                return False, "URL must include a scheme (http/https)"
            
            if parsed.scheme not in ["http", "https"]:
                return False, "Only HTTP and HTTPS schemes are supported"
            
            if not parsed.netloc:
                return False, "URL must include a valid domain"
            
            # Check for localhost/internal IPs (warning, not error)
            if self._is_internal_url(parsed.netloc):
                return True, "Warning: Target appears to be internal/localhost"
            
            return True, "URL is valid"
        
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"
    
    def _is_internal_url(self, netloc: str) -> bool:
        """Check if URL points to internal/local network"""
        internal_indicators = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
            "[::1]",
            "[::]"
        ]
        
        netloc_lower = netloc.lower()
        return any(netloc_lower.startswith(indicator) for indicator in internal_indicators)
    
    def assess_action_risk(self, action: PentestAction) -> RiskLevel:
        """Assess the risk level of a pentesting action"""
        action_type = action.action_type.lower()
        
        # Check if action is in risky category
        if any(risky in action_type for risky in self.RISKY_ACTIONS):
            return RiskLevel.RISKY
        
        # Check if action is in moderate category
        if any(moderate in action_type for moderate in self.MODERATE_ACTIONS):
            return RiskLevel.MODERATE
        
        # Check for specific risky parameters
        if action.parameters:
            if "payload" in action.parameters and len(action.parameters["payload"]) > 1000:
                return RiskLevel.RISKY
            
            if "file_content" in action.parameters:
                return RiskLevel.RISKY
            
            if action.parameters.get("attempts", 0) > 10:
                return RiskLevel.RISKY
        
        return RiskLevel.SAFE
    
    def requires_approval(self, action: PentestAction) -> bool:
        """Determine if an action requires user approval"""
        risk = self.assess_action_risk(action)
        
        # Always require approval for risky actions
        if risk == RiskLevel.RISKY:
            return True
        
        # Moderate actions require approval by default
        if risk == RiskLevel.MODERATE:
            return action.requires_approval
        
        # Safe actions don't need approval
        return False
    
    def validate_scope(self, url: str, base_url: str, scope_patterns: list = None) -> bool:
        """Validate that URL is within the allowed scope"""
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_url)
        
        # Must be same domain or subdomain
        if not (parsed_url.netloc == parsed_base.netloc or 
                parsed_url.netloc.endswith(f".{parsed_base.netloc}")):
            return False
        
        # Check custom scope patterns if provided
        if scope_patterns:
            import re
            for pattern in scope_patterns:
                regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
                if re.match(f"^{regex_pattern}$", url):
                    return True
            return False
        
        return True

