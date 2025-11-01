"""Authorization management for scan targets"""

import yaml
import json
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse
import re


class AuthorizationManager:
    """Manages authorized targets and scope validation"""
    
    def __init__(self, config_path: str = "config/authorized_targets.yaml"):
        self.config_path = Path(config_path)
        self.authorized_targets: List[Dict[str, Any]] = []
        self.whitelist: List[str] = []
        self._load_config()
    
    def _load_config(self) -> None:
        """Load authorized targets from configuration file"""
        if not self.config_path.exists():
            # Create default config
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            default_config = {
                "authorized_targets": [],
                "global_whitelist": []
            }
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f)
            return
        
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f) or {}
            self.authorized_targets = config.get("authorized_targets", [])
            self.whitelist = config.get("global_whitelist", [])
    
    def _save_config(self) -> None:
        """Save authorized targets to configuration file"""
        config = {
            "authorized_targets": self.authorized_targets,
            "global_whitelist": self.whitelist
        }
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f)
    
    def add_authorized_target(self, domain: str, scope_patterns: List[str] = None,
                            excluded_patterns: List[str] = None,
                            notes: str = "") -> bool:
        """Add a new authorized target"""
        # Reload config first to get latest state
        self._load_config()
        
        # Check if already exists
        for target in self.authorized_targets:
            if target["domain"] == domain:
                # Already exists, but still return True to indicate it's authorized
                return True
        
        self.authorized_targets.append({
            "domain": domain,
            "scope_patterns": scope_patterns or [f"*{domain}*"],
            "excluded_patterns": excluded_patterns or [],
            "notes": notes,
            "added_at": str(Path.cwd())  # Placeholder for timestamp
        })
        self._save_config()
        
        # Reload to verify
        self._load_config()
        return True
    
    def remove_authorized_target(self, domain: str) -> bool:
        """Remove an authorized target"""
        original_length = len(self.authorized_targets)
        self.authorized_targets = [
            t for t in self.authorized_targets if t["domain"] != domain
        ]
        if len(self.authorized_targets) < original_length:
            self._save_config()
            return True
        return False
    
    def is_authorized(self, url: str) -> bool:
        """Check if a URL is authorized for scanning"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Check global whitelist
        for pattern in self.whitelist:
            if self._match_pattern(domain, pattern):
                return True
        
        # Check authorized targets
        for target in self.authorized_targets:
            target_domain = target["domain"]
            if domain == target_domain or domain.endswith(f".{target_domain}"):
                return True
        
        return False
    
    def is_in_scope(self, url: str, target_domain: str) -> bool:
        """Check if URL is within the scope of a target"""
        parsed = urlparse(url)
        url_domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Find target config
        target_config = None
        for target in self.authorized_targets:
            if target["domain"] == target_domain:
                target_config = target
                break
        
        if not target_config:
            return False
        
        # Check excluded patterns first
        for pattern in target_config.get("excluded_patterns", []):
            if self._match_pattern(url, pattern):
                return False
        
        # Check scope patterns
        for pattern in target_config.get("scope_patterns", []):
            if self._match_pattern(url, pattern):
                return True
        
        # Default: same domain or subdomain
        return url_domain == target_domain or url_domain.endswith(f".{target_domain}")
    
    def _match_pattern(self, text: str, pattern: str) -> bool:
        """Match text against a pattern (supports wildcards)"""
        # Convert wildcard pattern to regex
        regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
        return bool(re.match(f"^{regex_pattern}$", text))
    
    def get_authorized_targets(self) -> List[Dict[str, Any]]:
        """Get list of all authorized targets"""
        return self.authorized_targets.copy()
    
    def add_to_whitelist(self, pattern: str) -> None:
        """Add a pattern to the global whitelist"""
        if pattern not in self.whitelist:
            self.whitelist.append(pattern)
            self._save_config()
    
    def remove_from_whitelist(self, pattern: str) -> bool:
        """Remove a pattern from the global whitelist"""
        if pattern in self.whitelist:
            self.whitelist.remove(pattern)
            self._save_config()
            return True
        return False

