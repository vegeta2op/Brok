"""Session and authentication management for web applications"""

from typing import Dict, Any, Optional
import json
from pathlib import Path


class SessionManager:
    """Manages authentication sessions for web applications during scans"""
    
    def __init__(self, storage_path: str = ".jimcrow_sessions.json"):
        self.storage_path = Path(storage_path)
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self._load_sessions()
    
    def _load_sessions(self) -> None:
        """Load stored sessions from file"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    self.sessions = json.load(f)
            except Exception:
                self.sessions = {}
    
    def _save_sessions(self) -> None:
        """Save sessions to file"""
        with open(self.storage_path, 'w') as f:
            json.dump(self.sessions, f, indent=2)
    
    def add_session(self, domain: str, credentials: Dict[str, str], 
                   cookies: Optional[Dict[str, str]] = None,
                   headers: Optional[Dict[str, str]] = None) -> None:
        """
        Add authentication session for a domain
        
        Args:
            domain: Target domain (e.g., "example.com")
            credentials: Login credentials {"username": "...", "password": "..."}
            cookies: Session cookies
            headers: Authentication headers (e.g., Authorization token)
        """
        self.sessions[domain] = {
            "credentials": credentials,
            "cookies": cookies or {},
            "headers": headers or {},
            "login_url": credentials.get("login_url", ""),
            "username_field": credentials.get("username_field", "username"),
            "password_field": credentials.get("password_field", "password")
        }
        self._save_sessions()
    
    def get_session(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get stored session for a domain"""
        return self.sessions.get(domain)
    
    def has_session(self, domain: str) -> bool:
        """Check if session exists for domain"""
        return domain in self.sessions
    
    def remove_session(self, domain: str) -> bool:
        """Remove session for domain"""
        if domain in self.sessions:
            del self.sessions[domain]
            self._save_sessions()
            return True
        return False
    
    def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get all stored sessions (passwords masked)"""
        masked_sessions = {}
        for domain, session in self.sessions.items():
            masked = session.copy()
            if "credentials" in masked and "password" in masked["credentials"]:
                masked["credentials"]["password"] = "********"
            masked_sessions[domain] = masked
        return masked_sessions

