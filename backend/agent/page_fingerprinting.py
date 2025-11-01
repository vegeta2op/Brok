"""Page fingerprinting to detect catch-all/404 pages that return 200 OK"""

import hashlib
from typing import Dict, Optional, Set
from bs4 import BeautifulSoup


class PageFingerprinter:
    """Detects when different URLs return the same catch-all page (SPA pattern)"""
    
    def __init__(self):
        # Store fingerprints of known pages
        self.fingerprints: Dict[str, str] = {}  # domain -> homepage fingerprint
        self.catchall_fingerprints: Set[str] = set()  # Known catch-all page fingerprints
        
    def fingerprint_content(self, html: str) -> str:
        """Create a fingerprint of page content.
        
        Focuses on:
        - Title
        - Main structural elements
        - Key text content
        - Ignores dynamic content like timestamps, session IDs
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remove dynamic elements that change between requests
            for tag in soup.find_all(['script', 'style', 'noscript']):
                tag.decompose()
            
            # Extract stable content
            parts = []
            
            # Title
            title = soup.find('title')
            if title:
                parts.append(f"TITLE:{title.get_text(strip=True)}")
            
            # Meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc and meta_desc.get('content'):
                parts.append(f"DESC:{meta_desc['content'][:100]}")
            
            # Main structural elements (h1, h2, nav)
            for tag in ['h1', 'h2', 'nav']:
                elements = soup.find_all(tag)
                for elem in elements[:3]:  # First 3 of each
                    text = elem.get_text(strip=True)[:50]
                    if text:
                        parts.append(f"{tag.upper()}:{text}")
            
            # Body text (first 500 chars of visible text)
            body_text = soup.get_text(separator=' ', strip=True)
            # Remove extra whitespace
            body_text = ' '.join(body_text.split())
            parts.append(f"BODY:{body_text[:500]}")
            
            # Create hash
            content = '|'.join(parts)
            return hashlib.md5(content.encode()).hexdigest()
            
        except Exception:
            # Fallback to simple hash if parsing fails
            return hashlib.md5(html.encode()).hexdigest()
    
    def learn_homepage(self, domain: str, html: str) -> str:
        """Learn the fingerprint of the homepage.
        
        Args:
            domain: Domain name (e.g., "ciatech.net")
            html: Homepage HTML content
            
        Returns:
            Fingerprint hash
        """
        fingerprint = self.fingerprint_content(html)
        self.fingerprints[domain] = fingerprint
        return fingerprint
    
    def is_same_as_homepage(self, domain: str, html: str) -> bool:
        """Check if this page is the same as the homepage (catch-all).
        
        Args:
            domain: Domain name
            html: Page HTML content
            
        Returns:
            True if this is likely a catch-all page showing homepage
        """
        if domain not in self.fingerprints:
            return False
        
        page_fingerprint = self.fingerprint_content(html)
        homepage_fingerprint = self.fingerprints[domain]
        
        # If fingerprints match, it's the same page
        is_catchall = page_fingerprint == homepage_fingerprint
        
        if is_catchall:
            self.catchall_fingerprints.add(page_fingerprint)
        
        return is_catchall
    
    def is_known_catchall(self, html: str) -> bool:
        """Check if this page matches any known catch-all page.
        
        Args:
            html: Page HTML content
            
        Returns:
            True if this matches a known catch-all page
        """
        fingerprint = self.fingerprint_content(html)
        return fingerprint in self.catchall_fingerprints
    
    def similarity_score(self, html1: str, html2: str) -> float:
        """Calculate similarity between two pages (0.0 to 1.0).
        
        Args:
            html1: First page HTML
            html2: Second page HTML
            
        Returns:
            Similarity score (1.0 = identical, 0.0 = completely different)
        """
        fp1 = self.fingerprint_content(html1)
        fp2 = self.fingerprint_content(html2)
        
        # Simple binary comparison for now
        # Could be enhanced with fuzzy matching
        return 1.0 if fp1 == fp2 else 0.0
    
    def analyze_response(self, domain: str, url: str, html: str, status_code: int) -> Dict[str, any]:
        """Analyze a response and determine if it's a real page or catch-all.
        
        Args:
            domain: Domain name
            url: Full URL requested
            html: Response HTML
            status_code: HTTP status code
            
        Returns:
            Analysis dict with:
            - is_real_page: bool
            - is_catchall: bool
            - reason: str
            - fingerprint: str
        """
        fingerprint = self.fingerprint_content(html)
        
        # Check if this is the same as homepage
        is_same_as_home = self.is_same_as_homepage(domain, html)
        
        # Check if this is a known catch-all
        is_known_catchall = fingerprint in self.catchall_fingerprints
        
        # Analysis
        is_catchall = is_same_as_home or is_known_catchall
        is_real_page = not is_catchall
        
        # Reason
        if is_same_as_home:
            reason = "Same content as homepage - likely catch-all/SPA router"
        elif is_known_catchall:
            reason = "Matches known catch-all page pattern"
        else:
            reason = "Appears to be unique content"
        
        return {
            'is_real_page': is_real_page,
            'is_catchall': is_catchall,
            'reason': reason,
            'fingerprint': fingerprint,
            'status_code': status_code
        }


# Global instance for the scanning session
_fingerprinter: Optional[PageFingerprinter] = None


def get_fingerprinter() -> PageFingerprinter:
    """Get or create global fingerprinter instance."""
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = PageFingerprinter()
    return _fingerprinter


def reset_fingerprinter():
    """Reset fingerprinter for new scan."""
    global _fingerprinter
    _fingerprinter = PageFingerprinter()

