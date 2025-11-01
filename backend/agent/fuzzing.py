"""Smart fuzzing engine with content-length analysis"""

import asyncio
import httpx
from typing import List, Dict, Set, Any, Optional
from urllib.parse import urljoin, urlparse
from collections import Counter
from .page_fingerprinting import get_fingerprinter


class FuzzingEngine:
    """Intelligent fuzzing engine that uses content-length comparison to find real endpoints"""
    
    def __init__(self, baseline_lengths: Optional[Set[int]] = None):
        self.baseline_lengths = baseline_lengths or set()  # Known catch-all lengths
        self.response_clusters: Dict[int, List[str]] = {}  # Group by length
        self.unique_responses: List[Dict[str, Any]] = []
        
    async def fuzz_paths(
        self,
        base_url: str,
        wordlist: List[str],
        max_concurrent: int = 10,
        timeout: float = 10.0
    ) -> Dict[str, Any]:
        """Fuzz multiple paths concurrently and identify unique responses
        
        Args:
            base_url: Base URL to fuzz (e.g., https://example.com)
            wordlist: List of paths to try (e.g., ['/admin', '/api', '/login'])
            max_concurrent: Max concurrent requests
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with discovered endpoints and statistics
        """
        results = {
            'total_tested': 0,
            'unique_found': 0,
            'catch_all_detected': False,
            'baseline_length': None,
            'unique_endpoints': [],
            'length_clusters': {},
            'status_codes': Counter()
        }
        
        # Semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fuzz_single_path(path: str) -> Optional[Dict[str, Any]]:
            """Fuzz a single path and return result"""
            async with semaphore:
                try:
                    url = urljoin(base_url, path)
                    
                    async with httpx.AsyncClient(
                        timeout=timeout,
                        follow_redirects=False,
                        verify=False
                    ) as client:
                        response = await client.get(url)
                        
                        content_length = len(response.text)
                        
                        return {
                            'path': path,
                            'url': url,
                            'status': response.status_code,
                            'length': content_length,
                            'headers': dict(response.headers),
                            'content': response.text,
                            'redirect': response.headers.get('Location')
                        }
                        
                except Exception as e:
                    return {
                        'path': path,
                        'url': urljoin(base_url, path),
                        'status': 0,
                        'length': 0,
                        'error': str(e)
                    }
        
        # Fuzz all paths concurrently
        tasks = [fuzz_single_path(path) for path in wordlist]
        responses = await asyncio.gather(*tasks)
        
        # Filter out errors
        valid_responses = [r for r in responses if r and r['status'] > 0]
        results['total_tested'] = len(valid_responses)
        
        # Group by content length
        length_groups: Dict[int, List[Dict[str, Any]]] = {}
        for resp in valid_responses:
            length = resp['length']
            if length not in length_groups:
                length_groups[length] = []
            length_groups[length].append(resp)
            
            # Track status codes
            results['status_codes'][resp['status']] += 1
        
        # Find the most common length (likely catch-all)
        if length_groups:
            length_counts = {length: len(resps) for length, resps in length_groups.items()}
            most_common_length = max(length_counts, key=length_counts.get)
            most_common_count = length_counts[most_common_length]
            
            # If >70% of responses have the same length, it's likely catch-all
            if most_common_count > len(valid_responses) * 0.7:
                results['catch_all_detected'] = True
                results['baseline_length'] = most_common_length
                self.baseline_lengths.add(most_common_length)
            
            results['length_clusters'] = {
                str(length): len(resps) for length, resps in length_groups.items()
            }
        
        # Find unique responses (different lengths)
        for length, responses_list in length_groups.items():
            # Skip catch-all length
            if length == results.get('baseline_length'):
                continue
            
            # If only 1-3 responses have this length, they're likely unique
            if len(responses_list) <= 3:
                for resp in responses_list:
                    # Additional verification with fingerprinting
                    fingerprinter = get_fingerprinter()
                    domain = urlparse(base_url).netloc
                    
                    page_analysis = fingerprinter.analyze_response(
                        domain, resp['url'], resp['content'], resp['status']
                    )
                    
                    if page_analysis['is_real_page']:
                        results['unique_endpoints'].append({
                            'path': resp['path'],
                            'url': resp['url'],
                            'status': resp['status'],
                            'length': resp['length'],
                            'reason': f"Unique length ({length} bytes), verified real page"
                        })
        
        results['unique_found'] = len(results['unique_endpoints'])
        
        return results
    
    async def smart_fuzz(
        self,
        base_url: str,
        wordlists: Dict[str, List[str]],
        max_concurrent: int = 10
    ) -> Dict[str, Any]:
        """Smart fuzzing that adapts based on results
        
        Args:
            base_url: Base URL to fuzz
            wordlists: Dictionary of wordlists by category
                      e.g., {'common': [...], 'admin': [...], 'api': [...]}
            max_concurrent: Max concurrent requests
            
        Returns:
            Comprehensive fuzzing results
        """
        all_results = {
            'base_url': base_url,
            'total_tested': 0,
            'unique_found': 0,
            'by_category': {},
            'all_unique_endpoints': []
        }
        
        # Start with common paths
        if 'common' in wordlists:
            common_results = await self.fuzz_paths(
                base_url,
                wordlists['common'],
                max_concurrent
            )
            
            all_results['by_category']['common'] = common_results
            all_results['total_tested'] += common_results['total_tested']
            all_results['unique_found'] += common_results['unique_found']
            all_results['all_unique_endpoints'].extend(common_results['unique_endpoints'])
        
        # If we found unique endpoints, fuzz more specific wordlists
        if all_results['unique_found'] > 0:
            # Fuzz admin paths if we found any admin-related endpoints
            if 'admin' in wordlists:
                admin_results = await self.fuzz_paths(
                    base_url,
                    wordlists['admin'],
                    max_concurrent
                )
                all_results['by_category']['admin'] = admin_results
                all_results['total_tested'] += admin_results['total_tested']
                all_results['unique_found'] += admin_results['unique_found']
                all_results['all_unique_endpoints'].extend(admin_results['unique_endpoints'])
            
            # Fuzz API paths
            if 'api' in wordlists:
                api_results = await self.fuzz_paths(
                    base_url,
                    wordlists['api'],
                    max_concurrent
                )
                all_results['by_category']['api'] = api_results
                all_results['total_tested'] += api_results['total_tested']
                all_results['unique_found'] += api_results['unique_found']
                all_results['all_unique_endpoints'].extend(api_results['unique_endpoints'])
        
        return all_results


# Common wordlists for fuzzing
COMMON_PATHS = [
    '/admin', '/login', '/api', '/graphql', '/swagger',
    '/admin/', '/administrator', '/wp-admin', '/phpmyadmin',
    '/signin', '/signup', '/register', '/auth',
    '/dashboard', '/profile', '/account', '/settings',
    '/api/v1', '/api/v2', '/rest', '/rest/api',
    '/debug', '/test', '/dev', '/.git/config', '/.env',
    '/backup', '/backups', '/config', '/docs',
    '/upload', '/uploads', '/files', '/download',
    '/search', '/users', '/user', '/robots.txt', '/sitemap.xml'
]

ADMIN_PATHS = [
    '/admin', '/admin/', '/admin/login', '/admin/index',
    '/administrator', '/administrator/', '/wp-admin', '/wp-admin/',
    '/admin/dashboard', '/admin/settings', '/admin/users',
    '/panel', '/cpanel', '/control', '/manager',
    '/admin.php', '/admin.html', '/admincp', '/admins',
    '/sysadmin', '/system', '/backend', '/manage'
]

API_PATHS = [
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
    '/graphql', '/rest', '/rest/api', '/rest/v1',
    '/api/users', '/api/auth', '/api/login', '/api/config',
    '/api/admin', '/api/data', '/api/endpoints',
    '/swagger', '/swagger-ui', '/api-docs', '/openapi',
    '/api/swagger.json', '/api/swagger.yaml',
    '/v1', '/v2', '/v3', '/rest/v2'
]

AUTH_PATHS = [
    '/login', '/signin', '/auth', '/authenticate',
    '/sign-in', '/log-in', '/connect', '/oauth',
    '/logout', '/signout', '/sign-out', '/log-out',
    '/register', '/signup', '/sign-up', '/join',
    '/forgot-password', '/reset-password', '/password-reset',
    '/verify', '/confirm', '/activate', '/token',
    '/sso', '/saml', '/oauth2', '/openid'
]

SENSITIVE_PATHS = [
    '/.git/config', '/.git/HEAD', '/.svn/entries',
    '/.env', '/.env.local', '/.env.production',
    '/config', '/config.php', '/config.json', '/configuration',
    '/.aws/credentials', '/.ssh/id_rsa', '/.ssh/authorized_keys',
    '/backup', '/backup.zip', '/backup.sql', '/db.sql',
    '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
    '/server-status', '/server-info', '/.htaccess', '/web.config',
    '/composer.json', '/package.json', '/yarn.lock'
]


def get_default_wordlists() -> Dict[str, List[str]]:
    """Get default categorized wordlists for fuzzing"""
    return {
        'common': COMMON_PATHS,
        'admin': ADMIN_PATHS,
        'api': API_PATHS,
        'auth': AUTH_PATHS,
        'sensitive': SENSITIVE_PATHS
    }

