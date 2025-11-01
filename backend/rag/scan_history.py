"""Scan history storage and retrieval"""

from typing import List, Dict, Any
from datetime import datetime
from sentence_transformers import SentenceTransformer
from .supabase_client import SupabaseClient
from ..models import ScanResult


class ScanHistory:
    """Manages scan history with RAG for learning from past scans"""
    
    def __init__(self):
        self.supabase = SupabaseClient()
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    
    async def save_scan(self, scan_result: ScanResult) -> str:
        """Save a scan result to history"""
        
        # Create text representation for embedding
        scan_text = f"""
        Target: {scan_result.target.url}
        Mode: {scan_result.mode}
        Vulnerabilities found: {len(scan_result.vulnerabilities)}
        Types: {', '.join(set(v.vuln_type.value for v in scan_result.vulnerabilities))}
        """
        
        # Generate embedding
        embedding = self.embedding_model.encode(scan_text).tolist()
        
        # Prepare data
        scan_data = {
            'id': scan_result.scan_id,
            'target_url': scan_result.target.url,
            'mode': scan_result.mode.value,
            'status': scan_result.status.value,
            'vulnerabilities': [v.model_dump() for v in scan_result.vulnerabilities],
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
            'metadata': scan_result.metadata,
            'embedding': embedding
        }
        
        # Insert into Supabase
        result = self.supabase.client.table('scan_history').insert(scan_data).execute()
        
        return result.data[0]['id'] if result.data else None
    
    async def get_scan(self, scan_id: str) -> Dict[str, Any] | None:
        """Retrieve a specific scan by ID"""
        result = self.supabase.client.table('scan_history').select('*').eq(
            'id', scan_id
        ).execute()
        
        return result.data[0] if result.data else None
    
    async def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans"""
        result = self.supabase.client.table('scan_history').select('*').order(
            'created_at', desc=True
        ).limit(limit).execute()
        
        return result.data if result.data else []
    
    async def search_similar_scans(
        self,
        target_url: str = None,
        vulnerability_type: str = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Find similar past scans using semantic search"""
        
        # Build query text
        query_parts = []
        if target_url:
            query_parts.append(f"Target: {target_url}")
        if vulnerability_type:
            query_parts.append(f"Vulnerability: {vulnerability_type}")
        
        query_text = " ".join(query_parts) if query_parts else "all scans"
        
        # Generate query embedding
        query_embedding = self.embedding_model.encode(query_text).tolist()
        
        # Search using vector similarity
        result = self.supabase.client.rpc(
            'match_scan_history',
            {
                'query_embedding': query_embedding,
                'match_threshold': 0.5,
                'match_count': limit
            }
        ).execute()
        
        return result.data if result.data else []
    
    async def get_vulnerability_stats(self) -> Dict[str, Any]:
        """Get statistics about discovered vulnerabilities"""
        scans = await self.get_recent_scans(limit=100)
        
        total_scans = len(scans)
        total_vulns = sum(len(scan['vulnerabilities']) for scan in scans)
        
        # Count by type
        vuln_types = {}
        severity_counts = {}
        
        for scan in scans:
            for vuln in scan['vulnerabilities']:
                vuln_type = vuln['vuln_type']
                severity = vuln['severity']
                
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'by_type': vuln_types,
            'by_severity': severity_counts
        }

