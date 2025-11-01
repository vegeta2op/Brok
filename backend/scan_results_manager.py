"""Scan results management - organized storage and retrieval"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import uuid


class ScanResultsManager:
    """Manages scan results storage in organized directory structure"""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """Initialize scan results manager
        
        Args:
            base_dir: Base directory for scan results (default: ~/.jimcrow/scan-results)
        """
        if base_dir is None:
            base_dir = Path.home() / ".jimcrow" / "scan-results"
        
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        self.active_dir = self.base_dir / "active"
        self.completed_dir = self.base_dir / "completed"
        self.failed_dir = self.base_dir / "failed"
        
        for dir_path in [self.active_dir, self.completed_dir, self.failed_dir]:
            dir_path.mkdir(exist_ok=True)
    
    def create_scan_session(self, target_url: str, scan_mode: str = "autonomous") -> Dict[str, Any]:
        """Create a new scan session
        
        Args:
            target_url: Target URL being scanned
            scan_mode: Scan mode (autonomous, assisted, etc.)
            
        Returns:
            Session metadata including scan_id and paths
        """
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        # Create scan directory
        scan_dirname = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{self._sanitize_url(target_url)}_{scan_id[:8]}"
        scan_dir = self.active_dir / scan_dirname
        scan_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for organized storage
        (scan_dir / "logs").mkdir(exist_ok=True)
        (scan_dir / "findings").mkdir(exist_ok=True)
        (scan_dir / "screenshots").mkdir(exist_ok=True)
        (scan_dir / "reports").mkdir(exist_ok=True)
        
        # Create session metadata
        session = {
            'scan_id': scan_id,
            'target_url': target_url,
            'scan_mode': scan_mode,
            'start_time': timestamp.isoformat(),
            'status': 'active',
            'scan_dir': str(scan_dir),
            'paths': {
                'base': str(scan_dir),
                'logs': str(scan_dir / "logs"),
                'findings': str(scan_dir / "findings"),
                'screenshots': str(scan_dir / "screenshots"),
                'reports': str(scan_dir / "reports")
            }
        }
        
        # Save session metadata
        self._save_metadata(scan_dir, session)
        
        return session
    
    def save_scan_progress(self, scan_id: str, progress_data: Dict[str, Any]):
        """Save scan progress during active scan
        
        Args:
            scan_id: Scan ID
            progress_data: Progress data to save
        """
        scan_dir = self._find_scan_dir(scan_id, self.active_dir)
        if not scan_dir:
            return
        
        # Save progress to logs
        progress_file = scan_dir / "logs" / f"progress_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(progress_file, 'w') as f:
            json.dump(progress_data, f, indent=2, default=str)
    
    def save_finding(self, scan_id: str, finding: Dict[str, Any]):
        """Save a vulnerability finding
        
        Args:
            scan_id: Scan ID
            finding: Vulnerability finding data
        """
        scan_dir = self._find_scan_dir(scan_id, self.active_dir)
        if not scan_dir:
            return
        
        # Save to findings directory
        finding_id = finding.get('vuln_id', str(uuid.uuid4()))
        finding_file = scan_dir / "findings" / f"{finding_id}.json"
        with open(finding_file, 'w') as f:
            json.dump(finding, f, indent=2, default=str)
    
    def complete_scan(self, scan_id: str, final_results: Dict[str, Any]) -> str:
        """Mark scan as completed and move to completed directory
        
        Args:
            scan_id: Scan ID
            final_results: Final scan results
            
        Returns:
            Path to completed scan directory
        """
        scan_dir = self._find_scan_dir(scan_id, self.active_dir)
        if not scan_dir:
            return ""
        
        # Update metadata
        metadata = self._load_metadata(scan_dir)
        metadata['status'] = 'completed'
        metadata['end_time'] = datetime.now().isoformat()
        metadata['summary'] = {
            'total_vulnerabilities': len(final_results.get('vulnerabilities', [])),
            'urls_scanned': len(final_results.get('scanned_urls', [])),
            'duration': self._calculate_duration(metadata['start_time'])
        }
        self._save_metadata(scan_dir, metadata)
        
        # Save final results
        results_file = scan_dir / "reports" / "final_results.json"
        with open(results_file, 'w') as f:
            json.dump(final_results, f, indent=2, default=str)
        
        # Generate HTML report
        self._generate_html_report(scan_dir, metadata, final_results)
        
        # Move to completed directory
        new_path = self.completed_dir / scan_dir.name
        scan_dir.rename(new_path)
        
        return str(new_path)
    
    def fail_scan(self, scan_id: str, error: str):
        """Mark scan as failed and move to failed directory
        
        Args:
            scan_id: Scan ID
            error: Error message
        """
        scan_dir = self._find_scan_dir(scan_id, self.active_dir)
        if not scan_dir:
            return
        
        # Update metadata
        metadata = self._load_metadata(scan_dir)
        metadata['status'] = 'failed'
        metadata['end_time'] = datetime.now().isoformat()
        metadata['error'] = error
        self._save_metadata(scan_dir, metadata)
        
        # Move to failed directory
        new_path = self.failed_dir / scan_dir.name
        scan_dir.rename(new_path)
    
    def list_scans(self, status: str = "all") -> List[Dict[str, Any]]:
        """List scans by status
        
        Args:
            status: Filter by status (all, active, completed, failed)
            
        Returns:
            List of scan metadata
        """
        scans = []
        
        dirs_to_check = []
        if status in ["all", "active"]:
            dirs_to_check.append(self.active_dir)
        if status in ["all", "completed"]:
            dirs_to_check.append(self.completed_dir)
        if status in ["all", "failed"]:
            dirs_to_check.append(self.failed_dir)
        
        for directory in dirs_to_check:
            for scan_dir in sorted(directory.iterdir(), reverse=True):
                if scan_dir.is_dir():
                    metadata = self._load_metadata(scan_dir)
                    if metadata:
                        scans.append(metadata)
        
        return scans
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan metadata by ID
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan metadata or None if not found
        """
        for directory in [self.active_dir, self.completed_dir, self.failed_dir]:
            scan_dir = self._find_scan_dir(scan_id, directory)
            if scan_dir:
                return self._load_metadata(scan_dir)
        return None
    
    def _find_scan_dir(self, scan_id: str, directory: Path) -> Optional[Path]:
        """Find scan directory by scan ID"""
        for scan_dir in directory.iterdir():
            if scan_dir.is_dir():
                metadata = self._load_metadata(scan_dir)
                if metadata and metadata.get('scan_id') == scan_id:
                    return scan_dir
        return None
    
    def _load_metadata(self, scan_dir: Path) -> Optional[Dict[str, Any]]:
        """Load scan metadata"""
        metadata_file = scan_dir / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                return json.load(f)
        return None
    
    def _save_metadata(self, scan_dir: Path, metadata: Dict[str, Any]):
        """Save scan metadata"""
        metadata_file = scan_dir / "metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
    
    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL for use in directory name"""
        # Remove protocol
        url = url.replace('https://', '').replace('http://', '')
        # Remove trailing slash
        url = url.rstrip('/')
        # Replace invalid characters
        for char in ['/', ':', '?', '&', '=', '#']:
            url = url.replace(char, '_')
        # Limit length
        return url[:50]
    
    def _calculate_duration(self, start_time_iso: str) -> str:
        """Calculate duration from start time"""
        start = datetime.fromisoformat(start_time_iso)
        end = datetime.now()
        duration = end - start
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        seconds = duration.seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def _generate_html_report(self, scan_dir: Path, metadata: Dict[str, Any], results: Dict[str, Any]):
        """Generate HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>JimCrow Scan Report - {metadata['target_url']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }}
        h1 {{ color: #2c3e50; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .vulnerability {{ border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; background: #fef5f5; }}
        .high {{ border-left-color: #e74c3c; }}
        .medium {{ border-left-color: #f39c12; }}
        .low {{ border-left-color: #3498db; }}
        .info {{ border-left-color: #95a5a6; }}
        .metadata {{ color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 JimCrow Penetration Test Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target:</strong> {metadata['target_url']}</p>
            <p><strong>Scan ID:</strong> {metadata['scan_id']}</p>
            <p><strong>Start Time:</strong> {metadata['start_time']}</p>
            <p><strong>End Time:</strong> {metadata.get('end_time', 'N/A')}</p>
            <p><strong>Duration:</strong> {metadata.get('summary', {}).get('duration', 'N/A')}</p>
            <p><strong>Vulnerabilities Found:</strong> {len(results.get('vulnerabilities', []))}</p>
            <p><strong>URLs Scanned:</strong> {len(results.get('scanned_urls', []))}</p>
        </div>
        
        <h2>Vulnerabilities</h2>
"""
        
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'info').lower()
            html_content += f"""
        <div class="vulnerability {severity}">
            <h3>{vuln.get('title', 'Unknown Vulnerability')}</h3>
            <p class="metadata"><strong>Severity:</strong> {vuln.get('severity', 'N/A').upper()} | 
               <strong>Type:</strong> {vuln.get('vuln_type', 'N/A')}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
            <p><strong>Affected URL:</strong> <code>{vuln.get('affected_url', 'N/A')}</code></p>
            <p><strong>Evidence:</strong> <code>{vuln.get('evidence', 'N/A')[:200]}</code></p>
            <p><strong>Remediation:</strong> {vuln.get('remediation', 'N/A')}</p>
        </div>
"""
        
        if not results.get('vulnerabilities'):
            html_content += "<p>✅ No vulnerabilities found during this scan.</p>"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        report_file = scan_dir / "reports" / "report.html"
        with open(report_file, 'w') as f:
            f.write(html_content)

