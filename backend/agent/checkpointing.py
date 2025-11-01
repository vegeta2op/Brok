"""LangGraph checkpointing and state persistence for scan recovery"""

import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from langgraph.checkpoint.sqlite import SqliteSaver


class ScanCheckpointer:
    """Manages checkpointing and state persistence for pentesting scans"""
    
    def __init__(self, checkpoint_dir: Optional[Path] = None):
        """Initialize checkpointer
        
        Args:
            checkpoint_dir: Directory for checkpoint database
        """
        if checkpoint_dir is None:
            checkpoint_dir = Path.home() / ".jimcrow" / "checkpoints"
        
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize SQLite checkpointer for persistence
        self.db_path = self.checkpoint_dir / "scan_checkpoints.db"
        self._init_database()
        
    def _init_database(self):
        """Initialize the checkpoint database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create scan metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_metadata (
                    scan_id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL UNIQUE,
                    target_url TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    last_checkpoint TEXT,
                    status TEXT NOT NULL,
                    current_phase TEXT,
                    urls_scanned INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0
                )
            """)
            
            conn.commit()
    
    def get_checkpointer(self):
        """Get LangGraph SQLite checkpointer instance
        
        Returns a context manager that yields SqliteSaver.
        Use with: async with checkpointer.get_checkpointer() as saver:
        """
        return SqliteSaver.from_conn_string(str(self.db_path))
    
    def save_scan_metadata(self, scan_id: str, thread_id: str, target_url: str, status: str):
        """Save scan metadata"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scan_metadata 
                (scan_id, thread_id, target_url, start_time, last_checkpoint, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, thread_id, target_url, datetime.now().isoformat(), 
                  datetime.now().isoformat(), status))
            conn.commit()
    
    def update_scan_status(self, scan_id: str, status: str, current_phase: str = None,
                          urls_scanned: int = None, vulnerabilities_found: int = None):
        """Update scan metadata"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            updates = ["last_checkpoint = ?", "status = ?"]
            params = [datetime.now().isoformat(), status]
            
            if current_phase:
                updates.append("current_phase = ?")
                params.append(current_phase)
            if urls_scanned is not None:
                updates.append("urls_scanned = ?")
                params.append(urls_scanned)
            if vulnerabilities_found is not None:
                updates.append("vulnerabilities_found = ?")
                params.append(vulnerabilities_found)
            
            params.append(scan_id)
            cursor.execute(f"UPDATE scan_metadata SET {', '.join(updates)} WHERE scan_id = ?", params)
            conn.commit()
    
    def get_scan_metadata(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan metadata"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_metadata WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def list_scans(self, status: str = None) -> list:
        """List all scans"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM scan_metadata WHERE status = ? ORDER BY start_time DESC", (status,))
            else:
                cursor.execute("SELECT * FROM scan_metadata ORDER BY start_time DESC")
            return [dict(row) for row in cursor.fetchall()]


# Global instance
_checkpointer = None

def get_checkpointer() -> ScanCheckpointer:
    """Get or create global checkpointer instance"""
    global _checkpointer
    if _checkpointer is None:
        _checkpointer = ScanCheckpointer()
    return _checkpointer
