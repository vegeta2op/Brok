"""Supabase client for RAG system"""

from supabase import create_client, Client
from typing import List, Dict, Any
from ..config import settings


class SupabaseClient:
    """Wrapper for Supabase operations"""
    
    _instance = None
    _client: Client = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize Supabase client"""
        if not settings.supabase_url or not settings.supabase_key:
            raise ValueError("Supabase credentials not configured")
        
        self._client = create_client(settings.supabase_url, settings.supabase_key)
    
    @property
    def client(self) -> Client:
        """Get Supabase client instance"""
        return self._client
    
    async def init_tables(self):
        """Initialize required database tables"""
        # This would typically be done via Supabase dashboard or migrations
        # Here we define the schema for reference
        
        # Knowledge base table
        kb_schema = """
        CREATE TABLE IF NOT EXISTS knowledge_base (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT,
            tags TEXT[],
            embedding vector(1536),
            created_at TIMESTAMP DEFAULT NOW()
        );
        
        CREATE INDEX IF NOT EXISTS idx_kb_embedding ON knowledge_base 
        USING ivfflat (embedding vector_cosine_ops);
        """
        
        # Scan history table
        scan_schema = """
        CREATE TABLE IF NOT EXISTS scan_history (
            id UUID PRIMARY KEY,
            target_url TEXT NOT NULL,
            mode TEXT,
            status TEXT,
            vulnerabilities JSONB,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            metadata JSONB,
            embedding vector(1536),
            created_at TIMESTAMP DEFAULT NOW()
        );
        
        CREATE INDEX IF NOT EXISTS idx_scan_embedding ON scan_history 
        USING ivfflat (embedding vector_cosine_ops);
        """
        
        return kb_schema, scan_schema

