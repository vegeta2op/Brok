"""Knowledge base for pentesting methodologies"""

from typing import List, Dict, Any
from sentence_transformers import SentenceTransformer
import numpy as np
from .supabase_client import SupabaseClient


class KnowledgeBase:
    """Manages pentesting knowledge base with RAG"""
    
    def __init__(self):
        self.supabase = SupabaseClient()
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    
    async def add_document(
        self,
        title: str,
        content: str,
        category: str = None,
        tags: List[str] = None
    ) -> str:
        """Add a document to the knowledge base"""
        
        # Generate embedding
        embedding = self.embedding_model.encode(content).tolist()
        
        # Insert into Supabase
        result = self.supabase.client.table('knowledge_base').insert({
            'title': title,
            'content': content,
            'category': category,
            'tags': tags or [],
            'embedding': embedding
        }).execute()
        
        return result.data[0]['id'] if result.data else None
    
    async def search(
        self,
        query: str,
        category: str = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Search knowledge base using semantic similarity"""
        
        # Generate query embedding
        query_embedding = self.embedding_model.encode(query).tolist()
        
        # Search using vector similarity
        rpc_params = {
            'query_embedding': query_embedding,
            'match_threshold': 0.5,
            'match_count': limit
        }
        
        if category:
            rpc_params['filter_category'] = category
        
        # Use Supabase RPC for vector search
        result = self.supabase.client.rpc(
            'match_knowledge_base',
            rpc_params
        ).execute()
        
        return result.data if result.data else []
    
    async def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get all documents in a category"""
        result = self.supabase.client.table('knowledge_base').select('*').eq(
            'category', category
        ).execute()
        
        return result.data if result.data else []
    
    async def populate_default_knowledge(self):
        """Populate knowledge base with default pentesting content"""
        
        default_docs = [
            {
                'title': 'SQL Injection Overview',
                'content': '''SQL Injection is a code injection technique that exploits a security vulnerability 
                in an application's software. It occurs when user input is improperly sanitized and directly 
                concatenated into SQL queries. Attackers can manipulate these queries to access, modify, or 
                delete data. Common payloads include: ' OR '1'='1, UNION SELECT, and time-based blind injection 
                techniques using SLEEP() or WAITFOR DELAY.''',
                'category': 'injection',
                'tags': ['sql', 'injection', 'owasp-top-10']
            },
            {
                'title': 'XSS (Cross-Site Scripting)',
                'content': '''Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into 
                web pages viewed by other users. There are three types: Reflected XSS (immediate response), 
                Stored XSS (persistent), and DOM-based XSS (client-side). Common payloads include <script>alert(1)</script>, 
                <img src=x onerror=alert(1)>, and event handlers like onload, onerror, onfocus.''',
                'category': 'injection',
                'tags': ['xss', 'javascript', 'owasp-top-10']
            },
            {
                'title': 'CSRF Protection',
                'content': '''Cross-Site Request Forgery (CSRF) tricks authenticated users into executing unwanted 
                actions. Prevention includes: using anti-CSRF tokens (random, unpredictable values tied to session), 
                SameSite cookie attribute (Lax or Strict), checking Referer/Origin headers, and requiring 
                re-authentication for sensitive actions.''',
                'category': 'authentication',
                'tags': ['csrf', 'session', 'owasp-top-10']
            },
            {
                'title': 'Security Headers',
                'content': '''Important HTTP security headers: Content-Security-Policy (prevent XSS), 
                Strict-Transport-Security (enforce HTTPS), X-Frame-Options (prevent clickjacking), 
                X-Content-Type-Options: nosniff (prevent MIME sniffing), Referrer-Policy (control referrer info).''',
                'category': 'configuration',
                'tags': ['headers', 'defense', 'best-practices']
            },
            {
                'title': 'Authentication Testing',
                'content': '''Test authentication mechanisms: check for default credentials, brute force protection, 
                password complexity, session timeout, secure cookie flags (HttpOnly, Secure, SameSite), 
                password reset vulnerabilities, multi-factor authentication bypass.''',
                'category': 'authentication',
                'tags': ['authentication', 'session', 'testing']
            }
        ]
        
        for doc in default_docs:
            await self.add_document(**doc)

