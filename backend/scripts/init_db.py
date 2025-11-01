"""Initialize Supabase database schema"""

import asyncio
from backend.rag.supabase_client import SupabaseClient
from backend.rag.knowledge_base import KnowledgeBase


async def init_database():
    """Initialize database schema and populate default data"""
    
    print("Initializing JimCrow database...")
    
    try:
        # Initialize Supabase client
        client = SupabaseClient()
        
        # Print schema information
        print("\n📋 Database Schema:")
        print("-" * 50)
        kb_schema, scan_schema = await client.init_tables()
        print("Knowledge Base Table Schema:")
        print(kb_schema)
        print("\nScan History Table Schema:")
        print(scan_schema)
        print("-" * 50)
        
        print("\n✓ Supabase client initialized")
        
        # Populate knowledge base
        print("\n📚 Populating knowledge base with default content...")
        kb = KnowledgeBase()
        await kb.populate_default_knowledge()
        print("✓ Knowledge base populated")
        
        print("\n✅ Database initialization complete!")
        print("\nNext steps:")
        print("1. Ensure your Supabase project has the tables created")
        print("2. Run migrations if needed")
        print("3. Start the application with: python -m backend.api.main")
        
    except Exception as e:
        print(f"\n❌ Error initializing database: {str(e)}")
        print("\nPlease ensure:")
        print("- SUPABASE_URL and SUPABASE_KEY are set in .env")
        print("- Your Supabase project is accessible")
        print("- pgvector extension is enabled in Supabase")


if __name__ == "__main__":
    asyncio.run(init_database())

