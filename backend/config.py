"""Configuration management for JimCrow"""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import Literal


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # LLM Provider Settings
    openai_api_key: str | None = None
    openrouter_api_key: str | None = None
    gemini_api_key: str | None = None
    llm_provider: Literal["openai", "openrouter", "gemini"] = "openai"
    llm_model: str = "gpt-4o-mini"  # Defaults: gpt-4o-mini, gemini-2.5-flash, anthropic/claude-3.5-sonnet
    
    # Gemini Thinking Mode (Extended thinking for complex reasoning)
    # See: https://ai.google.dev/gemini-api/docs/thinking
    # RECOMMENDED: Enable for strategic pentesting decisions
    gemini_thinking_enabled: bool = True
    
    @field_validator('llm_provider', mode='before')
    @classmethod
    def validate_provider(cls, v):
        """Validate and normalize LLM provider name"""
        if v is None:
            return "openai"
        v = str(v).lower()
        # Handle common variations
        if v in ["google", "gemini", "google-gemini"]:
            return "gemini"
        if v in ["openai", "openrouter", "gemini"]:
            return v
        # Default to openai if invalid
        return "openai"
    
    # Supabase Configuration
    supabase_url: str | None = None
    supabase_key: str | None = None
    
    # FastAPI Settings
    fastapi_host: str = "0.0.0.0"
    fastapi_port: int = 8000
    log_level: str = "INFO"
    
    # Security Settings
    max_concurrent_scans: int = 3
    request_timeout: int = 30
    rate_limit_per_second: int = 10
    
    # Scan Settings
    user_agent: str = "JimCrow-PenTest-Agent/0.1.0"
    max_depth: int = 5
    max_urls_per_scan: int = 1000
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Initialize settings with error handling
try:
    settings = Settings()
except Exception as e:
    # Fallback settings if .env is missing or invalid
    import warnings
    warnings.warn(f"Failed to load settings from .env: {e}. Using defaults.")
    settings = Settings(
        llm_provider="openai",
        llm_model="gpt-4o-mini"
    )

