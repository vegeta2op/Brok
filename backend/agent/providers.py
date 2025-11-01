"""LLM Provider abstraction for multiple AI services"""

from typing import Literal
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models import BaseChatModel
from ..config import settings


class LLMProvider:
    """Manages LLM providers (OpenAI, OpenRouter, Gemini)"""
    
    @staticmethod
    def get_llm(
        provider: Literal["openai", "openrouter", "gemini"] = None,
        model: str = None,
        temperature: float = 0.1
    ) -> BaseChatModel:
        """Get LLM instance based on provider"""
        
        provider = provider or settings.llm_provider
        model = model or settings.llm_model
        
        if provider == "openai":
            if not settings.openai_api_key:
                raise ValueError("OpenAI API key not configured")
            
            return ChatOpenAI(
                api_key=settings.openai_api_key,
                model=model,
                temperature=temperature
            )
        
        elif provider == "openrouter":
            if not settings.openrouter_api_key:
                raise ValueError("OpenRouter API key not configured")
            
            return ChatOpenAI(
                api_key=settings.openrouter_api_key,
                base_url="https://openrouter.ai/api/v1",
                model=model,
                temperature=temperature
            )
        
        elif provider == "gemini":
            if not settings.gemini_api_key:
                raise ValueError("Gemini API key not configured")
            
            # Configure with thinking mode if enabled
            # Extended thinking: https://ai.google.dev/gemini-api/docs/thinking
            model_kwargs = {}
            if settings.gemini_thinking_enabled and "2.0" in model:
                # Enable thinking mode for Gemini 2.0+ models
                model_kwargs["thinking"] = {"mode": "extended"}
            
            return ChatGoogleGenerativeAI(
                google_api_key=settings.gemini_api_key,
                model=model,
                temperature=temperature,
                model_kwargs=model_kwargs
            )
        
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    
    @staticmethod
    def get_embedding_model(provider: Literal["openai", "openrouter", "gemini"] = None):
        """Get embedding model for RAG"""
        from langchain_openai import OpenAIEmbeddings
        
        provider = provider or settings.llm_provider
        
        # For now, use OpenAI embeddings for all providers
        # Can be extended to support other embedding models
        if settings.openai_api_key:
            return OpenAIEmbeddings(api_key=settings.openai_api_key)
        
        raise ValueError("No embedding model configured")

