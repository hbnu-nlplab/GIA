"""
Hybrid LLM Provider
OpenAI API, vLLM, Ollama 지원
"""
import os
from typing import Optional, Literal
from dataclasses import dataclass

from langchain_openai import ChatOpenAI
from langchain_core.language_models import BaseChatModel


@dataclass
class LLMConfig:
    """LLM 설정"""
    backend: Literal["openai", "vllm", "ollama"] = "openai"
    model: str = "gpt-4o-mini"
    temperature: float = 0.0
    max_tokens: int = 4096
    
    # Backend-specific
    base_url: Optional[str] = None
    api_key: Optional[str] = None


class LLMProvider:
    """하이브리드 LLM 제공자
    
    OpenAI API, vLLM 서버, Ollama를 통합 지원합니다.
    """
    
    @staticmethod
    def create(config: LLMConfig) -> BaseChatModel:
        """LLM 인스턴스 생성
        
        Args:
            config: LLM 설정
            
        Returns:
            BaseChatModel 인스턴스
        """
        if config.backend == "openai":
            return LLMProvider._create_openai(config)
        elif config.backend == "vllm":
            return LLMProvider._create_vllm(config)
        elif config.backend == "ollama":
            return LLMProvider._create_ollama(config)
        else:
            raise ValueError(f"Unknown backend: {config.backend}")
    
    @staticmethod
    def _create_openai(config: LLMConfig) -> ChatOpenAI:
        """OpenAI API 클라이언트 생성"""
        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            api_key=config.api_key or os.getenv("OPENAI_API_KEY"),
        )
    
    @staticmethod
    def _create_vllm(config: LLMConfig) -> ChatOpenAI:
        """vLLM 서버 클라이언트 생성 (GPT-OSS-20B 등)
        
        vLLM은 OpenAI-compatible API를 제공하므로 ChatOpenAI 사용
        """
        base_url = config.base_url or os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1")
        
        return ChatOpenAI(
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            api_key="EMPTY",  # vLLM은 API key 불필요
            base_url=base_url,
        )
    
    @staticmethod
    def _create_ollama(config: LLMConfig) -> BaseChatModel:
        """Ollama 클라이언트 생성"""
        try:
            from langchain_community.chat_models import ChatOllama
        except ImportError:
            raise ImportError(
                "Ollama 사용을 위해 langchain-community 설치 필요: "
                "pip install langchain-community"
            )
        
        base_url = config.base_url or os.getenv("OLLAMA_API_URL", "http://localhost:11434")
        
        return ChatOllama(
            model=config.model,
            temperature=config.temperature,
            base_url=base_url,
        )
    
    @staticmethod
    def get_default_config(backend: str = "openai") -> LLMConfig:
        """기본 설정 반환"""
        configs = {
            "openai": LLMConfig(backend="openai", model="gpt-4o-mini"),
            "vllm": LLMConfig(backend="vllm", model="gpt-oss-20b"),
            "ollama": LLMConfig(backend="ollama", model="qwen2.5:32b"),
        }
        return configs.get(backend, configs["openai"])
