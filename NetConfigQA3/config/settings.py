"""
NetConfigQA3 Settings
환경변수 로드 및 설정 관리
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

# .env 파일 로드
try:
    from dotenv import load_dotenv
    
    # 프로젝트 루트에서 .env 찾기
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
    else:
        # 상위 폴더에서도 찾기
        alt_env_path = Path(__file__).parent.parent / '.env'
        if alt_env_path.exists():
            load_dotenv(alt_env_path)
except ImportError:
    print("Warning: python-dotenv not installed. Using environment variables directly.")


@dataclass
class PnetlabConfig:
    """PNETLab 연결 설정"""
    base_url: str
    username: str
    password: str
    jwt_token: str = ""  # JWT 토큰 (쿠키명: token)
    session: str = ""    # 세션 쿠키 (쿠키명: _session)
    xsrf_token: str = "" # XSRF 토큰 (쿠키명: XSRF-TOKEN)
    timeout: int = 30


@dataclass
class NSOConfig:
    """NSO 연결 설정"""
    base_url: str
    username: str
    password: str
    timeout: int = 30


@dataclass
class BatfishConfig:
    """Batfish 연결 설정"""
    host: str
    network_name: str = "netconfig_qa"


@dataclass  
class OpenAIConfig:
    """OpenAI API 설정"""
    api_key: str
    model: str = "gpt-4o-mini"
    temperature: float = 0


class Settings:
    """전역 설정 관리자"""
    
    def __init__(self):
        self._pnetlab: Optional[PnetlabConfig] = None
        self._nso: Optional[NSOConfig] = None
        self._batfish: Optional[BatfishConfig] = None
        self._openai: Optional[OpenAIConfig] = None
    
    @property
    def pnetlab(self) -> PnetlabConfig:
        """PNETLab 설정 반환"""
        if self._pnetlab is None:
            self._pnetlab = PnetlabConfig(
                base_url=os.getenv("PNETLAB_BASE_URL", "http://100.66.240.82"),
                username=os.getenv("PNETLAB_USER", "admin"),
                password=os.getenv("PNETLAB_PASS", ""),
                jwt_token=os.getenv("PNETLAB_JWT_TOKEN", ""),
                session=os.getenv("PNETLAB_SESSION", ""),
                xsrf_token=os.getenv("PNETLAB_XSRF_TOKEN", ""),
                timeout=int(os.getenv("PNETLAB_TIMEOUT", "30"))
            )
        return self._pnetlab
    
    @property
    def nso(self) -> NSOConfig:
        """NSO 설정 반환"""
        if self._nso is None:
            self._nso = NSOConfig(
                base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf/data"),
                username=os.getenv("NSO_USER", "admin"),
                password=os.getenv("NSO_PASS", "admin"),
                timeout=int(os.getenv("NSO_TIMEOUT", "30"))
            )
        return self._nso

    @property
    def batfish(self) -> BatfishConfig:
        """Batfish 설정 반환"""
        if self._batfish is None:
            self._batfish = BatfishConfig(
                host=os.getenv("BATFISH_HOST", "localhost"),
                network_name=os.getenv("BATFISH_NETWORK", "netconfig_qa")
            )
        return self._batfish
    
    @property
    def openai(self) -> OpenAIConfig:
        """OpenAI 설정 반환"""
        if self._openai is None:
            self._openai = OpenAIConfig(
                api_key=os.getenv("OPENAI_API_KEY", ""),
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                temperature=float(os.getenv("OPENAI_TEMPERATURE", "0"))
            )
        return self._openai
    
    @property
    def log_level(self) -> str:
        """로그 레벨 반환"""
        return os.getenv("LOG_LEVEL", "INFO")
    
    @property
    def log_file(self) -> str:
        """로그 파일 경로 반환"""
        return os.getenv("LOG_FILE", "logs/sanoa_audit.log")


# 전역 설정 인스턴스
settings = Settings()

