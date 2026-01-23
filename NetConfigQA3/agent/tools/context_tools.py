"""
Context 조회 도구

Level 2 Facts JSON에서 장비 정보를 검색합니다.
에이전트가 필요한 순간에만 상세 정보를 조회할 수 있도록 합니다.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)

# 기본 Context 경로
DEFAULT_CONTEXT_DIR = Path(__file__).parent.parent.parent / "config" / "context"


class ContextManager:
    """Context 파일을 관리하고 검색 기능을 제공합니다."""
    
    def __init__(self, context_dir: Optional[Path] = None):
        self.context_dir = context_dir or DEFAULT_CONTEXT_DIR
        self._facts_cache: Optional[Dict] = None
        self._summary_cache: Optional[Dict] = None
    
    def _load_facts(self) -> Dict[str, Any]:
        """Level 2 Facts를 로드합니다."""
        if self._facts_cache is None:
            facts_path = self.context_dir / "device_facts.json"
            if facts_path.exists():
                with open(facts_path, "r", encoding="utf-8") as f:
                    self._facts_cache = json.load(f)
            else:
                logger.warning(f"Facts 파일이 없습니다: {facts_path}")
                self._facts_cache = {"devices": []}
        return self._facts_cache
    
    def _load_summary(self) -> Dict[str, Any]:
        """Level 1 Summary를 로드합니다."""
        if self._summary_cache is None:
            summary_path = self.context_dir / "device_summary.json"
            if summary_path.exists():
                with open(summary_path, "r", encoding="utf-8") as f:
                    self._summary_cache = json.load(f)
            else:
                logger.warning(f"Summary 파일이 없습니다: {summary_path}")
                self._summary_cache = {"devices": [], "last_updated": None}
        return self._summary_cache
    
    def get_summary(self) -> Dict[str, Any]:
        """Level 1 Summary 전체를 반환합니다."""
        return self._load_summary()
    
    def get_last_updated(self) -> Optional[str]:
        """마지막 갱신 시간을 반환합니다."""
        summary = self._load_summary()
        return summary.get("last_updated")
    
    def list_devices(self) -> List[str]:
        """장비 목록을 반환합니다."""
        summary = self._load_summary()
        return [d["hostname"] for d in summary.get("devices", [])]
    
    def search(self, device: str, section: Optional[str] = None) -> Dict[str, Any]:
        """
        장비의 Facts 정보를 검색합니다.
        
        Args:
            device: 장비 이름 (대소문자 무시)
            section: 조회할 섹션 경로 (예: "routing.ospf", "interfaces")
                     None이면 전체 장비 정보 반환
        
        Returns:
            해당 장비/섹션의 정보. 없으면 에러 딕셔너리 반환.
        
        Examples:
            search("pe1") -> PE1의 전체 정보
            search("pe1", "routing.bgp") -> PE1의 BGP 정보만
            search("pe1", "interfaces") -> PE1의 인터페이스 목록
        """
        facts = self._load_facts()
        
        # 장비 찾기 (대소문자 무시)
        device_data = None
        for d in facts.get("devices", []):
            hostname = d.get("system", {}).get("hostname", "")
            if hostname.lower() == device.lower():
                device_data = d
                break
        
        if device_data is None:
            available = [d.get("system", {}).get("hostname", "") 
                        for d in facts.get("devices", [])]
            return {
                "error": f"장비 '{device}'를 찾을 수 없습니다.",
                "available_devices": available
            }
        
        # 섹션 필터링
        if section:
            keys = section.split(".")
            result = device_data
            for key in keys:
                if isinstance(result, dict) and key in result:
                    result = result[key]
                else:
                    return {
                        "error": f"섹션 '{section}'을 찾을 수 없습니다.",
                        "available_sections": list(device_data.keys()) if isinstance(device_data, dict) else []
                    }
            return {
                "device": device,
                "section": section,
                "data": result
            }
        
        return device_data


# 싱글톤 인스턴스
_context_manager: Optional[ContextManager] = None


def get_context_manager() -> ContextManager:
    """ContextManager 싱글톤을 반환합니다."""
    global _context_manager
    if _context_manager is None:
        _context_manager = ContextManager()
    return _context_manager


# MCP 도구용 함수들
def search_context(device: str, section: Optional[str] = None) -> Dict[str, Any]:
    """
    장비의 Facts 정보를 검색합니다.
    
    이 도구는 Level 2 (상세 정보)를 조회할 때 사용합니다.
    간단한 질문은 System Prompt의 Summary로 먼저 답변하고,
    상세 정보가 필요할 때만 이 도구를 호출하세요.
    
    Args:
        device: 장비 이름 (예: "pe1", "p1", "leaf1")
        section: 조회할 섹션 (옵션)
                 - "interfaces": 인터페이스 목록
                 - "routing.bgp": BGP 설정
                 - "routing.ospf": OSPF 설정
                 - "services.vrf": VRF 목록
                 - "configuration": 보안/운영 설정
    
    Returns:
        요청된 장비/섹션의 구조화된 정보
    """
    manager = get_context_manager()
    return manager.search(device, section)


def get_context_summary() -> Dict[str, Any]:
    """
    전체 네트워크 Summary를 반환합니다.
    
    이 정보는 이미 System Prompt에 포함되어 있으므로,
    일반적으로 이 도구를 호출할 필요가 없습니다.
    """
    manager = get_context_manager()
    return manager.get_summary()


def list_available_devices() -> List[str]:
    """현재 Context에 있는 장비 목록을 반환합니다."""
    manager = get_context_manager()
    return manager.list_devices()
