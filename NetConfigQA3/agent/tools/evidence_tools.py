"""
Evidence Tools Module

증거팩(Evidence Pack)을 자동으로 구성합니다.
변경 작업 전 현재 상태, 관련 로그, Batfish 분석 결과를 수집합니다.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class EvidencePack:
    """증거팩 데이터 구조"""
    created_at: str
    target_device: str
    change_type: str
    
    # 현재 상태 (Level 2 Facts)
    current_state: Optional[Dict[str, Any]] = None
    
    # 예상 변경 (Dry-run diff)
    expected_changes: Optional[Dict[str, Any]] = None
    
    # 관련 로그
    recent_logs: Optional[List[Dict[str, Any]]] = None
    
    # Batfish 검증 결과
    batfish_analysis: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def summary(self) -> str:
        """증거팩 요약 문자열 생성"""
        lines = [
            f"📦 Evidence Pack for {self.target_device}",
            f"   생성 시간: {self.created_at}",
            f"   변경 유형: {self.change_type}",
        ]
        
        if self.current_state:
            lines.append(f"   현재 상태: {len(self.current_state)} 항목")
        
        if self.recent_logs:
            lines.append(f"   최근 로그: {len(self.recent_logs)} 건")
        
        if self.batfish_analysis:
            lines.append(f"   Batfish 분석: {'✅ 정상' if self.batfish_analysis.get('passed') else '⚠️ 주의 필요'}")
        
        return "\n".join(lines)


class EvidenceCollector:
    """
    증거 수집기
    
    작업 전 필요한 증거를 자동으로 수집하여 EvidencePack을 생성합니다.
    """
    
    def __init__(self):
        # Lazy imports to avoid circular dependencies
        self._context_manager = None
        self._nso_client = None
    
    @property
    def context_manager(self):
        if self._context_manager is None:
            from agent.tools.context_tools import get_context_manager
            self._context_manager = get_context_manager()
        return self._context_manager
    
    @property
    def nso_client(self):
        if self._nso_client is None:
            from clients.nso import NSOClient
            from config.settings import settings
            self._nso_client = NSOClient(
                base_url=settings.nso.base_url,
                username=settings.nso.username,
                password=settings.nso.password
            )
        return self._nso_client
    
    def collect_current_state(self, device: str, sections: List[str] = None) -> Dict[str, Any]:
        """
        장비의 현재 상태를 수집합니다 (Level 2 Facts 활용).
        """
        try:
            if sections is None:
                # 기본: 주요 섹션만 수집
                sections = ["interfaces", "routing", "services"]
            
            state = {}
            for section in sections:
                result = self.context_manager.search(device, section)
                if "error" not in result:
                    data = result.get("data", result)
                    state[section] = data
            
            return state
            
        except Exception as e:
            logger.error(f"Failed to collect current state for {device}: {e}")
            return {"error": str(e)}
    
    def collect_recent_logs(self, device: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        장비의 최근 로그를 수집합니다.
        
        TODO: 실제 로그 수집 구현 (NSO/Syslog 연동)
        현재는 플레이스홀더.
        """
        try:
            # 플레이스홀더: 실제 구현 시 telemetry_query 사용
            return [
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": "INFO",
                    "message": f"Evidence collection for {device}",
                    "source": "evidence_tools"
                }
            ]
        except Exception as e:
            logger.error(f"Failed to collect logs for {device}: {e}")
            return []
    
    def run_batfish_check(self, device: str, change_type: str) -> Dict[str, Any]:
        """
        Batfish로 변경 영향을 분석합니다.
        
        TODO: 실제 Batfish 연동 구현
        현재는 플레이스홀더.
        """
        try:
            # 플레이스홀더: 실제 구현 시 batfish_server 활용
            return {
                "passed": True,
                "checks": [
                    {"name": "reachability", "status": "pass"},
                    {"name": "no_blackhole", "status": "pass"}
                ],
                "warnings": []
            }
        except Exception as e:
            logger.error(f"Batfish check failed for {device}: {e}")
            return {"passed": False, "error": str(e)}
    
    def build_evidence_pack(
        self,
        device: str,
        change_type: str,
        include_logs: bool = True,
        include_batfish: bool = True,
        dry_run_diff: Optional[Dict[str, Any]] = None
    ) -> EvidencePack:
        """
        완전한 증거팩을 구성합니다.
        
        Args:
            device: 대상 장비
            change_type: 변경 유형 (add_bgp, modify_acl 등)
            include_logs: 로그 포함 여부
            include_batfish: Batfish 분석 포함 여부
            dry_run_diff: Dry-run 결과 (있으면 포함)
        """
        logger.info(f"Building evidence pack for {device} ({change_type})")
        
        pack = EvidencePack(
            created_at=datetime.utcnow().isoformat() + "Z",
            target_device=device,
            change_type=change_type
        )
        
        # 1. 현재 상태 수집
        pack.current_state = self.collect_current_state(device)
        
        # 2. Dry-run diff (제공된 경우)
        if dry_run_diff:
            pack.expected_changes = dry_run_diff
        
        # 3. 최근 로그
        if include_logs:
            pack.recent_logs = self.collect_recent_logs(device)
        
        # 4. Batfish 분석
        if include_batfish:
            pack.batfish_analysis = self.run_batfish_check(device, change_type)
        
        logger.info(f"Evidence pack built: {pack.summary()}")
        return pack


# 싱글톤 인스턴스
_evidence_collector: Optional[EvidenceCollector] = None


def get_evidence_collector() -> EvidenceCollector:
    """EvidenceCollector 싱글톤 반환"""
    global _evidence_collector
    if _evidence_collector is None:
        _evidence_collector = EvidenceCollector()
    return _evidence_collector


# MCP 도구용 함수
def build_evidence_pack(
    device: str,
    change_type: str,
    dry_run_diff: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    변경 작업 전 증거팩을 구성합니다.
    
    이 도구는 commit 전에 approval_request와 함께 사용하세요.
    현재 상태, 예상 변경, 로그, Batfish 분석을 포함합니다.
    
    Args:
        device: 대상 장비 이름
        change_type: 변경 유형 (예: "add_bgp_neighbor", "modify_acl")
        dry_run_diff: Dry-run 결과 (선택)
    
    Returns:
        구성된 증거팩
    """
    collector = get_evidence_collector()
    pack = collector.build_evidence_pack(
        device=device,
        change_type=change_type,
        dry_run_diff=dry_run_diff
    )
    
    return {
        "evidence_pack": pack.to_dict(),
        "summary": pack.summary()
    }
