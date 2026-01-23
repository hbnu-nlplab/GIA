"""
Approval Gate Module

위험한 작업(commit, rollback, sync-to) 전 사용자 승인을 요청합니다.
CLI와 향후 Streamlit UI 모두 지원.

Approve/Reject/Modify 3가지 선택지 제공.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """승인 상태"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"


class RiskLevel(Enum):
    """위험도 수준"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ApprovalRequest:
    """승인 요청 데이터"""
    request_id: str
    action: str  # commit, rollback, sync-to
    target_devices: List[str]
    change_summary: str
    risk_level: RiskLevel
    impact_assessment: Dict[str, Any]
    rollback_method: str
    evidence_pack: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: ApprovalStatus = ApprovalStatus.PENDING
    user_comment: Optional[str] = None


class ApprovalGate:
    """
    Human-in-the-Loop 승인 게이트
    
    위험한 작업 전 사용자에게 승인을 요청하고,
    Approve/Reject/Modify 결정을 처리합니다.
    """
    
    def __init__(self):
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self._request_counter = 0
    
    def _generate_request_id(self) -> str:
        """고유 요청 ID 생성"""
        self._request_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"APR-{timestamp}-{self._request_counter:04d}"
    
    def assess_risk(self, action: str, devices: List[str], change_details: Dict[str, Any]) -> RiskLevel:
        """
        작업의 위험도를 평가합니다.
        
        위험도 기준:
        - CRITICAL: 금지된 작업 (any-any permit, default route 등)
        - HIGH: 5대 이상 동시 변경, rollback
        - MEDIUM: 1-4대 변경, commit
        - LOW: dry-run, 단순 조회
        """
        # 금지 패턴 체크
        forbidden_patterns = ["any-any", "permit ip any any", "ip route 0.0.0.0 0.0.0.0"]
        change_str = json.dumps(change_details).lower()
        for pattern in forbidden_patterns:
            if pattern in change_str:
                return RiskLevel.CRITICAL
        
        # 장비 수 기반 평가
        device_count = len(devices)
        
        if action == "rollback":
            return RiskLevel.HIGH
        elif action == "commit":
            if device_count >= 5:
                return RiskLevel.HIGH
            elif device_count >= 1:
                return RiskLevel.MEDIUM
        elif action == "sync-to":
            return RiskLevel.HIGH
        elif action == "dry_run":
            return RiskLevel.LOW
        
        return RiskLevel.MEDIUM
    
    def create_request(
        self,
        action: str,
        target_devices: List[str],
        change_summary: str,
        change_details: Dict[str, Any],
        rollback_id: Optional[str] = None,
        evidence_pack: Optional[Dict[str, Any]] = None
    ) -> ApprovalRequest:
        """
        승인 요청을 생성합니다.
        """
        request_id = self._generate_request_id()
        risk_level = self.assess_risk(action, target_devices, change_details)
        
        # 영향 분석
        impact = {
            "affected_devices": target_devices,
            "device_count": len(target_devices),
            "change_type": action,
            "details": change_details
        }
        
        # 롤백 방법 결정
        if rollback_id:
            rollback_method = f"NSO rollback file #{rollback_id}"
        else:
            rollback_method = "NSO rollback (자동 생성됨)"
        
        request = ApprovalRequest(
            request_id=request_id,
            action=action,
            target_devices=target_devices,
            change_summary=change_summary,
            risk_level=risk_level,
            impact_assessment=impact,
            rollback_method=rollback_method,
            evidence_pack=evidence_pack
        )
        
        self.pending_requests[request_id] = request
        logger.info(f"Approval request created: {request_id} ({action}, {risk_level.value})")
        
        return request
    
    def format_cli_prompt(self, request: ApprovalRequest) -> str:
        """
        CLI용 승인 요청 프롬프트를 생성합니다.
        """
        risk_emoji = {
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🟠",
            RiskLevel.CRITICAL: "🔴"
        }
        
        lines = [
            "",
            "=" * 60,
            "⚠️  승인 요청 (Approval Required)",
            "=" * 60,
            f"요청 ID: {request.request_id}",
            f"작업: {request.action.upper()}",
            f"위험도: {risk_emoji.get(request.risk_level, '⚪')} {request.risk_level.value.upper()}",
            "",
            f"📋 변경 내용:",
            f"   {request.change_summary}",
            "",
            f"🎯 대상 장비: {', '.join(request.target_devices)} ({len(request.target_devices)}대)",
            "",
            f"🔄 롤백 방법: {request.rollback_method}",
            "=" * 60,
        ]
        
        if request.evidence_pack:
            lines.append("📦 증거팩:")
            for key, value in request.evidence_pack.items():
                lines.append(f"   - {key}: {value}")
            lines.append("")
        
        lines.extend([
            "",
            "[A]pprove - 승인하고 실행",
            "[R]eject - 거부하고 취소",
            "[M]odify - 계획 수정 요청",
            "",
            "선택 (A/R/M): ",
        ])
        
        return "\n".join(lines)
    
    def process_cli_response(self, request_id: str, response: str, comment: Optional[str] = None) -> ApprovalStatus:
        """
        CLI 응답을 처리합니다.
        """
        if request_id not in self.pending_requests:
            raise ValueError(f"Request {request_id} not found")
        
        request = self.pending_requests[request_id]
        response = response.strip().upper()
        
        if response in ["A", "APPROVE", "Y", "YES"]:
            request.status = ApprovalStatus.APPROVED
        elif response in ["R", "REJECT", "N", "NO"]:
            request.status = ApprovalStatus.REJECTED
        elif response in ["M", "MODIFY"]:
            request.status = ApprovalStatus.MODIFIED
        else:
            # 기본: 거부 (안전 우선)
            request.status = ApprovalStatus.REJECTED
            logger.warning(f"Invalid response '{response}', defaulting to REJECTED")
        
        request.user_comment = comment
        logger.info(f"Request {request_id} -> {request.status.value}")
        
        return request.status
    
    def is_approved(self, request_id: str) -> bool:
        """요청이 승인되었는지 확인"""
        if request_id not in self.pending_requests:
            return False
        return self.pending_requests[request_id].status == ApprovalStatus.APPROVED
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """요청 정보 조회"""
        return self.pending_requests.get(request_id)


# 싱글톤 인스턴스
_approval_gate: Optional[ApprovalGate] = None


def get_approval_gate() -> ApprovalGate:
    """ApprovalGate 싱글톤 반환"""
    global _approval_gate
    if _approval_gate is None:
        _approval_gate = ApprovalGate()
    return _approval_gate


# MCP 도구용 함수
def request_approval(
    action: str,
    devices: List[str],
    change_summary: str,
    change_details: Dict[str, Any] = None,
    evidence_pack: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    위험한 작업 전 승인을 요청합니다.
    
    이 도구는 commit, rollback, sync-to 같은 파괴적 작업 전에 반드시 호출해야 합니다.
    
    Args:
        action: 작업 유형 (commit, rollback, sync-to)
        devices: 대상 장비 목록
        change_summary: 변경 내용 한 줄 요약
        change_details: 상세 변경 정보 (선택)
        evidence_pack: 증거팩 (선택)
    
    Returns:
        request_id와 승인 프롬프트
    """
    gate = get_approval_gate()
    
    request = gate.create_request(
        action=action,
        target_devices=devices,
        change_summary=change_summary,
        change_details=change_details or {},
        evidence_pack=evidence_pack
    )
    
    prompt = gate.format_cli_prompt(request)
    
    return {
        "request_id": request.request_id,
        "risk_level": request.risk_level.value,
        "prompt": prompt,
        "status": "pending",
        "message": "사용자 승인을 기다리고 있습니다."
    }
