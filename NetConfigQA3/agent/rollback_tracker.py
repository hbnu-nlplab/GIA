"""
Rollback Tracker Module

NSO commit 후 rollback ID를 추적하고, 롤백 기능을 제공합니다.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class RollbackEntry:
    """롤백 기록 항목"""
    rollback_id: str
    commit_time: str
    devices: List[str]
    change_summary: str
    user: str = "agent"
    status: str = "active"  # active, rolled_back, expired


class RollbackTracker:
    """
    Rollback ID 추적 및 관리
    
    모든 commit의 rollback ID를 기록하고,
    필요 시 즉각적인 롤백을 지원합니다.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or Path(__file__).parent.parent.parent / "config" / "rollback_history.json"
        self.history: List[RollbackEntry] = []
        self._load_history()
    
    def _load_history(self):
        """저장된 롤백 이력 로드"""
        try:
            if self.storage_path.exists():
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.history = [
                        RollbackEntry(**entry) for entry in data.get("entries", [])
                    ]
                logger.info(f"Loaded {len(self.history)} rollback entries")
        except Exception as e:
            logger.error(f"Failed to load rollback history: {e}")
            self.history = []
    
    def _save_history(self):
        """롤백 이력 저장"""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump({
                    "last_updated": datetime.utcnow().isoformat(),
                    "entries": [asdict(e) for e in self.history]
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save rollback history: {e}")
    
    def record_commit(
        self,
        rollback_id: str,
        devices: List[str],
        change_summary: str,
        user: str = "agent"
    ) -> RollbackEntry:
        """
        Commit 후 rollback ID를 기록합니다.
        """
        entry = RollbackEntry(
            rollback_id=rollback_id,
            commit_time=datetime.utcnow().isoformat() + "Z",
            devices=devices,
            change_summary=change_summary,
            user=user,
            status="active"
        )
        
        self.history.append(entry)
        self._save_history()
        
        logger.info(f"Recorded commit: rollback_id={rollback_id}, devices={devices}")
        return entry
    
    def get_latest_rollback_id(self, device: Optional[str] = None) -> Optional[str]:
        """
        최신 rollback ID를 반환합니다.
        device가 지정되면 해당 장비와 관련된 최신 ID 반환.
        """
        # 활성 상태인 것만 필터링, 최신순 정렬
        active = [e for e in self.history if e.status == "active"]
        
        if device:
            active = [e for e in active if device in e.devices]
        
        if not active:
            return None
        
        # 가장 최근 것 반환
        active.sort(key=lambda x: x.commit_time, reverse=True)
        return active[0].rollback_id
    
    def get_rollback_info(self, rollback_id: str) -> Optional[RollbackEntry]:
        """rollback ID로 정보 조회"""
        for entry in self.history:
            if entry.rollback_id == rollback_id:
                return entry
        return None
    
    def mark_as_rolled_back(self, rollback_id: str):
        """롤백 실행 후 상태 업데이트"""
        for entry in self.history:
            if entry.rollback_id == rollback_id:
                entry.status = "rolled_back"
                self._save_history()
                logger.info(f"Marked {rollback_id} as rolled back")
                return
    
    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """최근 롤백 이력 반환"""
        sorted_history = sorted(self.history, key=lambda x: x.commit_time, reverse=True)
        return [asdict(e) for e in sorted_history[:limit]]
    
    def format_rollback_response(self, rollback_id: str, devices: List[str], summary: str) -> str:
        """
        Commit 후 응답 메시지 생성
        """
        return (
            f"✅ 설정 적용 완료\n"
            f"   Rollback ID: {rollback_id}\n"
            f"   대상 장비: {', '.join(devices)}\n"
            f"   변경 내용: {summary}\n"
            f"\n"
            f"⚠️ 문제 발생 시 'rollback {rollback_id}'로 되돌릴 수 있습니다."
        )


# 싱글톤 인스턴스
_rollback_tracker: Optional[RollbackTracker] = None


def get_rollback_tracker() -> RollbackTracker:
    """RollbackTracker 싱글톤 반환"""
    global _rollback_tracker
    if _rollback_tracker is None:
        _rollback_tracker = RollbackTracker()
    return _rollback_tracker


# MCP 도구용 함수
def record_rollback_id(
    rollback_id: str,
    devices: List[str],
    change_summary: str
) -> Dict[str, Any]:
    """
    Commit 후 rollback ID를 기록합니다.
    
    이 함수는 nso.commit() 성공 후 자동으로 호출됩니다.
    """
    tracker = get_rollback_tracker()
    entry = tracker.record_commit(rollback_id, devices, change_summary)
    
    return {
        "recorded": True,
        "rollback_id": rollback_id,
        "message": tracker.format_rollback_response(rollback_id, devices, change_summary)
    }


def get_latest_rollback(device: str = None) -> Dict[str, Any]:
    """
    최신 rollback ID를 조회합니다.
    
    Args:
        device: 특정 장비 지정 (선택)
    
    Returns:
        최신 rollback 정보
    """
    tracker = get_rollback_tracker()
    rollback_id = tracker.get_latest_rollback_id(device)
    
    if rollback_id:
        entry = tracker.get_rollback_info(rollback_id)
        return {
            "rollback_id": rollback_id,
            "commit_time": entry.commit_time if entry else None,
            "devices": entry.devices if entry else [],
            "change_summary": entry.change_summary if entry else ""
        }
    
    return {
        "rollback_id": None,
        "message": "사용 가능한 rollback이 없습니다."
    }


def list_rollback_history(limit: int = 5) -> Dict[str, Any]:
    """
    최근 롤백 이력을 조회합니다.
    """
    tracker = get_rollback_tracker()
    history = tracker.get_history(limit)
    
    return {
        "count": len(history),
        "history": history
    }
