#!/usr/bin/env python3
"""
NSO Commit Hook

NSO commit 발생 시 자동으로 Context(Facts)를 갱신합니다.

구현 방식:
- Polling: 주기적으로 NSO rollback 파일 수를 확인하여 변경 감지
- 향후: NSO notification/subscription 방식으로 확장 가능

Usage:
    # 데몬 모드로 실행 (백그라운드)
    python scripts/nso_commit_hook.py --daemon
    
    # 1회 동기화
    python scripts/nso_commit_hook.py --sync-now
    
    # Polling 간격 설정 (초)
    python scripts/nso_commit_hook.py --daemon --interval 60
"""

import sys
import json
import time
import signal
import logging
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass

# 프로젝트 경로 설정
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from clients.nso import NSOClient
from config.settings import settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [CommitHook] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class CommitState:
    """마지막 commit 상태 추적"""
    last_rollback_count: int = 0
    last_check_time: Optional[str] = None
    last_sync_time: Optional[str] = None


class NSOCommitHook:
    """
    NSO Commit Hook
    
    NSO의 commit 발생을 감지하고 Context를 자동으로 갱신합니다.
    """
    
    def __init__(self, polling_interval: int = 30):
        self.polling_interval = polling_interval
        self.state_file = PROJECT_ROOT / "config" / ".commit_hook_state.json"
        self.state = self._load_state()
        self.running = False
        self._nso_client: Optional[NSOClient] = None
    
    @property
    def nso_client(self) -> NSOClient:
        if self._nso_client is None:
            self._nso_client = NSOClient(
                base_url=settings.nso.base_url,
                username=settings.nso.username,
                password=settings.nso.password
            )
        return self._nso_client
    
    def _load_state(self) -> CommitState:
        """이전 상태 로드"""
        try:
            if self.state_file.exists():
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    return CommitState(**data)
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
        return CommitState()
    
    def _save_state(self):
        """상태 저장"""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump({
                    "last_rollback_count": self.state.last_rollback_count,
                    "last_check_time": self.state.last_check_time,
                    "last_sync_time": self.state.last_sync_time
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def get_rollback_count(self) -> int:
        """
        NSO rollback 파일 수를 조회합니다.
        commit 발생 시 rollback 파일이 증가하므로 이를 통해 변경 감지.
        """
        try:
            # NSO Docker에서 rollback 파일 수 확인
            cmd = [
                'docker', 'exec', 'cisco-nso-dev',
                'bash', '-c',
                'ls /home/developer/ncs-instance/rollbacks/ 2>/dev/null | wc -l'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                count = int(result.stdout.strip())
                return count
            else:
                logger.warning(f"Failed to get rollback count: {result.stderr}")
                return self.state.last_rollback_count
                
        except subprocess.TimeoutExpired:
            logger.error("Timeout getting rollback count")
            return self.state.last_rollback_count
        except Exception as e:
            logger.error(f"Error getting rollback count: {e}")
            return self.state.last_rollback_count
    
    def detect_commit(self) -> bool:
        """
        새로운 commit이 발생했는지 감지합니다.
        """
        current_count = self.get_rollback_count()
        self.state.last_check_time = datetime.utcnow().isoformat()
        
        if current_count > self.state.last_rollback_count:
            logger.info(f"New commit detected! Rollbacks: {self.state.last_rollback_count} -> {current_count}")
            self.state.last_rollback_count = current_count
            self._save_state()
            return True
        
        return False
    
    def refresh_context(self) -> bool:
        """
        generate_context.py를 실행하여 Context를 갱신합니다.
        """
        try:
            logger.info("Refreshing context...")
            
            # generate_context.py 실행
            script_path = PROJECT_ROOT / "scripts" / "generate_context.py"
            
            result = subprocess.run(
                [sys.executable, str(script_path)],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=120  # 2분 타임아웃
            )
            
            if result.returncode == 0:
                self.state.last_sync_time = datetime.utcnow().isoformat()
                self._save_state()
                logger.info("Context refreshed successfully")
                return True
            else:
                logger.error(f"Context refresh failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Context refresh timed out")
            return False
        except Exception as e:
            logger.error(f"Context refresh error: {e}")
            return False
    
    def sync_now(self) -> Dict[str, Any]:
        """
        즉시 동기화를 수행합니다.
        """
        logger.info("Manual sync triggered")
        
        # 현재 rollback 수 업데이트
        self.state.last_rollback_count = self.get_rollback_count()
        
        # Context 갱신
        success = self.refresh_context()
        
        return {
            "success": success,
            "rollback_count": self.state.last_rollback_count,
            "sync_time": self.state.last_sync_time
        }
    
    def run_daemon(self):
        """
        데몬 모드로 실행합니다.
        Polling 방식으로 commit을 감지하고 Context를 갱신합니다.
        """
        logger.info(f"Starting NSO Commit Hook daemon (interval: {self.polling_interval}s)")
        self.running = True
        
        # 시그널 핸들러 설정
        def signal_handler(sig, frame):
            logger.info("Shutdown signal received")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # 초기 상태 설정
        self.state.last_rollback_count = self.get_rollback_count()
        self._save_state()
        logger.info(f"Initial rollback count: {self.state.last_rollback_count}")
        
        while self.running:
            try:
                # Commit 감지
                if self.detect_commit():
                    # 새 commit 감지 시 Context 갱신
                    self.refresh_context()
                
                # 다음 체크까지 대기
                time.sleep(self.polling_interval)
                
            except Exception as e:
                logger.error(f"Daemon loop error: {e}")
                time.sleep(self.polling_interval)
        
        logger.info("NSO Commit Hook daemon stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """현재 상태 반환"""
        return {
            "last_rollback_count": self.state.last_rollback_count,
            "last_check_time": self.state.last_check_time,
            "last_sync_time": self.state.last_sync_time,
            "polling_interval": self.polling_interval
        }


# 싱글톤 인스턴스
_commit_hook: Optional[NSOCommitHook] = None


def get_commit_hook(polling_interval: int = 30) -> NSOCommitHook:
    """NSOCommitHook 싱글톤 반환"""
    global _commit_hook
    if _commit_hook is None:
        _commit_hook = NSOCommitHook(polling_interval)
    return _commit_hook


# MCP 도구용 함수
def trigger_context_sync() -> Dict[str, Any]:
    """
    Context 동기화를 즉시 트리거합니다.
    
    NSO에서 최신 설정을 가져와 Facts를 갱신합니다.
    """
    hook = get_commit_hook()
    return hook.sync_now()


def get_commit_hook_status() -> Dict[str, Any]:
    """
    Commit Hook 상태를 조회합니다.
    """
    hook = get_commit_hook()
    return hook.get_status()


def main():
    parser = argparse.ArgumentParser(description="NSO Commit Hook")
    parser.add_argument(
        "--daemon", "-d",
        action="store_true",
        help="데몬 모드로 실행"
    )
    parser.add_argument(
        "--sync-now", "-s",
        action="store_true",
        help="즉시 동기화 수행"
    )
    parser.add_argument(
        "--interval", "-i",
        type=int,
        default=30,
        help="Polling 간격 (초, 기본: 30)"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="현재 상태 출력"
    )
    
    args = parser.parse_args()
    
    hook = NSOCommitHook(polling_interval=args.interval)
    
    if args.status:
        status = hook.get_status()
        print(json.dumps(status, indent=2))
    elif args.sync_now:
        result = hook.sync_now()
        print(json.dumps(result, indent=2))
    elif args.daemon:
        hook.run_daemon()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
