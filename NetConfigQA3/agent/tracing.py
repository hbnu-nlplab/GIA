"""
에이전트 트레이싱 및 디버깅 유틸리티

LangSmith 통합 및 구조화된 로깅
"""
import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def setup_langsmith(project_name: str = "NetConfigQA3-Agent") -> bool:
    """
    LangSmith 트레이싱 활성화
    
    환경변수 필요:
    - LANGCHAIN_API_KEY: LangSmith API 키
    
    Args:
        project_name: LangSmith 프로젝트 이름
        
    Returns:
        True if enabled, False otherwise
    """
    api_key = os.getenv("LANGCHAIN_API_KEY") or os.getenv("LANGSMITH_API_KEY")
    
    if not api_key:
        logger.warning("LANGCHAIN_API_KEY (or LANGSMITH_API_KEY) not set. LangSmith tracing disabled.")
        logger.info("Get your free API key at: https://smith.langchain.com")
        return False
    
    # LangSmith 환경변수 설정 (LANGCHAIN_ 접두사로 통일하여 SDK 호환성 확보)
    os.environ["LANGCHAIN_TRACING_V2"] = os.getenv("LANGCHAIN_TRACING_V2") or os.getenv("LANGSMITH_TRACING") or "true"
    os.environ["LANGCHAIN_API_KEY"] = api_key
    os.environ["LANGCHAIN_PROJECT"] = os.getenv("LANGCHAIN_PROJECT") or os.getenv("LANGSMITH_PROJECT") or project_name
    os.environ["LANGCHAIN_ENDPOINT"] = os.getenv("LANGCHAIN_ENDPOINT") or os.getenv("LANGSMITH_ENDPOINT") or "https://api.smith.langchain.com"
    
    logger.info(f"✅ LangSmith tracing enabled: {project_name}")
    logger.info(f"   View traces at: https://smith.langchain.com")
    
    return True


class StructuredLogger:
    """
    구조화된 JSON 로깅
    
    모든 에이전트 이벤트를 구조화된 형식으로 기록합니다.
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # JSON 로그 파일
        self.json_log_path = self.log_dir / "structured_events.jsonl"
    
    def log_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        이벤트 로깅
        
        Args:
            event_type: 이벤트 타입 (tool_call, llm_request, error 등)
            data: 이벤트 데이터
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            **data
        }
        
        # JSON Lines 형식으로 저장
        with open(self.json_log_path, 'a') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
    
    def log_tool_call(
        self,
        tool_name: str,
        params: Dict[str, Any],
        result: Any,
        duration_ms: float,
        success: bool = True,
        error: Optional[str] = None
    ) -> None:
        """
        도구 호출 로깅
        
        Args:
            tool_name: 도구 이름
            params: 호출 파라미터
            result: 실행 결과
            duration_ms: 실행 시간 (밀리초)
            success: 성공 여부
            error: 에러 메시지 (실패 시)
        """
        self.log_event("tool_call", {
            "tool": tool_name,
            "params": params,
            "result": str(result)[:200] if result else None,  # 결과 축약
            "duration_ms": duration_ms,
            "success": success,
            "error": error
        })
    
    def log_llm_request(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        duration_ms: float,
        cost_usd: Optional[float] = None
    ) -> None:
        """
        LLM 요청 로깅
        
        Args:
            model: 모델 이름
            prompt_tokens: 프롬프트 토큰 수
            completion_tokens: 완성 토큰 수
            duration_ms: 실행 시간
            cost_usd: 비용 (USD)
        """
        self.log_event("llm_request", {
            "model": model,
            "tokens": {
                "prompt": prompt_tokens,
                "completion": completion_tokens,
                "total": prompt_tokens + completion_tokens
            },
            "duration_ms": duration_ms,
            "cost_usd": cost_usd
        })
    
    def log_error(
        self,
        component: str,
        error_type: str,
        message: str,
        traceback: Optional[str] = None
    ) -> None:
        """
        에러 로깅
        
        Args:
            component: 컴포넌트 이름
            error_type: 에러 타입
            message: 에러 메시지
            traceback: 스택 트레이스
        """
        self.log_event("error", {
            "component": component,
            "error_type": error_type,
            "message": message,
            "traceback": traceback
        })
    
    def get_summary(self, last_n_hours: int = 1) -> Dict[str, Any]:
        """
        최근 이벤트 요약
        
        Args:
            last_n_hours: 조회할 시간 (시간)
            
        Returns:
            요약 통계
        """
        if not self.json_log_path.exists():
            return {"error": "No log file"}
        
        from_time = datetime.now().timestamp() - (last_n_hours * 3600)
        
        events = []
        with open(self.json_log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    event_time = datetime.fromisoformat(event['timestamp']).timestamp()
                    if event_time >= from_time:
                        events.append(event)
                except:
                    continue
        
        # 통계 계산
        tool_calls = [e for e in events if e['event_type'] == 'tool_call']
        llm_requests = [e for e in events if e['event_type'] == 'llm_request']
        errors = [e for e in events if e['event_type'] == 'error']
        
        return {
            "period_hours": last_n_hours,
            "total_events": len(events),
            "tool_calls": {
                "count": len(tool_calls),
                "success_rate": sum(1 for t in tool_calls if t.get('success')) / len(tool_calls) * 100 if tool_calls else 0
            },
            "llm_requests": {
                "count": len(llm_requests),
                "total_tokens": sum(t['tokens']['total'] for t in llm_requests if 'tokens' in t)
            },
            "errors": {
                "count": len(errors)
            }
        }


# 전역 인스턴스
_structured_logger: Optional[StructuredLogger] = None


def get_structured_logger() -> StructuredLogger:
    """구조화 로거 싱글톤 반환"""
    global _structured_logger
    if _structured_logger is None:
        _structured_logger = StructuredLogger()
    return _structured_logger


# 편의 함수들
def log_tool_call(tool_name: str, params: Dict, result: Any, duration_ms: float, success: bool = True):
    """도구 호출 로깅 (편의 함수)"""
    get_structured_logger().log_tool_call(tool_name, params, result, duration_ms, success)


def log_error(component: str, error_type: str, message: str):
    """에러 로깅 (편의 함수)"""
    get_structured_logger().log_error(component, error_type, message)
