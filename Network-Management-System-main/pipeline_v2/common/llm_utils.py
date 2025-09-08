from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from io import StringIO
import sys
import json
import os
import time
import random
import threading
from collections import defaultdict

from openai import OpenAI, RateLimitError


class ExperimentLogger:
    """실험 로그/결과/LLM 호출 내역을 구조적으로 관리"""

    def __init__(self, experiment_name: str, base_dir: str = "experiment_results"):
        self.experiment_name = experiment_name
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = Path(base_dir)

        # 디렉토리 구성 - base_dir을 직접 사용 (추가 타임스탬프 폴더 생성하지 않음)
        self.exp_dir = self.base_dir
        self.logs_dir = self.exp_dir / "logs"
        self.results_dir = self.exp_dir / "results"
        self.llm_history_dir = self.exp_dir / "llm_history"
        self.console_dir = self.exp_dir / "console_output"
        for d in [self.exp_dir, self.logs_dir, self.results_dir, self.llm_history_dir, self.console_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self.console_buffer = StringIO()
        self.original_stdout = sys.stdout
        self.llm_calls: List[Dict] = []
        
        # 질문별 ID 추적
        self.current_question_id: Optional[int] = None
        self.question_call_counters: Dict[int, Dict[str, int]] = {}

        print(f"[INFO] Experiment '{experiment_name}' initialized")
        print(f"[INFO] Results dir: {self.exp_dir}")

    # 콘솔 캡처
    def start_console_capture(self):
        sys.stdout = self.console_buffer

    def stop_console_capture(self):
        sys.stdout = self.original_stdout
        content = self.console_buffer.getvalue()
        if content:
            out_file = self.console_dir / f"console_{self.timestamp}.txt"
            out_file.write_text(content, encoding="utf-8")
            print(f"[INFO] Console output saved to: {out_file}")
        self.console_buffer = StringIO()

    # 질문 ID 관리
    def set_current_question_id(self, question_id: int):
        """현재 처리 중인 질문 ID 설정"""
        self.current_question_id = question_id
        if question_id not in self.question_call_counters:
            self.question_call_counters[question_id] = {}

    # 저장/로깅
    def log_llm_call(
        self,
        call_type: str,
        prompt: str,
        response: str,
        model: str = "gpt-4o-mini",
        metadata: Optional[Dict] = None,
    ) -> None:
        rec = {
            "timestamp": datetime.now().isoformat(),
            "call_type": call_type,
            "model": model,
            "prompt": prompt,
            "response": response,
            "metadata": metadata or {},
            "question_id": self.current_question_id,
        }
        self.llm_calls.append(rec)
        
        # 질문별 파일 네이밍
        if self.current_question_id is not None:
            question_id = self.current_question_id
            # 같은 질문 내에서 call_type별 순번 관리
            if call_type not in self.question_call_counters[question_id]:
                self.question_call_counters[question_id][call_type] = 0
            self.question_call_counters[question_id][call_type] += 1
            
            call_num = self.question_call_counters[question_id][call_type]
            if call_num > 1:
                # 같은 타입이 여러 번 호출되는 경우 순번 추가
                call_file = self.llm_history_dir / f"q{question_id:03d}_{call_type}_{call_num}.json"
            else:
                # 첫 번째 호출은 순번 없이
                call_file = self.llm_history_dir / f"q{question_id:03d}_{call_type}.json"
        else:
            # fallback to old naming
            call_file = self.llm_history_dir / f"llm_call_{len(self.llm_calls):03d}_{call_type}.json"
            
        call_file.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    def save_detailed_log(self, log_data: List[Dict], filename: str | None = None):
        if not filename:
            filename = f"detailed_log_{self.timestamp}.json"
        path = self.logs_dir / filename
        path.write_text(json.dumps(log_data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[INFO] Detailed log saved: {path}")

    def save_results(self, results: Dict, filename: str | None = None):
        if not filename:
            filename = f"results_{self.timestamp}.json"
        path = self.results_dir / filename
        path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[INFO] Results saved: {path}")

    def save_llm_history_summary(self):
        stats: Dict[str, Dict] = {}
        for c in self.llm_calls:
            t = c["call_type"]
            stats.setdefault(t, {"count": 0, "total_prompt_length": 0, "total_response_length": 0})
            stats[t]["count"] += 1
            stats[t]["total_prompt_length"] += len(c["prompt"]) if c.get("prompt") else 0
            stats[t]["total_response_length"] += len(c["response"]) if c.get("response") else 0
        summary = {
            "total_calls": len(self.llm_calls),
            "call_types": list(stats.keys()),
            "statistics": stats,
            "first_call": self.llm_calls[0]["timestamp"] if self.llm_calls else None,
            "last_call": self.llm_calls[-1]["timestamp"] if self.llm_calls else None,
        }
        path = self.llm_history_dir / f"llm_history_summary_{self.timestamp}.json"
        path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[INFO] LLM history summary saved: {path}")

    def finalize_experiment(self):
        self.stop_console_capture()
        self.save_llm_history_summary()
        meta = {
            "experiment_name": self.experiment_name,
            "timestamp": self.timestamp,
            "total_llm_calls": len(self.llm_calls),
            "directories": {
                "base": str(self.exp_dir),
                "logs": str(self.logs_dir),
                "results": str(self.results_dir),
                "llm_history": str(self.llm_history_dir),
                "console": str(self.console_dir),
            },
        }
        (self.exp_dir / "experiment_metadata.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print("=" * 70)
        print(f"Experiment '{self.experiment_name}' complete → {self.exp_dir}")
        print("=" * 70)


class MultiKeyOpenAIClient:
    """다중 API 키를 사용한 스마트 로드 밸런싱 OpenAI 클라이언트"""
    
    def __init__(self, api_keys: List[str]):
        if not api_keys:
            raise ValueError("❌ API 키가 하나도 제공되지 않았습니다")
        
        self.api_keys = api_keys
        self.clients = [OpenAI(api_key=key) for key in api_keys]
        
        # 각 키별 상태 추적
        self.key_stats = defaultdict(lambda: {
            'total_calls': 0,
            'rate_limited': 0,
            'last_rate_limit': 0,
            'avg_response_time': 0.0,
            'error_count': 0
        })
        
        # Round-robin 인덱스
        self.current_index = 0
        self.lock = threading.Lock()
        
        print(f"🔄 MultiKey 클라이언트 초기화: {len(api_keys)}개 키")
    
    def _get_next_client(self) -> tuple[OpenAI, int]:
        """다음 사용할 클라이언트와 인덱스 반환 (스마트 선택)"""
        with self.lock:
            current_time = time.time()
            
            # 1. Rate limit이 최근에 걸린 키들 제외 (5분 이내)
            available_indices = []
            for i, key in enumerate(self.api_keys):
                last_rate_limit = self.key_stats[key]['last_rate_limit']
                if current_time - last_rate_limit > 300:  # 5분 = 300초
                    available_indices.append(i)
            
            if not available_indices:
                # 모든 키가 rate limit에 걸렸다면, 전체 키 중에서 선택
                available_indices = list(range(len(self.api_keys)))
                print("⚠️ 모든 키가 최근 rate limit에 걸렸습니다. 가장 오래된 키 사용...")
            
            # 2. 에러가 가장 적은 키 우선 선택
            best_index = min(available_indices, 
                           key=lambda i: self.key_stats[self.api_keys[i]]['error_count'])
            
            # 3. Round-robin으로 분산 (동일 에러 수인 경우)
            if len(available_indices) > 1:
                self.current_index = (self.current_index + 1) % len(available_indices)
                best_index = available_indices[self.current_index]
            
            return self.clients[best_index], best_index
    
    def _update_stats(self, key_index: int, success: bool, response_time: float, was_rate_limited: bool = False):
        """키별 통계 업데이트"""
        key = self.api_keys[key_index]
        stats = self.key_stats[key]
        
        stats['total_calls'] += 1
        if was_rate_limited:
            stats['rate_limited'] += 1
            stats['last_rate_limit'] = time.time()
        
        if not success:
            stats['error_count'] += 1
        
        # 이동 평균으로 응답 시간 계산
        if stats['avg_response_time'] == 0:
            stats['avg_response_time'] = response_time
        else:
            stats['avg_response_time'] = (stats['avg_response_time'] * 0.9) + (response_time * 0.1)
    
    def chat_completions_create(self, **kwargs):
        """다중 키로 chat completions 요청"""
        max_retries = len(self.api_keys) * 2  # 모든 키를 2번씩 시도
        
        for attempt in range(max_retries):
            client, key_index = self._get_next_client()
            start_time = time.time()
            
            try:
                response = client.chat.completions.create(**kwargs)
                response_time = time.time() - start_time
                self._update_stats(key_index, True, response_time)
                
                # 성공 로깅
                key_suffix = self.api_keys[key_index][-8:]  # 마지막 8자리만
                if attempt > 0:  # 재시도 후 성공인 경우에만 로그
                    print(f"✅ API 호출 성공 (키: ...{key_suffix}, 재시도: {attempt}, 시간: {response_time:.2f}s)")
                
                return response
                
            except RateLimitError as e:
                response_time = time.time() - start_time
                self._update_stats(key_index, False, response_time, was_rate_limited=True)
                
                key_suffix = self.api_keys[key_index][-8:]
                print(f"⚠️ Rate limit (키: ...{key_suffix}) - 다른 키로 재시도... ({attempt+1}/{max_retries})")
                
                # Rate limit인 경우 바로 다른 키로 시도
                continue
                
            except Exception as e:
                response_time = time.time() - start_time
                self._update_stats(key_index, False, response_time)
                
                key_suffix = self.api_keys[key_index][-8:]
                print(f"❌ API 오류 (키: ...{key_suffix}): {str(e)[:100]}...")
                
                # 마지막 시도가 아니면 계속
                if attempt < max_retries - 1:
                    time.sleep(min(2 ** (attempt // len(self.api_keys)), 10))  # 지수 백오프 (최대 10초)
                    continue
                else:
                    raise e
        
        raise Exception(f"모든 API 키 ({len(self.api_keys)}개)에서 요청 실패")
    
    def print_stats(self):
        """각 키별 사용 통계 출력"""
        print("\n📊 API 키별 사용 통계:")
        print("-" * 80)
        print("키 (마지막8자)  | 호출수 | Rate제한 | 에러수 | 평균응답시간 | 상태")
        print("-" * 80)
        
        current_time = time.time()
        for i, key in enumerate(self.api_keys):
            stats = self.key_stats[key]
            key_suffix = key[-8:]
            
            # 상태 표시
            if current_time - stats['last_rate_limit'] < 300:
                status = "🔴 제한중"
            elif stats['error_count'] > stats['total_calls'] * 0.1:
                status = "🟡 불안정"
            else:
                status = "🟢 정상"
            
            print(f"...{key_suffix}        | {stats['total_calls']:6d} | {stats['rate_limited']:8d} | {stats['error_count']:6d} | {stats['avg_response_time']:10.2f}s | {status}")
        
        print("-" * 80)


class TrackedOpenAIClient:
    """LLM 호출 로깅을 추가한 OpenAI 클라이언트 (다중 키 지원)"""

    def __init__(self, logger: ExperimentLogger):
        from config import OPENAI_API_KEYS
        
        if len(OPENAI_API_KEYS) > 1:
            self.client = MultiKeyOpenAIClient(OPENAI_API_KEYS)
            self.is_multi_key = True
            print(f"🚀 다중 키 모드 활성화: {len(OPENAI_API_KEYS)}개 키")
        else:
            self.client = OpenAI(api_key=OPENAI_API_KEYS[0])
            self.is_multi_key = False
            print(f"🔑 단일 키 모드")
        
        self.logger = logger
        self.call_count = 0

    def chat_completions_create(self, call_type: str, **kwargs):
        self.call_count += 1
        
        # 메시지 포맷팅
        messages = kwargs.get("messages", [])
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])

        # API 호출
        # OpenAI chat.completions는 metadata 인자를 지원하지 않으므로 제거
        forwarded_kwargs = dict(kwargs)
        if "metadata" in forwarded_kwargs:
            forwarded_kwargs.pop("metadata", None)
        if self.is_multi_key:
            # 다중 키 사용
            resp = self.client.chat_completions_create(**forwarded_kwargs)
        else:
            # 단일 키 사용 (기존 방식)
            resp = self.client.chat.completions.create(**forwarded_kwargs)
        
        # 응답 추출
        text = resp.choices[0].message.content if resp.choices else ""
        
        # 메타데이터 생성
        meta = {
            "model": kwargs.get("model", "unknown"),
            "temperature": kwargs.get("temperature", "unknown"),
            "prompt_tokens": len(prompt.split()) if prompt else 0,
            "response_tokens": len(text.split()) if text else 0,
            "multi_key_mode": self.is_multi_key,
            "total_api_calls": self.call_count
        }
        # 외부에서 전달된 메타데이터 병합(컨텍스트 추적 등 디버깅용)
        try:
            extra = kwargs.get("metadata")
            if isinstance(extra, dict):
                # 문자열화로 JSON 직렬화 안전 보장
                safe_extra = {}
                for k, v in extra.items():
                    try:
                        safe_extra[str(k)] = v if isinstance(v, (str, int, float, bool, type(None))) else str(v)
                    except Exception:
                        safe_extra[str(k)] = str(v)
                meta.update(safe_extra)
        except Exception:
            pass
        
        # 로깅
        self.logger.log_llm_call(call_type, prompt, text, kwargs.get("model", "unknown"), meta)
        
        return resp
    
    def print_summary(self):
        """사용 요약 출력"""
        print(f"\n📈 전체 API 호출 수: {self.call_count}")
        if self.is_multi_key:
            self.client.print_stats()
