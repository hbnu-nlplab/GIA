# NetAlly 실험 갭 해결 계획

**작성일:** 2026-03-18
**목표:** Exp.4(Pure MAS) + Exp.5(NetAlly MAS) 실행을 위한 3개 갭 해결
**근거:** 8개 리뷰 에이전트 + 2개 분석 에이전트 결과

---

## 실험 구조 정리

```
Exp.2: Single LLM      → run_eval_vllm_offline.py (이미 완성)
Exp.4: Pure MAS         → NetAlly (도구 없이, MAS 구조만)      ← 갭 해결 필요
Exp.5: NetAlly MAS      → NetAlly (도구 포함, Batfish/NSO)     ← 갭 해결 필요

비교 축:
  Exp.2 vs Exp.4 → "MAS 구조 효과" (Orchestrator+Executor가 도움이 되나?)
  Exp.4 vs Exp.5 → "도구 효과" (Batfish/NSO가 정확도를 얼마나 올리나?)
  Exp.2 vs Exp.5 → "전체 시스템 효과" (논문 핵심 결과)
```

---

## Phase 1: 도구 없는 모드 (Exp.4 지원) — 30분

### Task 1.1: `runtime.py` — TOOL_BACKEND=none 지원
**파일:** `NetAlly/agent/runtime.py`
**위치:** SingleExecutorRuntime.__init__ (tool 로딩 부분)
**수정:**
```python
if self.tool_backend == "none":
    self.tools = []
    self._llm_with_tools = self._llm  # bind_tools 스킵
elif self.tool_backend == "legacy":
    self.tools = get_legacy_tools()
else:
    self.tools = get_core_tools()
```

### Task 1.2: `runtime.py` — 도구 없을 때 프롬프트 조정
**수정:** tools=[]이면 시스템 프롬프트에서 도구 관련 안내 제거
```python
if not self.tools:
    system_prompt = PURE_MAS_PROMPT  # 도구 없이 분석만
else:
    system_prompt = DEFAULT_EXECUTOR_PROMPT
```

### Task 1.3: `main.py` — 환경변수 문서화
`.env.tailscale`에 추가:
```
# Exp.4 (Pure MAS): NETALLY_TOOL_BACKEND=none
# Exp.5 (Full MAS): NETALLY_TOOL_BACKEND=mcp
```

**검증:**
```bash
NETALLY_TOOL_BACKEND=none uv run python -c "
from agent.runtime import SingleExecutorRuntime
rt = SingleExecutorRuntime(tool_backend='none')
print(f'Tools: {len(rt.tools)}')  # → 0
"
```

---

## Phase 2: Eval Runner 연결 (Exp.4+5 배치 실행) — 1일

### Task 2.1: `eval/experiment_runner.py` — 신규 파일
NetAlly `/api/chat`에 배치로 질문 전송, SSE 파싱, 결과 수집.

```python
class ExperimentRunner:
    def __init__(self, base_url="http://localhost:8111"):
        self.base_url = base_url

    async def ask(self, question: str, config_context: str = "") -> EvalResult:
        """단일 질문을 NetAlly에 보내고 답변+도구 사용 정보 수집."""
        payload = {"message": question, "config_context": config_context}
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream("POST", f"{self.base_url}/api/chat", json=payload) as resp:
                answer = ""
                tools_used = []
                latency_ms = 0
                async for line in resp.aiter_lines():
                    event = self._parse_sse(line)
                    if event.type == "tool_call":
                        tools_used.append({"name": event.tool, "args": event.args})
                    elif event.type == "tool_output":
                        # 도구 결과 기록
                    elif event.type == "tool_error":
                        tools_used.append({"name": event.tool, "error": event.error})
                    elif event.type == "answer":
                        answer = event.content
                return EvalResult(
                    answer=answer,
                    tools_used=tools_used,
                    latency_ms=latency_ms,
                )

    async def run_batch(self, dataset_path: str, output_path: str,
                        concurrency: int = 1):
        """데이터셋 전체를 순차 또는 병렬로 실행."""
        dataset = load_dataset(dataset_path)
        results = []
        for i, row in enumerate(dataset):
            result = await self.ask(row["question"])
            results.append({
                "question_id": row["question_id"],
                "question": row["question"],
                "gold": row["answer"],
                "pred": result.answer,
                "level": row["level"],
                "answer_type": row["answer_type"],
                "tools_used": result.tools_used,
                "latency_ms": result.latency_ms,
            })
            if (i+1) % 10 == 0:
                print(f"  Progress: {i+1}/{len(dataset)}")
                save_checkpoint(results, output_path)

        save_results(results, output_path)
```

### Task 2.2: 출력 형식을 analyze_results.py와 호환
**핵심:** `results_raw_vllm_*.json`과 동일한 구조로 출력
```json
{
  "meta": {"model": "...", "backend": "netally_mas", "lab": "Lab-B"},
  "results": [
    {"question_id": "...", "pred": "...", "gold": "...", "level": "L4", "answer_type": "path",
     "tools_used": [{"name": "batfish_traceroute", "args": {...}}]}
  ]
}
```
→ analyze_results.py로 바로 채점 가능!

### Task 2.3: CLI 인터페이스
```bash
# Exp.4 실행 (도구 없음)
NETALLY_TOOL_BACKEND=none python -m eval.experiment_runner \
  --dataset Data/Pnetlab/LabB_.../Dataset/dataset.csv \
  --output results/exp4_pure_mas_labB.json

# Exp.5 실행 (도구 포함)
NETALLY_TOOL_BACKEND=mcp python -m eval.experiment_runner \
  --dataset Data/Pnetlab/LabB_.../Dataset/dataset.csv \
  --output results/exp5_netally_mas_labB.json
```

---

## Phase 3: 관측성 (도구 호출 추적) — 반나절

### Task 3.1: 구조화된 로깅 추가
**파일:** `NetAlly/agent/runtime.py`
**위치:** `_invoke_tool()` 메서드
```python
async def _invoke_tool(self, name, args):
    start = time.monotonic()
    try:
        result = await tool.ainvoke(args)
        elapsed = (time.monotonic() - start) * 1000
        logger.info("TOOL_OK name=%s elapsed_ms=%.1f args=%s", name, elapsed, json.dumps(args)[:200])
        return result
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        logger.error("TOOL_FAIL name=%s elapsed_ms=%.1f error=%s", name, elapsed, str(e))
        return {"error": str(e), "tool": name, "_is_error": True}
```

### Task 3.2: Eval Runner에서 도구 메트릭 집계
```python
# 결과에서 자동 계산
tool_metrics = {
    "tool_call_rate": 호출된_질문수 / 전체_질문수,
    "tool_success_rate": 성공_호출수 / 전체_호출수,
    "avg_latency_ms": 평균_도구_지연,
    "by_level": {
        "L1": {"call_rate": 0.0, ...},
        "L4": {"call_rate": 0.95, ...},
        "L5": {"call_rate": 1.0, ...},
    }
}
```

### Task 3.3: LangSmith 트레이싱 (선택)
```bash
# .env.tailscale에 추가 (선택)
LANGCHAIN_TRACING_V2=true
LANGSMITH_API_KEY=lsv2_pt_xxx
LANGCHAIN_PROJECT=NetAlly-Exp5-LabB
```

---

## 실행 순서 + 의존관계

```
Phase 1 (도구 없는 모드)     ← 독립, 30분
      ↓
Phase 2 (Eval Runner)        ← Phase 1 완료 후, 1일
      ↓
Phase 3 (관측성)              ← Phase 2와 병렬 가능, 반나절

총 예상: 2일
```

## 검증 방법

**Phase 1 완료 후:**
```bash
# 도구 없는 모드 테스트
NETALLY_TOOL_BACKEND=none ./scripts/demo_up_local.sh
# 채팅에서 "P1의 hostname은?" → 도구 호출 없이 답변 확인
```

**Phase 2 완료 후:**
```bash
# Exp.4 소규모 테스트 (10문제)
python -m eval.experiment_runner --limit 10 --output test_exp4.json
# analyze_results.py로 채점
python Experiment/code/NetConfigQA2_2/analyze_results.py test_exp4.json
```

**Phase 3 완료 후:**
```bash
# 도구 호출 로그 확인
grep "TOOL_OK\|TOOL_FAIL" netally.log | head -20
```

---
*2026-03-18 — 10개 에이전트 분석 기반*
