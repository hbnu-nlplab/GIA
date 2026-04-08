# agents_v2 실행 이슈 정리

## 1. 실행 중 멈춤(hang) 현상

### 증상
`main_netconfig.py` 실행 중 몇 분 이상 진행이 없는 상태로 멈춤.
로그 마지막 줄이 항상 에이전트의 LLM 호출 직후에 위치함.

```
💡 [Agent 3: Synthesizer] Generating Answer...   ← 여기서 멈춤
```

### 원인
`app.invoke(initial_state)` 호출에 타임아웃이 없어서, LLM API가 응답을 주지 않으면
해당 스레드가 무한 대기 상태가 됨. `as_completed()`가 해당 future를 영원히 기다리며
전체 프로세스가 hang.

### 참고: 로그가 무한루프처럼 보이는 이유
`MAX_WORKERS=50`으로 50개 스레드가 동시에 실행되고, 모든 스레드가 공유 stdout(Tee)에
동시에 기록하기 때문에 로그가 뒤섞임. 실제로 루프 카운터 로직은 정상(`>=3`이면 END).

### 해결
`app.invoke()`를 별도 executor로 감싸서 타임아웃 적용 (300초):

```python
from concurrent.futures import ThreadPoolExecutor as _TPE, TimeoutError as _TE
with _TPE(max_workers=1) as _ex:
    _f = _ex.submit(app.invoke, initial_state)
    try:
        out = _f.result(timeout=300)
    except _TE:
        # [TIMEOUT] 결과 반환 후 다음 항목으로 진행
```

**적용 파일**: `main_netconfig.py`의 `process_item()` 함수 (line ~237)

---

## 2. 응답이 느린 원인

### 원인 A: 전체 config를 매번 컨텍스트로 전달 (코드 문제)

| 파일 | 컨텍스트 처리 방식 |
|------|------------------|
| `main.py` (기존) | 질문에 언급된 장비명만 필터링해서 전달 |
| `main_netconfig.py` (현재) | 전체 .cfg 파일 합산해서 항상 전달 |

```python
# main.py - 스마트 필터링
for device_name, config_content in global_context.items():
    if device_name.lower() in q_text.lower():
        found_configs.append(config_content)

# main_netconfig.py - 전체 전달 (문제)
context = "\n".join(global_context.values())
```

장비가 10개면 LLM 호출당 입력 토큰이 최대 10배 증가.

### 원인 B: Thinking 모델 사용 (모델 문제)

| 구분 | 기존 실험 | 현재 실험 |
|------|---------|---------|
| 모델 | gpt-4o-mini, gemini-flash-lite | qwen3-8b, gpt-oss-20b |
| 특징 | 빠른 경량 모델 | qwen3-8b는 thinking 모델 |
| 속도 | 빠름 | `<think>` 블록으로 출력 토큰 수배 증가 |

qwen3-8b는 실제 답변 전에 `<think>...</think>` 내부 추론을 수천 토큰 생성함.
`max_tokens=4096`으로 설정되어 있어 thinking 블록이 길어질수록 응답 지연.

### 원인 C: 과도한 병렬 요청

`MAX_WORKERS=50`으로 50개 스레드가 동시에 LLM API 호출 → OpenRouter rate limit/throttle 발생 가능.

### 원인 D: 항목당 LLM 호출 횟수

```
5 agents × (최대 3 inner loops × 3 outer loops) = 최대 45번 호출
```

최소 5번, 최대 45번 호출이므로 항목 1개 처리에 수 분 소요 가능.

---

## 3. 실험 설계 관련 메모

### 싱글 모델 vs MAS Mixed 비교 시 주의사항

- MAS는 호출 횟수가 많아 비용이 싱글보다 항상 높음
- "비용 효율" 주장은 **MAS all-gpt-oss-20b** vs **MAS mixed** 비교일 때만 성립
- 싱글 모델보다 MAS가 비용 면에서 낫다는 주장은 불가

### 권장 ablation 구성

| 실험 | 구성 | 목적 |
|------|------|------|
| Baseline-Weak | mistral3-8b only | 약한 모델 단독 성능 |
| Baseline-Strong | gpt-oss-20b only | 강한 모델 단독 성능 |
| MAS-Mixed | mistral3-8b + gpt-oss-20b | 제안 방법 |

- qwen3-8b는 thinking 모델로 비용/속도 프로파일이 달라 별도 취급
- 3모델 조합은 현재 코드(MODEL1/MODEL2 두 슬롯)에서 지원 안 됨
