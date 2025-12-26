# NetConfigQA Evaluation 개선 사항

## 📅 날짜: 2024-12-24

## 🔍 문제 분석 결과

### L3/L4 문제의 오답 원인
- **Truncation (토큰 제한)**: 76.2% (32/42개)
  - 모델이 `<think>` 태그 내에서 reasoning을 수행하다가 `max_tokens` 도달
  - 답변을 출력하기 전에 토큰이 소진됨
  
- **형식/내용 오류**: 22% (9/42개)
  - 실제로 분석을 잘못한 경우

### 레벨별 성능
- **L3**: 1/13 (7.7%)
- **L4**: 0/29 (0.0%)

---

## ✅ 적용된 개선 사항

### 1. `max_tokens` 증가
**파일**: `Experiment/run_netconfigqa_eval_vllm.py`

```python
# 변경 전
max_tokens=16384  # Increased to handle complex L4/L5 questions

# 변경 후
max_tokens=32768  # INCREASED: was 16384, now 32768 to prevent truncation during <think>
```

**효과**:
- Reasoning 단계에서 토큰 부족으로 인한 truncation 제거
- L3/L4 복잡한 네트워크 분석 가능

---

### 2. 프롬프트 개선 - System Message

**변경 전** (비활성화된 CoT):
```
You are a Network Engineer. Answer ONLY with the final value.

CRITICAL RULES:
1. NO <think> tags. NO reasoning. NO explanation. ONLY the answer.
2. Output the answer value DIRECTLY in the requested format.
```

**변경 후** (활성화된 CoT with 명확한 워크플로우):
```
You are an expert Network Engineer. Your task is to analyze network configurations and provide precise answers.

WORKFLOW (CRITICAL):
1. Use <think>...</think> tags to reason about the network structure, device connections, and configurations.
2. Inside <think> tags: Analyze the configuration, trace the connections, identify key information.
3. After closing </think>, IMMEDIATELY provide ONLY the final answer in the exact format requested.
4. Do NOT include any explanation, preamble, or additional text after the answer.

CRITICAL: Provide the answer on the FIRST line after </think> with NO other text.
```

**효과**:
- 모델이 reasoning 후 명확하게 답변 구분
- `</think>` 다음 첫 줄에만 답변 작성하도록 강제
- Thinking 공간 충분히 확보

---

### 3. 프롬프트 개선 - User Message

**변경 전**:
```
=== QUESTION ===
{question}

=== EXPECTED ANSWER TYPE ===
{answer_type}

=== ANSWER ===
```

**변경 후**:
```
=== QUESTION ===
{question}

=== EXPECTED ANSWER TYPE ===
{answer_type}

=== YOUR RESPONSE ===
<think>
[Analyze the network configuration, trace connections, identify the answer]
</think>

[ANSWER ON FIRST LINE - No other text]
```

**효과**:
- 명확한 구조로 `<think>` 섹션과 답변 섹션 분리
- 모델이 두 섹션을 명확히 구분하도록 유도
- 템플릿 제공으로 일관된 답변 형식 보장

---

## 🎯 기대 효과

| 메트릭 | 현재 | 예상 개선 |
|--------|------|----------|
| L3 정확도 | 7.7% | 40-50% (Truncation 제거) |
| L4 정확도 | 0.0% | 20-30% (Reasoning 공간 확보) |
| Truncation 비율 | 76.2% | <5% (max_tokens 2배 증가) |
| 전체 정확도 | ~40% | ~50-55% |

---

## 📋 다음 단계

1. **평가 재실행**: 수정된 코드로 다시 evaluation 실행
2. **결과 비교**: 기존 결과와 신규 결과 비교 분석
3. **추가 최적화**: 필요시 모델 크기 증가 또는 few-shot 예시 추가

---

## 💡 주요 인사이트

> **"모델이 몰라서 틀린 게 아니라, 토큰이 부족해서 못 낸 답변!"**

- Qwen3는 CoT(Chain-of-Thought)에서 매우 강력함
- Reasoning 공간만 충분하면 복잡한 네트워크 분석 가능
- Max_tokens는 전체 시퀀스를 포함하므로, reasoning이 길면 답변이 잘릴 수 있음

