# Evaluation 개선 사항 최종 정리

## 🔧 수정된 파일
- **`Experiment/run_netconfigqa_eval_vllm.py`**

---

## 📊 3가지 핵심 개선

### 1️⃣ max_tokens 2배 증가
```python
# 라인 141
max_tokens=32768  # ← 기존: 16384 (2배 증가!)
```

**왜 필요했는가?**
- 현재: L3/L4 문제에서 76.2%가 truncation으로 인해 오답
- `<think>...</think>` reasoning이 길어서 답변 부분이 잘림
- 32768이면 충분한 thinking + 답변 공간 확보 가능

---

### 2️⃣ System Message 개선 (CoT 활성화)
```python
# 라인 152-174
기존: "NO <think> tags. NO reasoning." ❌
신규: "Use <think>...</think> tags to reason about..." ✅

→ 명확한 WORKFLOW 제시:
   1. <think>에서 분석
   2. </think> 후 바로 답변
   3. 첫 줄에만 답변 (설명 없음)
```

**왜 필요했는가?**
- 복잡한 L3/L4 문제는 reasoning 필수
- 하지만 reasoning 후 답변이 명확하게 구분되어야 함
- 첫 줄에 답변만 있도록 강제

---

### 3️⃣ User Message 구조 개선
```python
# 라인 176-191
기존:
=== ANSWER ===

신규:
=== YOUR RESPONSE ===
<think>
[Analyze the network configuration, trace connections, identify the answer]
</think>

[ANSWER ON FIRST LINE - No other text]
```

**왜 필요했는가?**
- 명확한 템플릿으로 모델이 구조 이해
- Reasoning과 답변 섹션 명확히 분리
- 모델이 일관된 형식으로 답변하도록 유도

---

## 📈 예상 개선 효과

| 메트릭 | 현재 | 목표 | 근거 |
|--------|------|------|------|
| L3 정확도 | 7.7% | 40-50% | Truncation 제거 + CoT 활성화 |
| L4 정확도 | 0.0% | 20-30% | Reasoning 공간 충분함 |
| 전체 Truncation | 76.2% | <5% | max_tokens 2배 |
| 전체 정확도 | ~42% | ~50-55% | 위의 모든 개선 합산 |

---

## 🚀 사용 방법

기존과 동일합니다!

```bash
python Experiment/run_netconfigqa_eval_vllm.py \
  --model "Qwen3-8B" \
  --dataset "Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251224_012740.csv" \
  --config_dir "Data/Pnetlab/Research_Institute_Internal_DC/configs"
```

---

## ✨ 핵심 설계 원칙

> **"모델에게 충분한 시간(토큰)과 명확한 지시를 주면, 복잡한 네트워크 분석도 가능하다"**

### Before (Truncation 문제)
```
토큰: [configs] [question] <think> ... reasoning ... [토큰 소진] ❌
결과: </think> 다음 답변이 잘림
```

### After (개선된 구조)
```
토큰: [configs] [question] <think> ... 충분한 reasoning ... </think> [답변] ✅
결과: 전체 reasoning + 완전한 답변 보존
```

---

## 📝 검증 항목

다음 실행 후 확인할 사항:

1. ✅ Truncation 비율 감소 (76% → <5%)
2. ✅ 빈 pred 감소 (76% → <5%)
3. ✅ L3 정확도 증가 (7.7% → 40%+)
4. ✅ L4 정확도 증가 (0% → 20%+)
5. ✅ raw_pred가 완전한 reasoning + 답변 포함
6. ✅ 답변이 명확하게 구분됨 (</think> 다음 첫 줄)

