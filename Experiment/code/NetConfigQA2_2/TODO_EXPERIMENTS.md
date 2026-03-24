# 실험 할 일 정리 (2026-03-24)

> 목표 저널: IEEE TNSE
> 마감: 목요일 (2026-03-27)

## 모델 세트: 기존 통신학회 모델 유지!

| # | 모델 | 비고 |
|---|------|------|
| 1 | GPT-4o-mini | API |
| 2 | Llama-3.1-8B | 로컬 |
| 3 | Mistral3-8B | 로컬 |
| 4 | Qwen3-8B | 로컬 |
| 5 | GPT-OSS-20B | 로컬 |

**새 모델(Qwen3.5-9B 등)이 아님!** 기존 모델로 해야 통신학회 결과와 비교 가능.

## 내가 할 것 (유진)

### 1. 기존 모델 × 확장 벤치마크 (Single LLM)
- **뭘**: 5개 모델 × 4 Lab (LabA/B/C/D)
- **데이터셋**: 확장 NetConfigQA (9,462 QA)
- **목적**: 기존 벤치마크 대비 변별력 향상 증명
- **실행**: `run_eval_vllm_offline.py`
- **상태**: ⏳

### 2. MAS + MCP (NetAlly)
- **뭘**: Best 모델로 NetAlly 평가
- **데이터셋**: 확장 NetConfigQA
- **목적**: MAS가 도구를 활용하여 시뮬레이션 장벽 완화
- **상태**: ⏳ (팀원 MAS 실험 후 진행)

### 3. Ablation: Single LLM + MCP
- **뭘**: Best 모델 + Batfish/NSO 도구 직접 연결 (MAS 구조 없이)
- **데이터셋**: Lab-D만 (가장 어려운)
- **목적**: "도구만으로 충분한가?" → MAS 구조 필요성 증명
- **상태**: ⏳

## 팀원이 할 것 (현정)

### 4. MAS (도구 없음)
- 확장 벤치마크에 NetAgent(debate MAS) 적용
- 기존 모델로

### 5. 논문 실험 흐름 정리

## 실험 스토리

```
통신학회: 기존 벤치마크 + 기존 모델 → 변별력 낮음
  ↓ 비교
확장 벤치마크 + 기존 모델 → 변별력 생김 (1번 실험)
  ↓
MAS 구조만으로도 향상 (4번, 팀원)
  ↓
MAS + MCP가 가장 좋음 (2번)
  ↓
도구만으로는 부족 (3번, Ablation)
```

## 새 모델 결과 (보관)

results/ 폴더에 이미 있음. 논문에는 미사용, 추후 확장 실험용:
- Qwen3.5-9B, GPT-OSS-20B, Nemotron-Cascade, Qwen3-Coder, Qwen3.5-4B, Foundation-Sec-8B

## 참고

- GPU: NVIDIA A5000 (vLLM)
- 조건: zero-shot, temperature=0, num_ctx=49,152
- 평가: `analyze_results.py` (TA-Acc)
- 실험 스토리라인 상세: `NetAlly/docs/IEEE/experiment_storyline.md`
