# NetConfigQA 2.0 + NetAlly 전체 실험 결과 요약

> 최종 수정: 2026-04-10
> 채점 기준: TA-Acc (Type-Aware Accuracy)
> Scorer: analyze_results.py (None/N/A 통일, config prefix strip, 한국어 정규화 포함)

---

## 1. 한눈에 보는 결론

- **Single LLM 전체 1위**: Mistral3-8B (평균 TA-Acc 36.42%)
- **MCP 도구 추가 시 최고**: Single+MCP Mistral3-8B (Lab B 82.65%)
- **MCP 기여**: +40.37%p (42.28 → 82.65)
- **핵심 발견**: L4(시뮬레이션), L5(What-If)는 도구 없이 불가능 (Single LLM 평균 L4=15.85%, L5=12.13%)

---

## 2. Single LLM 결과 (도구 없음, config 텍스트만)

> 출처: `paper_summary_20260331_112207.md` (전체 데이터셋, 4 Labs 완료)

### 2-1. 모델 순위 (4개 Lab 평균)

| 순위 | 모델 | Params | 평균 TA-Acc | 평균 L4 | 평균 L5 |
|:----:|------|-------:|----------:|-------:|-------:|
| 1 | Mistral3-8B | 8B | **36.42%** | 15.85% | 12.13% |
| 2 | GPT-OSS-20B | 20B | 36.06% | 12.62% | 13.20% |
| 3 | Qwen3-8B | 8B | 32.59% | 11.19% | 11.52% |
| 4 | GPT-4o-mini | 8B* | 32.33% | 15.62% | 5.87% |
| 5 | Llama-3.1-8B | 8B | 20.19% | 5.93% | 6.00% |

### 2-2. Lab별 TA-Acc (%)

| 모델 | Lab A | Lab B | Lab C | Lab D | 평균 |
|------|------:|------:|------:|------:|----:|
| Mistral3-8B | 43.38 | **42.28** | **33.33** | **26.70** | **36.42** |
| GPT-OSS-20B | **46.99** | 41.54 | 31.51 | 24.19 | 36.06 |
| Qwen3-8B | 41.11 | 38.42 | 28.92 | 21.92 | 32.59 |
| GPT-4o-mini | 39.43 | 39.02 | 28.56 | 22.32 | 32.33 |
| Llama-3.1-8B | 23.30 | 25.23 | 17.78 | 14.48 | 20.19 |

### 2-3. 각 Lab에서 가장 잘한 모델

| Lab | 최고 모델 | TA-Acc |
|-----|----------|------:|
| Lab A | GPT-OSS-20B | 46.99% |
| Lab B | Mistral3-8B | 42.28% |
| Lab C | Mistral3-8B | 33.33% |
| Lab D | Mistral3-8B | 26.70% |

---

## 3. MCP 도구 추가 실험 (Lab B, 2,157문제 전체)

### 3-1. 시스템별 비교

| 시스템 | MAS | MCP | 모델 | TA-Acc | 시간/q | 총 시간 |
|--------|:---:|:---:|------|------:|------:|-------:|
| Single LLM | | | Mistral3-8B | 42.28% | ~1s | ~36min |
| Single+MCP | | O | gpt-oss-20b | 60.94% | 7.6s | 4.6h |
| MAS+MCP† | O | O | Mistral3-8B | 72.85% | 7.6s | 4.6h |
| **Single+MCP** | | **O** | **Mistral3-8B** | **82.65%** | **2.4s** | **1.4h** |

> †MAS+MCP는 cfg 도구 미포함 버전. cfg 도구 포함하여 재실행 필요.

### 3-2. 레벨별 상세 비교 (Lab B)

| Level | 문제 수 | Single LLM | Single+MCP (oss-20b) | MAS+MCP† | Single+MCP (Mistral) |
|-------|------:|----------:|---------:|---------:|-------------------:|
| L1 Fact Extraction | 1,274 | 42.28%* | 64.04% | 64.48% | **80.81%** |
| L2 Aggregation | 57 | 42.28%* | 50.29% | **91.23%** | **91.23%** |
| L3 Cross-Comparison | 255 | 42.28%* | 43.14% | 80.00% | **82.48%** |
| L4 Simulation | 443 | 42.28%* | 64.11% | **88.26%** | **88.26%** |
| L5 What-If | 128 | 42.28%* | 59.38% | **80.47%** | 78.12% |
| **전체** | **2,157** | **42.28%** | **60.94%** | **72.85%** | **82.65%** |

> *Single LLM은 Lab B 전체 평균만 있고, 레벨별 수치는 Mistral3-8B 기준 추정치가 아닌 전체 평균.
> †MAS+MCP는 cfg 도구 미포함 버전.

### 3-3. MCP 도구 기여 분석

| 비교 | 차이 | 의미 |
|------|-----:|------|
| Single LLM → Single+MCP | **+40.37%p** | MCP 도구의 핵심 기여 |
| Single+MCP → MAS+MCP† | 비교 불가 | MAS+MCP에 cfg 도구 미포함 |
| Mistral3-8B vs gpt-oss-20b (Single+MCP) | **+21.71%p** | instruction following 차이 |

---

## 4. 모델 비교: Single+MCP (Lab B, 2,157문제)

| 모델 | Params | L1 | L2 | L3 | L4 | L5 | 전체 | 속도 |
|------|------:|----:|----:|----:|----:|----:|-----:|-----:|
| **Mistral3-8B** | 8B | **80.8** | **91.2** | **82.5** | **88.3** | **78.1** | **82.7%** | 2.4s/q |
| gpt-oss-20b | 20B | 64.0 | 50.3 | 43.1 | 64.1 | 59.4 | 60.9% | 7.6s/q |

**gpt-oss-20b가 낮은 원인:**
- cfg 도구에 과의존 (L1에서 cfg 825회 vs Mistral의 10회)
- NSO 구조화 도구를 잘 활용하지 못함
- 값 추출 시 empty/N/A 답변 다수 (L1에서 44%가 empty)

---

## 5. 도구 사용 통계 (Single+MCP Mistral3-8B, sampled 100문제)

| Level | 평균 도구/q | 주요 도구 (사용률) |
|-------|----------:|------------------|
| L1 | 1.2 | cfg (50%), nso_get_device_info (45%) |
| L2 | 1.2 | nso_get_all_device_info (76%), cfg (24%) |
| L3 | 2.8 | cfg (75%), nso (16%), batfish_bgp (9%) |
| L4 | 1.1 | batfish_traceroute (90%) |
| L5 | 2.1 | nso_all_device_info + batfish_failure |
| **전체** | **1.7** | **NSO(L1-L2), cfg(L1-L3), Batfish(L4-L5)** |

**도구 선택 전략 (Collector 자동 선택):**
- L1-L2: NSO(구조화 JSON) + cfg(원문 보완) 혼합
- L3: cfg(원문 비교) 위주 — cross-device 비교에 원문이 정확
- L4: Batfish traceroute 단독 — 시뮬레이션 필수
- L5: NSO(토폴로지 파악) + Batfish(장애 시뮬레이션) 조합

---

## 6. 효율성 비교

| 시스템 | 모델 | TA-Acc | 시간/q | LLM 호출/q | 토큰/q |
|--------|------|------:|------:|---------:|------:|
| Single LLM | Mistral3-8B | 42.28% | ~1s | 1 | ~2K |
| **Single+MCP** | **Mistral3-8B** | **82.65%** | **2.4s** | **2.0** | **4.6K** |
| MAS+MCP† | Mistral3-8B | 72.85% | 7.6s | 5.8 | 10.9K |
| Single+MCP | gpt-oss-20b | 60.94% | 7.6s | 2.0 | ~8K |

---

## 7. 주요 Findings

1. **MCP 도구가 핵심 기여**: Single LLM 42% → Single+MCP 83% (+40%p)
2. **L4-L5에서 도구 필수**: Single LLM L4≈16%, L5≈12% → Single+MCP L4=88%, L5=78%
3. **cfg 도구 효과**: NSO만 사용 시 L1=64%, cfg 추가 시 L1=81% (+17%p)
4. **모델 크기 ≠ 성능**: Mistral3-8B(83%) > gpt-oss-20b(61%), instruction following이 중요
5. **도구 선택 자동화**: Collector가 질문 유형에 따라 cfg/NSO/Batfish를 자동 선택
6. **효율성**: Single+MCP는 LLM 2회 호출, 2.4s/q로 +40%p 성능 향상 — 실용적

---

## 8. 실험 진행 상태

### ✅ 완료

| 실험 | 모델 | Lab | 문제 수 | TA-Acc |
|------|------|-----|------:|------:|
| Single LLM | Mistral3-8B | A,B,C,D | 전체 | 36.42% (avg) |
| Single LLM | GPT-OSS-20B | A,B,C,D | 전체 | 36.06% (avg) |
| Single LLM | Qwen3-8B | A,B,C,D | 전체 | 32.59% (avg) |
| Single LLM | GPT-4o-mini | A,B,C,D | 전체 | 32.33% (avg) |
| Single LLM | Llama-3.1-8B | A,B,C,D | 전체 | 20.19% (avg) |
| Single+MCP | Mistral3-8B | B | 2,157 | **82.65%** |
| Single+MCP | gpt-oss-20b | B | 2,157 | 60.94% |
| MAS+MCP† | Mistral3-8B | B | 2,157 | 72.85% |

### 📐 다음 단계

- [ ] MAS+MCP Mistral3-8B (cfg 도구 포함) Lab B 재실행
- [ ] Single+MCP Mistral3-8B Lab A, C, D
- [ ] MAS+MCP Mistral3-8B Lab A, C, D
- [ ] Pure MAS (도구 없음) Lab A-D — 팀원 담당
- [ ] Phase 2 모델 ablation (Lab D only)

---

## 참고: 결과 파일 경로

| 실험 | 파일 |
|------|------|
| Single LLM 전체 | `Experiment/code/NetConfigQA2_2/paper_summary_20260331_112207.md` |
| MAS+MCP Mistral3-8B (cfg 없음) | `NetAlly/results/netally_eval_direct_Dataset_20260403_221504.json` |
| MAS+MCP Mistral3-8B L1 재실행 | `NetAlly/results/netally_eval_direct_Dataset_20260404_101640.json` |
| Single+MCP Mistral3-8B v2 | `NetAlly/results/netally_eval_direct_Dataset_20260405_200454.json` |
| Single+MCP gpt-oss-20b | `NetAlly/results/netally_eval_direct_Dataset_20260405_213805.json` |

---
*Single LLM 데이터 출처: aggregate_paper_results.py*
*MCP 실험 데이터: run_netally_eval_direct.py + analyze_results.py*
