# NetAlly MCP 실험 결과 요약

> 생성 시각: 2026-04-10
> 채점 기준: TA-Acc (Type-Aware Accuracy)
> 데이터셋: Lab B (LabB_NCN_Basic_SP_20nodes), 2,157문제 전체
> Scorer: analyze_results.py (None/N/A 통일, config prefix strip, 한국어 정규화 포함)

---

## 1. 한눈에 보는 결론

| 시스템 | 모델 | TA-Acc | 비고 |
|--------|------|------:|------|
| Single LLM (best) | Mistral3-8B | 42.28% | 도구 없음, config 텍스트만 |
| Single+MCP | gpt-oss-20b | 60.94% | 도구 있음, debate 없음 |
| MAS+MCP | Mistral3-8B | 72.85% | 도구 있음 (cfg 도구 미포함), 5-agent debate |
| **Single+MCP** | **Mistral3-8B** | **82.65%** | **도구 있음 (cfg 포함), debate 없음** |

- MCP 도구 기여: +40.37%p (42.28 → 82.65)
- 최고 성능: Single+MCP Mistral3-8B (82.65%)

## 2. 레벨별 상세 (Lab B, 2,157문제)

### Single+MCP Mistral3-8B (최고 성능)

| Level | 문제 수 | TA-Acc | 주요 도구 |
|-------|------:|------:|----------|
| L1 Fact Extraction | 1,274 | 80.81% | cfg + nso_get_device_info |
| L2 Aggregation | 57 | 91.23% | nso_get_all_device_info |
| L3 Cross-Comparison | 255 | 82.48% | cfg + batfish_bgp_sessions |
| L4 Simulation | 443 | 88.26% | batfish_traceroute |
| L5 What-If | 128 | 78.12% | batfish_multi_link_failure + nso |
| **전체** | **2,157** | **82.65%** | |

### MAS+MCP Mistral3-8B (cfg 도구 미포함)

| Level | 문제 수 | TA-Acc | 비고 |
|-------|------:|------:|------|
| L1 | 1,274 | 64.48% | cfg 도구 없어서 낮음 |
| L2 | 57 | 91.23% | Single+MCP와 동일 |
| L3 | 255 | 80.00% | debate 효과 (+debate, -cfg) |
| L4 | 443 | 88.26% | 동일 |
| L5 | 128 | 80.47% | debate 효과 (+2.35%p) |
| **전체** | **2,157** | **72.85%** | cfg 도구 포함 시 재실행 필요 |

### Single+MCP gpt-oss-20b

| Level | 문제 수 | TA-Acc | 비고 |
|-------|------:|------:|------|
| L1 | 1,274 | 64.04% | cfg에 과의존, 값 추출 실패 다수 |
| L2 | 57 | 50.29% | NSO 안 쓰고 cfg만 사용 |
| L3 | 255 | 43.14% | instruction following 약함 |
| L4 | 443 | 64.11% | Batfish 사용하지만 해석 부족 |
| L5 | 128 | 59.38% | 한국어 출력 + 형식 오류 |
| **전체** | **2,157** | **60.94%** | |

## 3. 모델 비교 (Single+MCP)

| 모델 | Params | L1 | L2 | L3 | L4 | L5 | 전체 | 속도 |
|------|------:|----:|----:|----:|----:|----:|-----:|-----:|
| **Mistral3-8B** | 8B | **80.8** | **91.2** | **82.5** | **88.3** | **78.1** | **82.7** | 2.4s/q |
| gpt-oss-20b | 20B | 64.0 | 50.3 | 43.1 | 64.1 | 59.4 | 60.9 | 7.6s/q |

> 파라미터 수(20B) > instruction following(RLHF) ≠ 도구 활용 능력.
> Mistral3-8B가 도구 선택/결과 해석 모두에서 우수.

## 4. 도구 사용 통계 (Single+MCP Mistral3-8B)

| Level | 평균 도구/q | 주요 도구 (사용률) |
|-------|----------:|------------------|
| L1 | 1.2 | cfg (50%), nso_get_device_info (45%) |
| L2 | 1.2 | nso_get_all_device_info (76%), cfg (24%) |
| L3 | 2.8 | cfg (75%), nso (16%), batfish_bgp (9%) |
| L4 | 1.1 | batfish_traceroute (90%) |
| L5 | 2.1 | nso_all_device_info + batfish_failure |
| **전체** | **1.7** | |

## 5. 효율성 비교

| 시스템 | 모델 | TA-Acc | 시간/q | 총 시간 | LLM 호출/q |
|--------|------|------:|------:|-------:|---------:|
| Single LLM | Mistral3-8B | 42.28% | ~1s | ~36min | 1 |
| Single+MCP | Mistral3-8B | 82.65% | 2.4s | 1.4h | 2.0 |
| MAS+MCP | Mistral3-8B | 72.85% | 7.6s | 4.6h | 5.8 |
| Single+MCP | gpt-oss-20b | 60.94% | 7.6s | 4.6h | 2.0 |

## 6. 주요 Findings

1. **MCP 도구가 핵심 기여**: Single LLM 42% → Single+MCP 83% (+40%p)
2. **L4-L5에서 도구 필수**: Single LLM L4=16%, L5=12% → Single+MCP L4=88%, L5=78%
3. **cfg 도구 효과**: NSO만 사용 시 L1=64%, cfg 추가 시 L1=81% (+17%p)
4. **모델 크기 ≠ 성능**: Mistral3-8B(82.7%) > gpt-oss-20b(60.9%), instruction following이 중요
5. **도구 선택 자동화**: Collector가 질문 유형에 따라 cfg/NSO/Batfish를 자동 선택

## 7. 남은 실험

- [ ] MAS+MCP Mistral3-8B (cfg 도구 포함) 재실행 — 공정한 비교
- [ ] Single+MCP Lab A, C, D
- [ ] MAS+MCP Lab A, C, D
- [ ] Phase 2 모델 ablation (Lab D)

---

## 참고: 결과 파일 경로

| 실험 | 파일 |
|------|------|
| MAS+MCP Mistral3-8B (cfg 없음) | `netally_eval_direct_Dataset_20260403_221504.json` |
| MAS+MCP Mistral3-8B L1 재실행 | `netally_eval_direct_Dataset_20260404_101640.json` |
| Single+MCP Mistral3-8B v2 | `netally_eval_direct_Dataset_20260405_200454.json` |
| Single+MCP gpt-oss-20b | `netally_eval_direct_Dataset_20260405_213805.json` |

---
*수동 정리 (자동 생성 아님)*
