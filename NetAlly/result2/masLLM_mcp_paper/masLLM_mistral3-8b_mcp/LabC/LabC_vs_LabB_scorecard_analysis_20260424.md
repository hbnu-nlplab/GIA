# LabC vs LabB Scorecard Analysis

비교 기준:

- LabB: `result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp/LabB/results_analyzed_netally_20260423_143122_scorecard.md`
- LabC: `result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp/LabC/netally_eval_direct_LabC_NCN_Security_L2VPN_30nodes_20260424_130543_analyzed_scorecard.md`

## 결론

paper analyzer scorecard 기준으로 LabC가 LabB보다 아주 약간 높다.

| Lab | Count | Type-Aware Accuracy |
|---|---:|---:|
| LabB | 2,157 | 59.75% |
| LabC | 2,674 | 60.01% |

차이는 `+0.26%p`로 매우 작다. 따라서 "LabC가 구조적으로 훨씬 쉽다"기보다는, 여러 하위 항목의 상승과 하락이 상쇄된 결과로 보는 것이 맞다.

## 왜 raw runner summary와 scorecard가 다른가?

`run_netally_eval_direct.py`가 마지막에 출력하는 summary는 실행 중 내부 scorer로 계산한 빠른 진행용 요약이다. 반면 `result2`의 scorecard는 `Experiment/code/NetConfigQA2_2/analyze_results.py` 후처리 결과이며, 논문용 지표로 사용한다.

특히 negative sample 처리 기준이 다르다.

- Scorecard Type-Aware Accuracy는 `NOT_CONFIGURED` 계약 준수를 엄격하게 반영한다.
- Semantic Negative Relaxed는 별도 지표로 제공된다.
- LabB/LabC 모두 semantic negative는 높지만, strict abstention이 낮아서 전체 Type-Aware Accuracy가 raw runner summary보다 낮게 나온다.

따라서 논문/표/최종 비교에는 `result2/..._scorecard.md`와 `..._analyzed.json`을 기준으로 사용한다.

## Level별 비교

| Level | LabB | LabC | Diff |
|---|---:|---:|---:|
| L1 | 46.03% | 46.89% | +0.86%p |
| L2 | 94.74% | 82.67% | -12.07%p |
| L3 | 81.31% | 75.82% | -5.49%p |
| L4 | 80.36% | 77.25% | -3.11%p |
| L5 | 66.41% | 29.68% | -36.73%p |

LabC가 전체에서 근소하게 높은 이유는 L1 샘플 수가 크고 L1이 소폭 상승했기 때문이다. 반대로 L2-L5는 대부분 LabB보다 낮다.

## Status별 비교

| Status | LabB | LabC | Diff |
|---|---:|---:|---:|
| OK | 75.83% | 71.94% | -3.89%p |
| NOT_CONFIGURED strict | 15.06% | 14.13% | -0.93%p |
| Semantic Negative relaxed | 89.67% | 88.77% | -0.90%p |
| Contract Compliance | 16.80% | 15.92% | -0.88%p |

LabC는 configured positive 문제에서는 LabB보다 낮다. Negative도 semantic relaxed 기준으로는 비슷하지만, strict `NOT_CONFIGURED` 계약 준수는 둘 다 낮다.

## Answer Type별 비교

| Type | LabB | LabC | Diff |
|---|---:|---:|---:|
| number | 69.58% | 72.99% | +3.41%p |
| map | 49.34% | 50.23% | +0.89%p |
| set | 46.33% | 44.46% | -1.87%p |
| text | 63.25% | 58.81% | -4.44%p |

LabC의 상승분은 주로 `number`와 `map`에서 나온다. 반대로 `text`와 `set`은 떨어졌다.

## 해석

LabC가 LabB보다 높게 나온 핵심 이유:

1. LabC는 L1이 `46.89%`로 LabB보다 `+0.86%p` 높고, L1 샘플이 1,271개로 전체의 큰 비중을 차지한다.
2. LabC는 `number` 유형이 `72.99%`로 LabB보다 `+3.41%p` 높다.
3. LabC는 전체 샘플이 2,674개로 LabB보다 많아, L4/L1의 대량 샘플이 전체 평균에 큰 영향을 준다.

하지만 주의할 점:

1. LabC L5는 `29.68%`로 LabB `66.41%`보다 크게 낮다.
2. LabC L2/L3/L4도 LabB보다 낮다.
3. 전체 차이는 `+0.26%p`뿐이라 통계적으로 큰 개선이라고 주장하기 어렵다.

논문 해석 문장 후보:

> LabC achieved a marginally higher overall TA-Acc than LabB under the strict scorecard metric, mainly due to small gains in high-volume L1 and numeric/map-style questions. However, its performance degraded substantially on L5 what-if questions, indicating that the added security/L2VPN complexity increases reasoning difficulty despite stable performance on simpler extraction and simulation tasks.
