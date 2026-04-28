# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Qwen3-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Qwen3-8B/LabA/results_raw_vllm_en_20260326_102234.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:27

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 56.24% |
| Strict TA-Acc | 36.35% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 73.47% |
| L2 | 72.14% |
| L3 | 36.90% |
| L4 | 24.84% |
| L5 | 23.30% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 26.39% |
| number | 60.53% |
| set | 89.07% |
| text | 33.89% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 51.33% |
| Explicit NOT_CONFIGURED | 0.53% |
| Semantic Negative | 68.00% |
| Contract Compliance | 0.78% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 21 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 22 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 23 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 24 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 25 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 26 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 27 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 28 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 29 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 30 | L1 | NOT_CONFIGURED | text | `null` | `The` | 0.00 |
| 51 | L1 | NOT_CONFIGURED | text | `null` | `6` | 0.00 |
| 52 | L1 | NOT_CONFIGURED | text | `null` | `informational` | 0.00 |
| 53 | L1 | NOT_CONFIGURED | text | `null` | `6` | 0.00 |
| 54 | L1 | NOT_CONFIGURED | text | `null` | `` | 0.00 |
| 55 | L1 | NOT_CONFIGURED | text | `null` | `6` | 0.00 |
