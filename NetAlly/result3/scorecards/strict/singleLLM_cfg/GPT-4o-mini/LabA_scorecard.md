# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `GPT-4o-mini`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-4o-mini/LabA/results_raw_vllm_en_20260326_081401.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:43:46

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 34.25% |
| Strict TA-Acc | 34.25% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 40.55% |
| L2 | 74.54% |
| L3 | 28.17% |
| L4 | 12.42% |
| L5 | 11.65% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 19.38% |
| number | 36.84% |
| set | 34.95% |
| text | 35.36% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 40.31% |
| Explicit NOT_CONFIGURED | 19.73% |
| Semantic Negative | 85.60% |
| Contract Compliance | 23.05% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 61 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 62 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 63 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 64 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 65 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 66 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 67 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 68 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 69 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 70 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 71 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 72 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 73 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 74 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 75 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
