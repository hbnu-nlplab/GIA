# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Mistral3-8B/LabB/results_raw_vllm_en_20260325_202142.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:43:55

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 36.80% |
| Strict TA-Acc | 36.80% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 42.93% |
| L2 | 89.10% |
| L3 | 51.37% |
| L4 | 9.26% |
| L5 | 18.87% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 29.22% |
| number | 37.98% |
| set | 43.49% |
| text | 32.95% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 44.69% |
| Explicit NOT_CONFIGURED | 14.89% |
| Semantic Negative | 84.59% |
| Contract Compliance | 17.60% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 21 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 22 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 23 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 24 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 25 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 26 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 27 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 28 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 29 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 30 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 31 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 32 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 33 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 34 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 35 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
