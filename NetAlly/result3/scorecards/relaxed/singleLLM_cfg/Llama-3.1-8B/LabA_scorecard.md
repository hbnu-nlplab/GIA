# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Llama-3.1-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Llama-3.1-8B/LabA/results_raw_vllm_en_20260325_193817.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:37

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 37.73% |
| Strict TA-Acc | 22.40% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 57.41% |
| L2 | 49.28% |
| L3 | 11.90% |
| L4 | 5.23% |
| L5 | 8.74% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 15.28% |
| number | 35.53% |
| set | 59.16% |
| text | 26.99% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 29.54% |
| Explicit NOT_CONFIGURED | 5.33% |
| Semantic Negative | 57.33% |
| Contract Compliance | 9.30% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 21 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 22 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 23 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 24 | L1 | NOT_CONFIGURED | text | `null` | `UTC Wed Dec 17 2025` | 0.00 |
| 25 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 26 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 27 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 28 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 29 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 30 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 51 | L1 | NOT_CONFIGURED | text | `null` | `no logging buffered` | 0.00 |
| 52 | L1 | NOT_CONFIGURED | text | `null` | `debug` | 0.00 |
| 53 | L1 | NOT_CONFIGURED | text | `null` | `no logging buffered` | 0.00 |
| 54 | L1 | NOT_CONFIGURED | text | `null` | `no logging buffered` | 0.00 |
| 55 | L1 | NOT_CONFIGURED | text | `null` | `no logging buffered` | 0.00 |
