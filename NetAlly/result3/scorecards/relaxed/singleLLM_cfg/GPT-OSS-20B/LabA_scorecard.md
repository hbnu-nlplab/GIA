# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-OSS-20B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-OSS-20B/LabA/results_raw_vllm_en_20260326_100514.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:35

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 60.94% |
| Strict TA-Acc | 40.50% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 78.84% |
| L2 | 98.57% |
| L3 | 42.46% |
| L4 | 24.84% |
| L5 | 13.59% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 29.08% |
| number | 72.70% |
| set | 92.43% |
| text | 35.36% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 55.87% |
| Explicit NOT_CONFIGURED | 3.73% |
| Semantic Negative | 73.07% |
| Contract Compliance | 5.11% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 21 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 22 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 23 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 24 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 25 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 26 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 27 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 28 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 29 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 30 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 51 | L1 | NOT_CONFIGURED | text | `null` | `5` | 0.00 |
| 52 | L1 | NOT_CONFIGURED | text | `null` | `5` | 0.00 |
| 53 | L1 | NOT_CONFIGURED | text | `null` | `5` | 0.00 |
| 54 | L1 | NOT_CONFIGURED | text | `null` | `default` | 0.00 |
| 55 | L1 | NOT_CONFIGURED | text | `null` | `informational` | 0.00 |
