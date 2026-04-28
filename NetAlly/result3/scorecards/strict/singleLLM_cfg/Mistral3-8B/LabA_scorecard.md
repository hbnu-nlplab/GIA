# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Mistral3-8B/LabA/results_raw_vllm_en_20260325_202043.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:41

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 35.68% |
| Strict TA-Acc | 35.68% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 41.11% |
| L2 | 77.86% |
| L3 | 26.59% |
| L4 | 21.57% |
| L5 | 13.59% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 21.81% |
| number | 33.88% |
| set | 40.34% |
| text | 36.19% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 42.23% |
| Explicit NOT_CONFIGURED | 20.00% |
| Semantic Negative | 90.93% |
| Contract Compliance | 21.99% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 16 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 21 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 22 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 23 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 24 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 25 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 26 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 27 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 28 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 30 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| 61 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 62 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 63 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 64 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| 65 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
