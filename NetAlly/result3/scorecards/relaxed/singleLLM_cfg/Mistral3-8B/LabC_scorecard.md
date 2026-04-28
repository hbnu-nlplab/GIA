# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Mistral3-8B/LabC/results_raw_vllm_en_20260325_202327.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:46:54

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 39.95% |
| Strict TA-Acc | 27.50% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 67.82% |
| L2 | 69.78% |
| L3 | 20.00% |
| L4 | 5.77% |
| L5 | 47.10% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 40.40% |
| number | 28.91% |
| set | 74.89% |
| text | 32.07% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 32.01% |
| Explicit NOT_CONFIGURED | 10.14% |
| Semantic Negative | 70.47% |
| Contract Compliance | 14.40% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 21 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 23 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 24 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 25 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 27 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 28 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 29 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 31 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 32 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 34 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 35 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 36 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 37 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 38 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 39 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
