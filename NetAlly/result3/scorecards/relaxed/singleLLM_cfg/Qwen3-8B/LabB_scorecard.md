# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Qwen3-8B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Qwen3-8B/LabB/results_raw_vllm_en_20260325_203512.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:44:05

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 13.03% |
| Strict TA-Acc | 11.64% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 15.76% |
| L2 | 51.32% |
| L3 | 19.61% |
| L4 | 0.23% |
| L5 | 0.00% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 29.56% |
| number | 0.00% |
| set | 43.27% |
| text | 0.00% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 15.83% |
| Explicit NOT_CONFIGURED | 0.00% |
| Semantic Negative | 5.25% |
| Contract Compliance | 0.00% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 1 | L1 | OK | text | `"pe4"` | `` | 0.00 |
| 2 | L1 | OK | text | `"leaf6"` | `` | 0.00 |
| 3 | L1 | OK | text | `"p7"` | `` | 0.00 |
| 4 | L1 | OK | text | `"leaf5"` | `` | 0.00 |
| 5 | L1 | OK | text | `"p2"` | `` | 0.00 |
| 6 | L1 | OK | text | `"p6"` | `` | 0.00 |
| 7 | L1 | OK | text | `"p8"` | `` | 0.00 |
| 8 | L1 | OK | text | `"pe3"` | `` | 0.00 |
| 9 | L1 | OK | text | `"leaf7"` | `` | 0.00 |
| 10 | L1 | OK | text | `"p5"` | `` | 0.00 |
| 11 | L1 | OK | text | `"pe2"` | `` | 0.00 |
| 12 | L1 | OK | text | `"p3"` | `` | 0.00 |
| 13 | L1 | OK | text | `"leaf2"` | `` | 0.00 |
| 14 | L1 | OK | text | `"p4"` | `` | 0.00 |
| 15 | L1 | OK | text | `"leaf3"` | `` | 0.00 |
