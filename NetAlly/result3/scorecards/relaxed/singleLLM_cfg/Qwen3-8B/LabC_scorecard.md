# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Qwen3-8B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Qwen3-8B/LabC/results_raw_vllm_en_20260325_203623.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:44

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 8.33% |
| Strict TA-Acc | 8.22% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 13.96% |
| L2 | 48.51% |
| L3 | 8.00% |
| L4 | 0.63% |
| L5 | 0.00% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 28.07% |
| number | 0.00% |
| set | 34.81% |
| text | 0.00% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 10.36% |
| Explicit NOT_CONFIGURED | 0.00% |
| Semantic Negative | 0.54% |
| Contract Compliance | 0.00% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 1 | L1 | OK | text | `"p5"` | `` | 0.00 |
| 2 | L1 | OK | text | `"p1"` | `` | 0.00 |
| 3 | L1 | OK | text | `"leaf6"` | `` | 0.00 |
| 4 | L1 | OK | text | `"pe3"` | `` | 0.00 |
| 5 | L1 | OK | text | `"p8"` | `` | 0.00 |
| 6 | L1 | OK | text | `"leaf2"` | `` | 0.00 |
| 7 | L1 | OK | text | `"leaf12"` | `` | 0.00 |
| 8 | L1 | OK | text | `"leaf8"` | `` | 0.00 |
| 9 | L1 | OK | text | `"leaf7"` | `` | 0.00 |
| 10 | L1 | OK | text | `"p10"` | `` | 0.00 |
| 11 | L1 | OK | text | `"leaf5"` | `` | 0.00 |
| 12 | L1 | OK | text | `"pe2"` | `` | 0.00 |
| 13 | L1 | OK | text | `"pe6"` | `` | 0.00 |
| 14 | L1 | OK | text | `"p7"` | `` | 0.00 |
| 15 | L1 | OK | text | `"p2"` | `` | 0.00 |
