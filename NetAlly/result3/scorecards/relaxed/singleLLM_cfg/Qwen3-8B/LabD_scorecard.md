# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Qwen3-8B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Qwen3-8B/LabD/results_raw_vllm_en_20260325_203911.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:45

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 5.68% |
| Strict TA-Acc | 5.68% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 12.91% |
| L2 | 45.07% |
| L3 | 5.83% |
| L4 | 0.00% |
| L5 | 0.00% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 27.35% |
| number | 0.00% |
| set | 28.48% |
| text | 0.00% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 6.81% |
| Explicit NOT_CONFIGURED | 0.00% |
| Semantic Negative | 0.00% |
| Contract Compliance | N/A |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 1 | L1 | OK | text | `"leaf14"` | `` | 0.00 |
| 2 | L1 | OK | text | `"fw2"` | `` | 0.00 |
| 3 | L1 | OK | text | `"leaf15"` | `` | 0.00 |
| 4 | L1 | OK | text | `"pe5"` | `` | 0.00 |
| 5 | L1 | OK | text | `"p3"` | `` | 0.00 |
| 6 | L1 | OK | text | `"p2"` | `` | 0.00 |
| 7 | L1 | OK | text | `"p8"` | `` | 0.00 |
| 8 | L1 | OK | text | `"leaf16"` | `` | 0.00 |
| 9 | L1 | OK | text | `"leaf1"` | `` | 0.00 |
| 10 | L1 | OK | text | `"pe1"` | `` | 0.00 |
| 11 | L1 | OK | text | `"p10"` | `` | 0.00 |
| 12 | L1 | OK | text | `"p6"` | `` | 0.00 |
| 13 | L1 | OK | text | `"p12"` | `` | 0.00 |
| 14 | L1 | OK | text | `"leaf8"` | `` | 0.00 |
| 15 | L1 | OK | text | `"leaf2"` | `` | 0.00 |
