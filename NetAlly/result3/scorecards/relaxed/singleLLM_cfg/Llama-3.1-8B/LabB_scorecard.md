# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `Llama-3.1-8B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Llama-3.1-8B/LabB/results_raw_vllm_en_20260325_193946.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:21

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 42.81% |
| Strict TA-Acc | 29.04% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 60.04% |
| L2 | 49.94% |
| L3 | 43.14% |
| L4 | 2.26% |
| L5 | 7.89% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 28.88% |
| number | 38.32% |
| set | 67.34% |
| text | 32.49% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 38.30% |
| Explicit NOT_CONFIGURED | 3.33% |
| Semantic Negative | 55.34% |
| Contract Compliance | 6.01% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 5 | L1 | OK | text | `"p2"` | `Leaf2` | 0.00 |
| 41 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 42 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 43 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 44 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 45 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 46 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 47 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 48 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 49 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 50 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 51 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 52 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 53 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 54 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
