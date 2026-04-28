# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-4o-mini`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-4o-mini/LabC/results_raw_vllm_en_20260326_083253.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:34

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 33.73% |
| Strict TA-Acc | 23.48% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 63.65% |
| L2 | 65.04% |
| L3 | 10.77% |
| L4 | 4.09% |
| L5 | 0.65% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 28.09% |
| number | 28.20% |
| set | 57.78% |
| text | 27.52% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 25.86% |
| Explicit NOT_CONFIGURED | 14.31% |
| Semantic Negative | 63.95% |
| Contract Compliance | 22.38% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 4 | L1 | OK | text | `"pe3"` | `P3` | 0.00 |
| 41 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 42 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 43 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 44 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 45 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 46 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 47 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 48 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 49 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 50 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 51 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 52 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 53 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 54 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
