# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-OSS-20B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-OSS-20B/LabC/results_raw_vllm_en_20260325_205618.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:19

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 26.50% |
| Strict TA-Acc | 16.21% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 48.43% |
| L2 | 57.60% |
| L3 | 23.34% |
| L4 | 0.84% |
| L5 | 1.94% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 37.28% |
| number | 0.00% |
| set | 87.35% |
| text | 16.85% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 18.21% |
| Explicit NOT_CONFIGURED | 8.51% |
| Semantic Negative | 58.33% |
| Contract Compliance | 14.60% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 3 | L1 | OK | text | `"leaf6"` | `` | 0.00 |
| 6 | L1 | OK | text | `"leaf2"` | `` | 0.00 |
| 8 | L1 | OK | text | `"leaf8"` | `` | 0.00 |
| 18 | L1 | OK | text | `"leaf9"` | `` | 0.00 |
| 22 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 24 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 28 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 31 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 32 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 37 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 40 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 41 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 42 | L1 | OK | text | `"KST 9"` | `` | 0.00 |
| 43 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 44 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
