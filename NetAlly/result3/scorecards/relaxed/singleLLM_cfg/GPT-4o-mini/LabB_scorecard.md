# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-4o-mini`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-4o-mini/LabB/results_raw_vllm_en_20260326_082035.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:33

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 50.44% |
| Strict TA-Acc | 33.84% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 68.55% |
| L2 | 74.74% |
| L3 | 50.59% |
| L4 | 6.55% |
| L5 | 10.94% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 26.64% |
| number | 48.40% |
| set | 80.08% |
| text | 36.75% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 41.93% |
| Explicit NOT_CONFIGURED | 11.38% |
| Semantic Negative | 74.08% |
| Contract Compliance | 15.37% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
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
| 55 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
