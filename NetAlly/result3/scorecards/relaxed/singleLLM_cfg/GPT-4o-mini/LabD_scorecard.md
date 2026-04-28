# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-4o-mini`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-4o-mini/LabD/results_raw_vllm_en_20260326_085554.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:35

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 25.00% |
| Strict TA-Acc | 17.62% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 58.27% |
| L2 | 42.17% |
| L3 | 10.30% |
| L4 | 3.44% |
| L5 | 4.41% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 27.42% |
| number | 19.97% |
| set | 47.81% |
| text | 20.59% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 18.54% |
| Explicit NOT_CONFIGURED | 12.95% |
| Semantic Negative | 57.73% |
| Contract Compliance | 22.43% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 7 | L1 | OK | text | `"p8"` | `PE8` | 0.00 |
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
