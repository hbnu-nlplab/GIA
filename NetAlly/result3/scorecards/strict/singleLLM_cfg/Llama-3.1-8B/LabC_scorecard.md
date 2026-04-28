# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `Llama-3.1-8B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Llama-3.1-8B/LabC/results_raw_vllm_en_20260325_194207.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:38

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 17.89% |
| Strict TA-Acc | 17.89% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 32.36% |
| L2 | 50.19% |
| L3 | 9.18% |
| L4 | 1.99% |
| L5 | 3.23% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 24.29% |
| number | 13.27% |
| set | 35.55% |
| text | 12.47% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 22.54% |
| Explicit NOT_CONFIGURED | 0.00% |
| Semantic Negative | 26.63% |
| Contract Compliance | 0.00% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 41 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 42 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 43 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 44 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 45 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 46 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 47 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 48 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 49 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 50 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 51 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 52 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 53 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 54 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 55 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
