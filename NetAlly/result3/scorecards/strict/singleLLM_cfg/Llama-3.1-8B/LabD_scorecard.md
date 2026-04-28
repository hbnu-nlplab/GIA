# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `Llama-3.1-8B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Llama-3.1-8B/LabD/results_raw_vllm_en_20260325_194817.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:40

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 14.97% |
| Strict TA-Acc | 14.97% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 33.59% |
| L2 | 52.69% |
| L3 | 7.75% |
| L4 | 1.99% |
| L5 | 6.32% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 24.04% |
| number | 10.80% |
| set | 31.93% |
| text | 11.34% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 17.71% |
| Explicit NOT_CONFIGURED | 1.08% |
| Semantic Negative | 26.62% |
| Contract Compliance | 4.05% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
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
| 55 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
