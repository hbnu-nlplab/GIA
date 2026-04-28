# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/Mistral3-8B/LabD/results_raw_vllm_en_20260325_202624.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:26

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 21.48% |
| Strict TA-Acc | 21.48% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 41.82% |
| L2 | 55.78% |
| L3 | 21.98% |
| L4 | 5.49% |
| L5 | 18.63% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 25.91% |
| number | 17.65% |
| set | 37.07% |
| text | 18.49% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 23.87% |
| Explicit NOT_CONFIGURED | 9.35% |
| Semantic Negative | 67.45% |
| Contract Compliance | 13.87% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 26 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 32 | L1 | OK | text | `"15.7"` | `version 15.7` | 0.00 |
| 41 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
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
