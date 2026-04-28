# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_cfg`
- Model: `GPT-OSS-20B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-OSS-20B/LabD/results_raw_vllm_en_20260325_210443.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:19

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 11.03% |
| Strict TA-Acc | 11.03% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 23.47% |
| L2 | 60.00% |
| L3 | 18.42% |
| L4 | 0.60% |
| L5 | 0.03% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 24.85% |
| number | 0.00% |
| set | 39.58% |
| text | 8.13% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 12.18% |
| Explicit NOT_CONFIGURED | 5.22% |
| Semantic Negative | 50.54% |
| Contract Compliance | 10.32% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 1 | L1 | OK | text | `"leaf14"` | `` | 0.00 |
| 3 | L1 | OK | text | `"leaf15"` | `` | 0.00 |
| 8 | L1 | OK | text | `"leaf16"` | `` | 0.00 |
| 9 | L1 | OK | text | `"leaf1"` | `` | 0.00 |
| 14 | L1 | OK | text | `"leaf8"` | `` | 0.00 |
| 15 | L1 | OK | text | `"leaf2"` | `` | 0.00 |
| 19 | L1 | OK | text | `"leaf3"` | `` | 0.00 |
| 22 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 27 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 28 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 31 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 35 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 37 | L1 | OK | text | `"15.7"` | `` | 0.00 |
| 41 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 42 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
