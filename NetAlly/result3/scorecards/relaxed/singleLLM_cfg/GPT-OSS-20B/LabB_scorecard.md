# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-OSS-20B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-OSS-20B/LabB/results_raw_vllm_en_20260325_205105.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:46:48

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 36.44% |
| Strict TA-Acc | 22.21% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 51.22% |
| L2 | 73.92% |
| L3 | 29.93% |
| L4 | 3.16% |
| L5 | 0.86% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 32.73% |
| number | 0.00% |
| set | 91.20% |
| text | 27.07% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 26.42% |
| Explicit NOT_CONFIGURED | 10.51% |
| Semantic Negative | 64.27% |
| Contract Compliance | 16.35% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 7 | L1 | OK | text | `"p8"` | `` | 0.00 |
| 17 | L1 | OK | text | `"leaf8"` | `` | 0.00 |
| 41 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 42 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 43 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 44 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 45 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 46 | L1 | OK | text | `"KST 9"` | `` | 0.00 |
| 47 | L1 | OK | text | `"KST 9"` | `` | 0.00 |
| 48 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| 49 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 50 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 51 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 52 | L1 | OK | text | `"KST 9"` | `KST 9 0` | 0.00 |
| 53 | L1 | OK | text | `"KST 9"` | `` | 0.00 |
