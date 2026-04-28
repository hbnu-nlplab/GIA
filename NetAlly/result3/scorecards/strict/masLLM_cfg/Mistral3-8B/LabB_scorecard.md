# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabB`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_cfg/mistral3_8b/labB/results_raw_mistral3_8b_20260408_123355.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:46:38

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 35.85% |
| Strict TA-Acc | 35.85% |
| Total Samples | 2157 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 46.25% |
| L2 | 57.51% |
| L3 | 36.96% |
| L4 | 10.61% |
| L5 | 7.81% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 24.16% |
| number | 45.21% |
| set | 41.06% |
| text | 28.00% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 45.86% |
| Explicit NOT_CONFIGURED | 8.06% |
| Semantic Negative | 77.23% |
| Contract Compliance | 10.43% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_TIMEZONE_TEXT_pe4 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf3 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf5 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf6 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf1 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p2 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe2 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf8 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p3 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe3 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf7 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p5 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p7 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p1 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf2 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
