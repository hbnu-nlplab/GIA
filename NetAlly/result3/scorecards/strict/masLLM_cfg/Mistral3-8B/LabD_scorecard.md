# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabD`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_cfg/mistral3_8b/labD/results_raw_mistral3_8b_20260408_145644.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:46:47

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 23.60% |
| Strict TA-Acc | 23.60% |
| Total Samples | 3370 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 48.30% |
| L2 | 56.91% |
| L3 | 22.33% |
| L4 | 5.67% |
| L5 | 9.32% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 24.90% |
| number | 23.99% |
| set | 40.06% |
| text | 17.38% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 26.56% |
| Explicit NOT_CONFIGURED | 8.63% |
| Semantic Negative | 79.32% |
| Contract Compliance | 10.88% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_TIMEZONE_TEXT_leaf10 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf9 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf14 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf6 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p8 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf3 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf16 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p6 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_asbr1 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf1 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe2 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe8 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p10 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p12 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p11 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
