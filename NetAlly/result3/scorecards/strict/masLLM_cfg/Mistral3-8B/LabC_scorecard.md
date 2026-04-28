# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabC`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_cfg/mistral3_8b/labC/results_raw_mistral3_8b_20260408_102716.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:48:10

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 28.99% |
| Strict TA-Acc | 28.99% |
| Total Samples | 2674 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 47.33% |
| L2 | 38.93% |
| L3 | 25.66% |
| L4 | 7.86% |
| L5 | 11.61% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 22.88% |
| number | 31.16% |
| set | 41.39% |
| text | 22.53% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 34.36% |
| Explicit NOT_CONFIGURED | 8.33% |
| Semantic Negative | 78.08% |
| Contract Compliance | 10.67% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| L2VPN_UNIDIR_COUNT | L3 | OK | number | `0` | `1` | 0.00 |
| L2VPN_PWID_MISMATCH_PAIRS | L3 | OK | set | `[]` | `["PE3-PE6"]` | 0.00 |
| L2VPN_MISMATCH_COUNT | L3 | OK | number | `0` | `2` | 0.00 |
| IBGP_MISSING_PAIRS_65001 | L3 | OK | set | `[]` | `["10.255.0.32"]` | 0.00 |
| IBGP_MISSING_PAIRS_65000 | L3 | OK | set | `["p7<->p8", "p7<->pe1", "p7<->pe2", "p7<->pe3", "p7<->pe4", "p8<->pe1", "p8<->pe` | `` | 0.00 |
| IBGP_MISSING_PAIRS_COUNT_65000 | L3 | OK | number | `11` | `0` | 0.00 |
| IBGP_MISSING_PAIRS_COUNT_65001 | L3 | OK | number | `0` | `2` | 0.00 |
| IBGP_UNDER_PEERED_DEVICES_65000 | L3 | OK | set | `["p7", "p8", "pe1", "pe2", "pe3", "pe4"]` | `["P7"]` | 0.29 |
| SYSTEM_TIMEZONE_TEXT_pe1 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe6 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p1 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p2 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p7 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf4 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe2 | L1 | OK | text | `"KST 9"` | `KST` | 0.00 |
