# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `singleLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/singleLLM_mcp/mistral3-8b/LabA/netally_eval_direct_singleLLM_mcp_LabA_20260428_174505.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:44:00

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 49.07% |
| Strict TA-Acc | 49.07% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 31.59% |
| L2 | 43.67% |
| L3 | 80.29% |
| L4 | 67.32% |
| L5 | 66.99% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 39.80% |
| number | 67.43% |
| set | 33.57% |
| text | 51.88% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 63.00% |
| Explicit NOT_CONFIGURED | 15.73% |
| Semantic Negative | 83.47% |
| Contract Compliance | 18.85% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_HOSTNAME_TEXT_leaf4 | L1 | OK | text | `"leaf4"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_leaf3 | L1 | OK | text | `"leaf3"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_p4 | L1 | OK | text | `"p4"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_pe1 | L1 | OK | text | `"pe1"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_p3 | L1 | OK | text | `"p3"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_pe2 | L1 | OK | text | `"pe2"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_p2 | L1 | OK | text | `"p2"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_HOSTNAME_TEXT_p1 | L1 | OK | text | `"p1"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf4 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_p1 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf2 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_pe1 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
| SYSTEM_VERSION_TEXT_p3 | L1 | OK | text | `"15.7"` | `NOT_CONFIGURED` | 0.00 |
