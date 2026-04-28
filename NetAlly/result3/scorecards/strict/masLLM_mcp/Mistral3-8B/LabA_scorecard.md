# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_mcp`
- Model: `Mistral3-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_mcp_paper/masLLM_mistral3-8b_mcp/LabA/netally_eval_direct_LabA_Research_Institute_DC_10nodes_20260423_224508.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:46:41

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 58.26% |
| Strict TA-Acc | 58.26% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 41.61% |
| L2 | 88.57% |
| L3 | 79.10% |
| L4 | 70.59% |
| L5 | 80.58% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 54.45% |
| number | 68.42% |
| set | 46.18% |
| text | 62.34% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 76.04% |
| Explicit NOT_CONFIGURED | 15.73% |
| Semantic Negative | 84.00% |
| Contract Compliance | 18.73% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_VERSION_TEXT_p2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf3 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_leaf1 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| SYSTEM_VERSION_TEXT_pe2 | L1 | OK | text | `"15.7"` | `15.9` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf1 | L1 | NOT_CONFIGURED | text | `null` | `informational` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_pe1 | L1 | NOT_CONFIGURED | text | `null` | `warnings` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf4 | L1 | NOT_CONFIGURED | text | `null` | `informational` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf3 | L1 | NOT_CONFIGURED | text | `null` | `informational` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_p4 | L1 | NOT_CONFIGURED | text | `null` | `warnings` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_pe2 | L1 | NOT_CONFIGURED | text | `null` | `warnings` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_p2 | L1 | NOT_CONFIGURED | text | `null` | `warnings` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_p1 | L1 | NOT_CONFIGURED | text | `null` | `warnings` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_leaf2 | L1 | NOT_CONFIGURED | text | `null` | `informational` | 0.00 |
