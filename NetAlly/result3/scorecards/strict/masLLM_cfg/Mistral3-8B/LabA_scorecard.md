# NetConfigQA Result3 Scorecard

- Mode: `strict`
- Method: `masLLM_cfg`
- Model: `Mistral3-8B`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/NetAlly/result2/masLLM_cfg/mistral3_8b/labA/results_raw_mistral3_8b_20260408_120625.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:26

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 37.09% |
| Strict TA-Acc | 37.09% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 41.39% |
| L2 | 43.58% |
| L3 | 46.43% |
| L4 | 18.95% |
| L5 | 7.77% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 25.79% |
| number | 50.99% |
| set | 43.91% |
| text | 25.31% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 49.25% |
| Explicit NOT_CONFIGURED | 8.00% |
| Semantic Negative | 78.13% |
| Contract Compliance | 10.24% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| SYSTEM_TIMEZONE_TEXT_p4 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p2 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf1 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf3 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p1 | L1 | NOT_CONFIGURED | text | `null` | `not set` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe2 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf2 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_p3 | L1 | NOT_CONFIGURED | text | `null` | `not set` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_leaf4 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| SYSTEM_TIMEZONE_TEXT_pe1 | L1 | NOT_CONFIGURED | text | `null` | `UTC` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_pe1 | L1 | NOT_CONFIGURED | text | `null` | `7` | 0.00 |
| LOGGING_BUFFERED_SEVERITY_TEXT_p4 | L1 | NOT_CONFIGURED | text | `null` | `not set` | 0.00 |
| NTP_SERVER_LIST_p2 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| NTP_SERVER_LIST_pe1 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
| NTP_SERVER_LIST_leaf4 | L1 | NOT_CONFIGURED | set | `[]` | `[]` | 0.00 |
