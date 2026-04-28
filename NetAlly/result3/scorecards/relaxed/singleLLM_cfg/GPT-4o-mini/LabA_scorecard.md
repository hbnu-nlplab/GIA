# NetConfigQA Result3 Scorecard

- Mode: `relaxed`
- Method: `singleLLM_cfg`
- Model: `GPT-4o-mini`
- Lab: `LabA`
- Raw: `/home/sdlab08/projects/GIA/Experiment/code/NetConfigQA2_2/result_final/GPT-4o-mini/LabA/results_raw_vllm_en_20260326_081401.json`
- Dataset status overlay: 0 rows
- Generated: 2026-04-28T20:38:33

## Overall

| Metric | Value |
|---|---:|
| Type-Aware Accuracy | 53.66% |
| Strict TA-Acc | 34.25% |
| Total Samples | 1272 |

## Level Breakdown

| Level | TA-Acc |
|---|---:|
| L1 | 76.14% |
| L2 | 74.54% |
| L3 | 28.17% |
| L4 | 12.42% |
| L5 | 11.65% |

## Type Breakdown

| Type | TA-Acc |
|---|---:|
| map | 21.25% |
| number | 48.68% |
| set | 78.03% |
| text | 44.56% |

## Positive vs Negative

| Slice | Accuracy |
|---|---:|
| OK | 40.31% |
| Explicit NOT_CONFIGURED | 19.73% |
| Semantic Negative | 85.60% |
| Contract Compliance | 23.05% |

## Sample Errors

| ID | Level | Status | Type | Gold | Pred | Score |
|---|---|---|---|---|---|---:|
| 91 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"up","GigabitEthernet0/1":"up","GigabitEthernet0/2":"up","` | 0.89 |
| 94 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"up","GigabitEthernet0/1":"up","GigabitEthernet0/2":"up","` | 0.89 |
| 97 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"up","GigabitEthernet0/1":"up","GigabitEthernet0/2":"up","` | 0.67 |
| 100 | L1 | OK | map | `{"GigabitEthernet0/0": "up", "GigabitEthernet0/1": "up", "GigabitEthernet0/2": "` | `{"GigabitEthernet0/0":"10.0.0.1 255.255.255.254","GigabitEthernet0/1":"10.0.0.2 ` | 0.00 |
| 101 | L1 | OK | number | `4` | `2` | 0.00 |
| 102 | L1 | OK | number | `5` | `2` | 0.00 |
| 103 | L1 | OK | number | `7` | `3` | 0.00 |
| 104 | L1 | OK | number | `5` | `3` | 0.00 |
| 105 | L1 | OK | number | `6` | `3` | 0.00 |
| 106 | L1 | OK | number | `5` | `0` | 0.00 |
| 107 | L1 | OK | number | `7` | `3` | 0.00 |
| 108 | L1 | OK | number | `6` | `0` | 0.00 |
| 109 | L1 | OK | number | `6` | `0` | 0.00 |
| 110 | L1 | OK | number | `4` | `2` | 0.00 |
| 152 | L1 | OK | number | `5` | `4` | 0.00 |
