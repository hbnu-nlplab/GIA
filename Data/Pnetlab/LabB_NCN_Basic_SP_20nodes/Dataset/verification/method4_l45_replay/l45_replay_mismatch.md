# Method 4 L4/L5 Replay Mismatch Report

## spof_detection:566d4b6821
- status: MISMATCH
- metric: spof_detection
- reason: 
- detail: missing={'leaf6'}
- replay_answer: ["pe3"]
- dataset_answer: ["pe3", "leaf6"]

## policy_compliance_check:55fdaa2721
- status: MISMATCH
- metric: policy_compliance_check
- reason: 
- detail: token_f1=0.286
- replay_answer: VIOLATION: 10.0.1.0 -> 8.8.8.8, 10.0.1.1 -> 8.8.8.8, 10.0.11.0 -> 8.8.8.8
- dataset_answer: "VIOLATION: 10.10.10.31 -> 10.10.10.0, 172.16.1.3 -> 10.10.10.0, 10.10.10.1 -> 10.10.10.0"
