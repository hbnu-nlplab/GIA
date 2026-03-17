# Method 4 L4/L5 Replay Mismatch Report

## spof_detection:566d4b6821
- status: MISMATCH
- metric: spof_detection
- reason: 
- detail: missing={'p7'}
- replay_answer: []
- dataset_answer: ["p7"]

## policy_compliance_check:da0910f0db
- status: MISMATCH
- metric: policy_compliance_check
- reason: 
- detail: token_f1=0.571
- replay_answer: VIOLATION: 10.0.1.0 -> 8.8.8.8, 10.0.1.1 -> 8.8.8.8, 10.0.11.0 -> 8.8.8.8
- dataset_answer: "VIOLATION: 10.0.30.1 -> 8.8.8.8, 10.10.10.1 -> 8.8.8.8, 10.0.30.3 -> 8.8.8.8"
