# NetConfigQA Comparison Report

> **Generated on**: 2026-03-06 13:03:51

### 1. Traditional NLP Metrics

| 모델 | Rouge-1 | Rouge-2 | Rouge-L | EM | BLEU | BertScore | f1(Token) | Type-Aware Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Qwen3-Coder | 0.00 | 0.00 | 0.00 | 17.65 | 0.00 | 91.24 | 20.92 | 19.54 |

---

### 2. Type-Aware Accuracy by Answer Type

| 모델 | map | numeric | text | number | set |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3-Coder | 29.24 | 0.00 | 19.55 | 13.53 | 30.03 |

> Note: `number`는 주로 정수/카운트(개수) 유형, `numeric`은 수치값(스칼라/실수 가능) 유형입니다. 둘 다 동일한 숫자 채점 로직으로 평가되지만 분석을 위해 분리 집계합니다.


---

### 3. Type-Aware Accuracy by Level

| 모델 | L1 | L2 | L3 | L4 | L5 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Qwen3-Coder | 44.33 | 32.64 | 12.00 | 3.02 | 6.61 |

