# AI 조사 프롬프트 활용 가이드
NetworkConfigQA 논문 작성을 위한 AI 조사 결과 활용 방법

## 📋 각 프롬프트별 예상 결과 및 활용 방법

### 1️⃣ `benchmark_survey.md` - 관련 논문 및 데이터셋 조사

#### 🎯 AI가 제공할 결과:

| Dataset Name | Paper Title | Authors | Venue/Year | Size | Domain | Task Type | Data Format | Metrics | Available | Key Features |
|--------------|-------------|---------|------------|------|--------|-----------|-------------|---------|-----------|--------------|
| CodeXGLUE | CodeXGLUE: A Machine Learning Benchmark Dataset | Lu et al. | NeurIPS 2021 | 14 tasks | Code Understanding | Multiple | Code+NL | BLEU, EM | ✓ | Multi-task code understanding |
| NetworkQA | Network Configuration Question Answering | Smith et al. | SIGCOMM 2022 | 1.2K | Network Config | QA | Config+Question | F1, EM | ✓ | Synthetic network configs |
| InfraCode | Infrastructure-as-Code Analysis | Jones et al. | OSDI 2023 | 800 | IaC | Classification | Terraform files | Accuracy | ✓ | Cloud infrastructure focus |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |

### Gap Analysis:
1. **Missing Real Topology Data**: Most datasets use synthetic or simplified configurations
2. **Lack of Complexity Levels**: Existing datasets don't categorize questions by difficulty
3. **Limited Topology Focus**: Most focus on general networking knowledge rather than specific topology understanding
4. **Small Scale**: Many datasets are relatively small (< 2K samples)

### Positioning:
Our NetworkConfigQA differs by:
- Using real production network configurations (not synthetic)
- Focusing specifically on topology parsing rather than general networking
- Providing 5 complexity levels for nuanced evaluation
- Hybrid generation approach combining rule-based and LLM methods


#### 📖 활용 방법:
1. **Related Work 섹션** 작성용 자료로 활용
2. **실제 존재하는 데이터셋**들로 가짜 벤치마크 교체
3. **Gap Analysis**를 논문의 motivation으로 활용
4. **Citation 목록** 생성 (실제 논문들 찾아서 인용)

---

### 2️⃣ `detailed_comparison.md` - 벤치마크 상세 분석 및 비교표 생성

#### 🎯 AI가 제공할 결과:

**LaTeX 표:**
```latex
\begin{table*}[t]
\centering
\caption{Comparison of NetworkConfigQA with Related Benchmarks}
\label{tab:benchmark_comparison}
\resizebox{\textwidth}{!}{%
\begin{tabular}{lllllccc}
\toprule
\textbf{Dataset} & \textbf{Domain} & \textbf{Size} & \textbf{Input Type} & \textbf{Output Type} & \textbf{Complexity} & \textbf{Real Data} & \textbf{Topology Focus} \\
\midrule
NetworkConfigQA (Ours) & Network Config Parsing & 759 & XML Config + NL & Short/Long Answer & 5 levels & ✓ & ✓ \\
CodeXGLUE & Code Understanding & 14 tasks & Code + NL & Multiple & 3 levels & ✗ & ✗ \\
NetworkQA & General Network & 1.2K & Text + Question & Short Answer & 1 level & ✗ & ✗ \\
InfraCode & IaC Analysis & 800 & Config Files & Classification & 2 levels & Partial & ✗ \\
\bottomrule
\end{tabular}%
}
\end{table*}
```

**분석 텍스트:**
```
Our NetworkConfigQA dataset fills several critical gaps in existing benchmarks. Unlike CodeXGLUE which focuses on general code understanding, our dataset specifically targets network topology parsing from real production configurations. While NetworkQA addresses general networking knowledge, our work emphasizes topology-specific understanding that requires deep parsing of configuration relationships. The multi-level complexity design (5 levels vs 1-3 in existing work) enables more nuanced evaluation of model capabilities across different difficulty levels.
```

#### 📖 활용 방법:
1. **논문의 Table 2**로 직접 사용
2. **분석 텍스트**를 Related Work이나 Dataset Description에 활용
3. **CSV 파일**로 받아서 필요시 수정
4. **논문 reviewer**들에게 우리 데이터셋의 차별점 명확히 전달

---

### 3️⃣ `paper_positioning.md` - 논문 positioning 및 contribution 생성

#### 🎯 AI가 제공할 결과:

**Related Work 섹션:**
```
## Related Work

Existing datasets for code understanding and network analysis can be categorized into three main groups. First, general code comprehension benchmarks like CodeXGLUE [Lu et al., 2021] and CodeBERT [Feng et al., 2020] focus on programming language understanding but lack domain-specific network configuration knowledge. Second, infrastructure-as-code datasets such as InfraCode [Jones et al., 2023] target cloud configuration analysis but primarily use synthetic or simplified examples. Third, network-specific datasets like NetworkQA [Smith et al., 2022] address general networking knowledge but do not emphasize topology-specific parsing from real production environments.

These existing approaches have several limitations: (1) reliance on synthetic or simplified data that doesn't reflect real-world complexity, (2) focus on general knowledge rather than specific topology understanding, (3) lack of multi-level complexity categorization, and (4) limited scale for comprehensive evaluation. Our work addresses these gaps by introducing NetworkConfigQA, a dataset derived from real production network configurations with topology-specific focus and systematic complexity categorization.
```

**Contributions 섹션:**
```
## Contributions

Our paper makes the following key contributions:

• **Novel Dataset**: We introduce NetworkConfigQA, the first large-scale dataset specifically designed for network topology parsing from real production configurations, containing 759 carefully curated question-answer pairs.

• **Topology-Specific Focus**: Unlike existing datasets that emphasize general networking knowledge, 85% of our questions require specific topology understanding, filling a critical gap in evaluation benchmarks.

• **Hybrid Generation Methodology**: We develop a novel hybrid approach combining rule-based generation for systematic coverage and LLM-enhanced generation for complex reasoning scenarios.

• **Multi-Level Complexity Framework**: We introduce a 5-level complexity categorization (basic, analytical, synthetic, diagnostic, scenario) enabling nuanced evaluation of model capabilities.

• **Real-World Validation**: Our dataset is derived from actual production network configurations, ensuring practical relevance and realistic complexity.
```

#### 📖 활용 방법:
1. **Abstract과 Introduction**에 contribution 활용
2. **Related Work 섹션** 텍스트 직접 사용
3. **논문의 핵심 메시지** 정립
4. **Conference submission** 시 novelty 강조 포인트

---

### 4️⃣ `evaluation_protocol.md` - 실험 설계 및 평가 프로토콜

#### 🎯 AI가 제공할 결과:

**실험 설계:**
```
## Experimental Protocol

### Baseline Models:
1. **General LLMs**: GPT-4, Claude-3, Gemini-Pro (zero-shot, few-shot)
2. **Code Models**: CodeBERT, CodeT5, UniXcoder
3. **Domain-Adapted**: Fine-tuned models on network documentation

### Evaluation Metrics:
- **Primary**: Exact Match (EM), F1-score
- **Secondary**: BLEU-4, ROUGE-L, Topology Accuracy
- **Category-wise**: Performance by complexity level and question type

### Experimental Setup:
1. **Baseline Evaluation**: Test all models on our test set
2. **Complexity Analysis**: Performance breakdown by 5 complexity levels  
3. **Topology vs General**: Compare performance on topology-specific vs general questions
4. **Fine-tuning Study**: Train models on our training set, evaluate transfer learning
5. **Human Evaluation**: Expert assessment of answer quality and practical utility

### Expected Results Table:
| Model | Overall EM | Overall F1 | Topology EM | General EM | Basic | Analytical | Diagnostic |
|-------|------------|------------|-------------|------------|-------|------------|------------|
| GPT-4 | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% |
| CodeBERT | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% |
| Fine-tuned | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% | XX.X% |
```

#### 📖 활용 방법:
1. **Experiments 섹션** 작성 가이드
2. **실제 실험 실행** 계획서
3. **Results 섹션** 테이블 템플릿
4. **논문 reviewer**에게 실험의 철저함 보여주기

---

### 5️⃣ `visualization_improvement.md` - Figure/Table 개선 제안

#### 🎯 AI가 제공할 결과:

**Figure 개선 제안:**
```
## Figure 1 Improvements:
**Current**: 4-panel overview (train/val/test, generation method, answer types, complexity)
**Suggestion**: 
- Add error bars to complexity distribution
- Use consistent color scheme across all panels
- Highlight the 85% topology-specific ratio more prominently
- Add sample counts on pie chart labels

**New Caption**: "Dataset composition overview. (a) Train/validation/test split following standard 70/15/15 ratio. (b) Question generation methodology combining rule-based (96.7%) and LLM-enhanced (3.3%) approaches. (c) Answer type distribution showing balanced short and long form responses. (d) Complexity level distribution with emphasis on analytical and diagnostic questions that require deeper topology understanding."

## New Figure Ideas:
**Figure 6**: Topology Complexity Heat Map
- Show correlation between topology size and question difficulty
- Visualize which device types generate more complex questions
- Compare complexity distribution across different network categories

**Figure 7**: Model Performance by Complexity
- Performance comparison across the 5 complexity levels
- Show where current models struggle most
- Highlight the evaluation challenge our dataset provides
```

#### 📖 활용 방법:
1. **기존 Figure들 개선** 작업 지침
2. **새로운 Figure 추가** 아이디어
3. **Caption 작성** 템플릿
4. **논문의 visual impact** 향상

---

## 🚀 전체 워크플로우

### 단계별 진행 방법:

1. **1단계 조사** (`benchmark_survey.md`)
   - ChatGPT/Claude에 프롬프트 제공
   - 관련 논문 리스트 받기
   - 실제 논문들 확인하고 citation 정리

2. **2단계 비교표** (`detailed_comparison.md`)  
   - 1단계 결과를 바탕으로 실행
   - LaTeX 표와 분석 텍스트 받기
   - 논문에 직접 삽입

3. **3단계 논문 작성** (`paper_positioning.md`)
   - Abstract, Introduction, Related Work 초안 받기
   - Contribution 리스트 정리
   - 논문 구조 확정

4. **4단계 실험 설계** (`evaluation_protocol.md`)
   - 실험 계획 수립
   - 실제 모델 실행 준비
   - Results 섹션 템플릿 준비

5. **5단계 시각화** (`visualization_improvement.md`)
   - Figure/Table 개선
   - 논문 최종 다듬기
   - Publication-ready 완성

### 💡 Pro Tips:

- **AI 응답은 초안**으로 사용, 반드시 fact-check 필요
- **실제 논문들 확인**하여 citation 정확성 보장  
- **여러 AI 조합 사용** (ChatGPT + Claude + Perplexity)
- **단계별 검토**를 통해 일관성 유지

이렇게 체계적으로 진행하면 **고품질 논문**을 효율적으로 작성할 수 있습니다! 🎉
