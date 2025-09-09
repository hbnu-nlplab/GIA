"""
네트워크 구성 파싱 데이터셋 논문용 벤치마크 조사 프롬프트
AI Research Assistant Prompts for Network Configuration Parsing Benchmark Survey
"""

# ============================================================================
# 프롬프트 1: 관련 논문 및 데이터셋 조사
# ============================================================================

BENCHMARK_SURVEY_PROMPT = """
You are a research assistant helping to write an academic paper about a new dataset for network configuration parsing. I need you to find and analyze existing benchmarks and datasets that are relevant to our work.

## Research Task:
Find and analyze existing datasets/benchmarks in the following areas:

### Primary Areas (Most Important):
1. **Network Configuration Analysis**
   - Datasets for parsing network device configurations
   - Benchmarks for network topology understanding
   - Configuration file analysis datasets

2. **Infrastructure-as-Code (IaC) Datasets**
   - Terraform, Ansible, CloudFormation configuration datasets
   - Infrastructure configuration parsing benchmarks

3. **Code Understanding & Parsing**
   - Datasets for structured file parsing (XML, JSON, YAML)
   - Code comprehension benchmarks (CodeXGLUE, CodeBERT datasets)

### Secondary Areas:
4. **Domain-Specific Question Answering**
   - Technical documentation QA datasets
   - Domain-specific reading comprehension benchmarks

5. **Network Management & Monitoring**
   - Network troubleshooting datasets
   - Network performance analysis benchmarks

## For Each Dataset/Benchmark Found, Provide:
1. **Dataset Name** and **Paper Title**
2. **Authors** and **Publication Venue** (Conference/Journal, Year)
3. **Dataset Size** (number of samples, files, etc.)
4. **Domain Focus** (what specific area it covers)
5. **Task Type** (QA, classification, parsing, generation, etc.)
6. **Data Format** (what type of input/output)
7. **Evaluation Metrics** used
8. **Availability** (public/private, download link if available)
9. **Key Characteristics** that differentiate it from others

## Output Format:
Please structure your findings as a table with these columns:
| Dataset Name | Paper Title | Authors | Venue/Year | Size | Domain | Task Type | Data Format | Metrics | Available | Key Features |

## Additional Analysis:
After the table, please provide:
1. **Gap Analysis**: What aspects are missing in existing datasets that our NetworkConfigQA addresses?
2. **Positioning**: How does our focus on "real network topology parsing" differ from existing work?
3. **Comparison Points**: What metrics/characteristics should we highlight to show our dataset's novelty?

## Search Strategy:
Please search recent papers (2020-2024) from:
- NLP venues: ACL, EMNLP, NAACL, ICLR, NeurIPS
- Systems venues: NSDI, OSDI, SIGCOMM, IMC
- AI venues: AAAI, IJCAI
- Domain-specific: NOMS, IM, CNSM (network management conferences)

Look for keywords: "network configuration", "configuration parsing", "network topology", "infrastructure as code", "code understanding", "structured data parsing", "network dataset"
"""

# ============================================================================
# 프롬프트 2: 벤치마크 상세 분석 및 비교표 생성
# ============================================================================

DETAILED_COMPARISON_PROMPT = """
Based on the datasets you found, create a detailed comparison table for our paper. I need both a LaTeX table and analysis for academic writing.

## Task: Create Benchmark Comparison Table

### Table Requirements:
Create a comparison table with the following columns:
1. **Dataset** - Name of the dataset/benchmark
2. **Domain** - Primary application domain
3. **Size** - Number of samples/questions/files
4. **Input Type** - Type of input data (configs, code, docs, etc.)
5. **Output Type** - Type of expected output (short answer, long answer, classification, etc.)
6. **Complexity** - Whether it supports multiple difficulty levels
7. **Real Data** - Whether it uses real-world production data
8. **Topology Focus** - Whether it specifically targets network topology understanding

### Our Dataset Characteristics:
- **NetworkConfigQA**: {total_samples} samples
- **Domain**: Network Configuration Parsing
- **Input**: Real network device XML configurations + natural language questions
- **Output**: Short/Long answers with explanations
- **Complexity**: 5 levels (basic, analytical, synthetic, diagnostic, scenario)
- **Real Data**: Yes (production network configurations)
- **Topology Focus**: Yes (specifically targets topology understanding vs general networking knowledge)

### Output Format:
1. **LaTeX Table**: Publication-ready table with proper formatting
2. **CSV Table**: For easy editing and data manipulation
3. **Analysis Section**: 2-3 paragraphs highlighting our dataset's unique contributions

### Analysis Should Cover:
1. **Novelty**: What makes our dataset different from existing ones?
2. **Gap Filling**: What research gaps does our dataset address?
3. **Methodological Advantages**: Why is our approach (real topology + hybrid generation) superior?

### LaTeX Template:
```latex
\\begin{{table*}}[t]
\\centering
\\caption{{Comparison of NetworkConfigQA with Related Benchmarks}}
\\label{{tab:benchmark_comparison}}
\\resizebox{{\\textwidth}}{{!}}{{%
\\begin{{tabular}}{{lllllccc}}
\\toprule
\\textbf{{Dataset}} & \\textbf{{Domain}} & \\textbf{{Size}} & \\textbf{{Input Type}} & \\textbf{{Output Type}} & \\textbf{{Complexity}} & \\textbf{{Real Data}} & \\textbf{{Topology Focus}} \\\\
\\midrule
% Insert comparison data here
\\bottomrule
\\end{{tabular}}%
}}
\\end{{table*}}
```

Please fill this template with real data from your research.
"""

# ============================================================================
# 프롬프트 3: 논문 작성용 positioning 및 contribution 생성
# ============================================================================

PAPER_POSITIONING_PROMPT = """
Based on your benchmark survey, help me write the positioning and contribution sections for our NetworkConfigQA paper.

## Background Information:
Our dataset, NetworkConfigQA, has these characteristics:
- **{total_samples}** question-answer pairs
- Generated from **real production network configurations** (XML files)
- **{topology_ratio:.1%}** of questions focus on topology-specific understanding (not general networking knowledge)
- **Hybrid generation**: Rule-based + LLM-enhanced question generation
- **5 complexity levels**: basic, analytical, synthetic, diagnostic, scenario
- **Multi-persona**: Questions from different professional perspectives (network engineer, security auditor, etc.)

## Tasks:

### 1. Related Work Section (2-3 paragraphs)
Write a related work section that:
- Summarizes existing datasets/benchmarks you found
- Categorizes them into logical groups
- Identifies limitations of existing approaches
- Sets up the motivation for our work

### 2. Contributions Section (Bullet points)
Generate 4-5 key contributions that highlight:
- What's novel about our approach
- What research gaps we're filling
- What methodological advances we're making
- What practical applications this enables

### 3. Dataset Positioning Statement (1 paragraph)
Write a clear positioning statement explaining:
- How our dataset differs from existing work
- Why topology-specific focus is important
- Why real production data matters
- How our hybrid generation approach is superior

### 4. Evaluation Strategy (1-2 paragraphs)
Suggest how to evaluate our dataset against existing benchmarks:
- What experiments to run
- What metrics to compare
- How to demonstrate superiority
- What baseline models to use

### Writing Style:
- Academic but accessible
- Clear motivation and positioning
- Avoid overclaiming
- Use precise technical language
- Include specific numbers/percentages where helpful

### Output Format:
Please provide each section with clear headers and ready-to-use academic text.
"""

# ============================================================================
# 프롬프트 4: 실험 설계 및 평가 프로토콜 생성
# ============================================================================

EVALUATION_PROTOCOL_PROMPT = """
Design a comprehensive evaluation protocol to demonstrate the value and uniqueness of our NetworkConfigQA dataset.

## Dataset Context:
- **NetworkConfigQA**: {total_samples} samples, {topology_ratio:.1%} topology-focused
- **Real network topology data** from production environments
- **Hybrid generation** (rule-based + LLM)
- **Multi-complexity** questions (5 levels)

## Evaluation Goals:
1. **Validate dataset quality** and consistency
2. **Demonstrate topology-specific value** vs general networking knowledge
3. **Show practical utility** for network configuration understanding
4. **Compare with existing benchmarks** (where applicable)

## Required Experimental Design:

### Experiment 1: Baseline Model Performance
Design experiments using:
- **General LLMs**: GPT-4, Claude, Gemini (zero-shot, few-shot)
- **Code-Understanding Models**: CodeBERT, CodeT5, UniXcoder
- **Domain-Adapted Models**: Any network-specific models found in literature

**Metrics to Report**:
- Exact Match accuracy
- F1 score (token-level)
- BLEU score (for longer answers)
- Category-wise performance
- Complexity-wise performance

### Experiment 2: Topology-Specific vs General Knowledge
Design evaluation to show:
- Performance gap between topology-specific and general networking questions
- Whether models struggle more with our topology-focused questions
- Comparison with general networking QA benchmarks (if available)

### Experiment 3: Fine-tuning Effectiveness
Design experiments showing:
- Performance improvement when fine-tuning on our dataset
- Transfer learning to other network configuration tasks
- Few-shot learning effectiveness

### Experiment 4: Human Evaluation
Design human evaluation for:
- Question quality and difficulty assessment
- Answer correctness validation
- Practical utility rating from network professionals

## Experimental Protocol Template:

### Setup:
- **Models**: [List of models to evaluate]
- **Splits**: Use our train/val/test splits
- **Metrics**: [Primary and secondary metrics]
- **Baselines**: [Comparison baselines]

### Statistical Analysis:
- Significance testing protocol
- Confidence intervals
- Effect size measurements

### Error Analysis:
- Categorize failure modes
- Analyze performance by question type
- Identify model limitations

## Output Requirements:
1. **Detailed experimental protocol** (step-by-step)
2. **Expected results table template** (with placeholders)
3. **Statistical analysis plan**
4. **Timeline and resource requirements**

Please provide a comprehensive evaluation plan that would be convincing to paper reviewers.
"""

# ============================================================================
# 프롬프트 5: 논문 Figure 및 Table 개선 제안
# ============================================================================

VISUALIZATION_IMPROVEMENT_PROMPT = """
Review and improve the visualizations for our NetworkConfigQA paper to make them more impactful and publication-ready.

## Current Visualizations:
We have generated these figures and tables:
1. **Figure 1**: Dataset overview (4 subplots: train/val/test split, generation method, answer types, complexity distribution)
2. **Figure 2**: Category distribution (category counts + topology-specific vs general)
3. **Figure 3**: Complexity analysis (stacked bar + question length by complexity)
4. **Figure 4**: Question-answer length distributions
5. **Figure 5**: Topology focus analysis (keyword frequency + category scores)
6. **Table 1**: Basic dataset statistics
7. **Table 2**: Benchmark comparison (currently with dummy data)
8. **Table 3**: Category-wise detailed analysis

## Improvement Tasks:

### 1. Figure Enhancement Suggestions
For each figure, suggest improvements for:
- **Clarity**: How to make the message clearer
- **Visual Appeal**: Better colors, layouts, fonts
- **Academic Standards**: What makes figures publication-ready
- **Information Density**: What to add/remove for maximum impact

### 2. New Figure Ideas
Suggest 2-3 additional figures that would strengthen the paper:
- What aspects of our dataset aren't well visualized yet?
- What comparisons with other datasets would be impactful?
- What would help readers understand our contribution better?

### 3. Table Improvements
For each table, suggest:
- Better organization and grouping
- Additional metrics that would be valuable
- More effective presentation format
- What information is missing

### 4. Caption Writing
Write publication-ready captions for each figure/table that:
- Clearly explain what's shown
- Highlight key takeaways
- Guide reader attention to important details
- Follow academic writing conventions

### 5. Statistical Significance
Suggest where to add:
- Error bars or confidence intervals
- Statistical significance tests
- Correlation analyses
- Distribution comparisons

## Output Format:
For each visualization, provide:
1. **Current Assessment**: What works well, what doesn't
2. **Specific Improvements**: Concrete suggestions with rationale
3. **Publication-Ready Caption**: Complete caption text
4. **Implementation Notes**: How to make the changes

## Style Guidelines:
- **Academic conferences**: ACL, EMNLP style figures
- **Color blind friendly**: Accessible color schemes
- **High resolution**: Vector graphics where possible
- **Consistent styling**: Unified look across all figures

Please provide detailed, actionable feedback for publication-quality visualizations.
"""

# ============================================================================
# 메인 실행 함수
# ============================================================================

def generate_research_prompts(dataset_stats):
    """
    데이터셋 통계를 기반으로 연구용 프롬프트를 생성합니다.
    
    Args:
        dataset_stats: 데이터셋 분석 결과 딕셔너리
    
    Returns:
        dict: 각 연구 단계별 프롬프트들
    """
    
    prompts = {
        "benchmark_survey": BENCHMARK_SURVEY_PROMPT,
        "detailed_comparison": DETAILED_COMPARISON_PROMPT.format(**dataset_stats),
        "paper_positioning": PAPER_POSITIONING_PROMPT.format(**dataset_stats),
        "evaluation_protocol": EVALUATION_PROTOCOL_PROMPT.format(**dataset_stats),
        "visualization_improvement": VISUALIZATION_IMPROVEMENT_PROMPT
    }
    
    return prompts


def save_prompts_to_files(prompts, output_dir="docs/research_prompts"):
    """프롬프트들을 파일로 저장"""
    from pathlib import Path
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    for prompt_name, prompt_content in prompts.items():
        file_path = output_path / f"{prompt_name}.md"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# {prompt_name.replace('_', ' ').title()}\n\n")
            f.write(prompt_content)
        
        print(f"✅ Saved: {file_path}")


if __name__ == "__main__":
    # 예시 데이터셋 통계 (실제 분석 결과로 대체 필요)
    example_stats = {
        'total_samples': 759,
        'topology_ratio': 0.85,  # 85% topology-focused
        'train_samples': 531,
        'validation_samples': 114,
        'test_samples': 114
    }
    
    prompts = generate_research_prompts(example_stats)
    save_prompts_to_files(prompts)
    
    print("\n" + "="*60)
    print("🎯 AI 연구 조사 프롬프트 생성 완료!")
    print("="*60)
    print("\n📋 생성된 프롬프트들:")
    for i, (name, _) in enumerate(prompts.items(), 1):
        print(f"{i}. {name.replace('_', ' ').title()}")
    
    print(f"\n📁 저장 위치: docs/research_prompts/")
    print("\n🚀 사용법:")
    print("1. 각 프롬프트를 ChatGPT, Claude, 또는 다른 AI에게 순서대로 제공")
    print("2. 응답을 받아서 논문 작성에 활용")
    print("3. 실제 데이터로 placeholder 값들을 교체")
    print("4. 조사 결과를 바탕으로 벤치마크 비교표 업데이트")
