# 🧠 LLM 기반 문서 선택 RAG 개선 방안

## 💡 현재 RAG 방식의 한계점

### 기존 벡터 검색 방식
```python
# 현재 pipeline_3_advanced.py의 방식
def retrieve_documents(question: str, top_k: int = 5):
    # 1. 질문을 벡터로 임베딩
    query_embedding = embedding_model.embed(question)
    
    # 2. ChromaDB에서 유사도 검색
    results = chromadb.query(
        query_embeddings=[query_embedding],
        n_results=top_k
    )
    
    # 3. 상위 K개 문서 반환
    return results['documents']
```

### 한계점 분석
1. **의미적 유사도의 한계**: 벡터 유사도 ≠ 실제 답변 유용성
2. **컨텍스트 무시**: 질문의 맥락을 고려하지 않음
3. **고정적 선택**: 항상 같은 기준으로 문서 선택

## 🚀 LLM 기반 문서 선택 방식

### 핵심 아이디어
"LLM이 직접 문서 목록을 보고 질문에 가장 유용한 문서들을 선택하게 하자"

### 구현 방법 1: 문서 요약 기반 선택
```python
def llm_based_document_selection(question: str, top_k: int = 10):
    # 1. 모든 문서의 요약 정보 준비
    doc_summaries = get_all_document_summaries()
    
    # 2. LLM에게 문서 선택 요청
    selection_prompt = f"""
    네트워크 엔지니어링 질문에 답하기 위해 가장 유용한 문서들을 선택해주세요.

    질문: {question}

    사용 가능한 문서들:
    {format_document_list(doc_summaries)}

    위 문서 중에서 이 질문에 답하는 데 가장 유용한 상위 {top_k}개 문서의 
    번호를 선택해주세요. 번호만 쉼표로 구분해서 답하세요.

    예: 1,5,12,23,45,67,89,101,134,156
    """
    
    # 3. LLM 응답으로 문서 선택
    response = llm.generate(selection_prompt)
    selected_ids = parse_selected_ids(response)
    
    # 4. 선택된 문서들의 전체 내용 로드
    selected_documents = load_documents(selected_ids)
    
    return selected_documents

def get_all_document_summaries():
    """모든 문서의 요약 정보 생성"""
    summaries = []
    for i, doc_path in enumerate(all_document_paths):
        summary = {
            'id': i+1,
            'filename': os.path.basename(doc_path),
            'device': extract_device_name(doc_path),
            'section': extract_section_type(doc_path),
            'preview': get_first_lines(doc_path, 3)
        }
        summaries.append(summary)
    return summaries

def format_document_list(summaries):
    """문서 목록을 LLM이 읽기 좋은 형태로 포맷"""
    formatted = []
    for summary in summaries:
        line = f"[{summary['id']}] {summary['filename']} - " \
               f"장비:{summary['device']}, 섹션:{summary['section']}"
        formatted.append(line)
    return "\n".join(formatted)
```

### 구현 방법 2: 하이브리드 접근
```python
def hybrid_document_selection(question: str, top_k: int = 10):
    # 1단계: 벡터 검색으로 후보군 축소 (20개)
    vector_candidates = vector_search(question, top_k=20)
    
    # 2단계: LLM이 후보군에서 최종 선택 (10개)
    final_selection = llm_select_from_candidates(
        question, vector_candidates, final_k=top_k
    )
    
    return final_selection

def llm_select_from_candidates(question, candidates, final_k):
    """LLM이 후보 문서들 중에서 최종 선택"""
    candidate_info = []
    for i, doc in enumerate(candidates):
        candidate_info.append(f"[{i+1}] {doc['metadata']['filename']}")
    
    prompt = f"""
    다음 후보 문서들 중에서 질문 '{question}'에 답하는 데 
    가장 유용한 {final_k}개를 선택해주세요:
    
    {chr(10).join(candidate_info)}
    
    선택된 문서 번호: 
    """
    
    response = llm.generate(prompt)
    selected_indices = parse_indices(response)
    
    return [candidates[i-1] for i in selected_indices if i <= len(candidates)]
```

## 📊 구체적 구현 계획

### Step 1: 문서 메타데이터 준비
```python
# docs7_export 폴더의 모든 문서 분석
def analyze_document_structure():
    """
    기존 문서들의 구조 분석:
    - 01_sample10_device.txt → 장비: sample10, 섹션: device
    - 38_sample8_bgp_neighbor.txt → 장비: sample8, 섹션: bgp_neighbor
    """
    doc_metadata = {}
    for filename in os.listdir("docs7_export"):
        parts = filename.replace('.txt', '').split('_')
        doc_id = parts[0]
        device = parts[1] 
        section = '_'.join(parts[2:])
        
        doc_metadata[filename] = {
            'doc_id': doc_id,
            'device': device,
            'section': section,
            'full_path': f"docs7_export/{filename}"
        }
    
    return doc_metadata
```

### Step 2: 새로운 RAG 파이프라인 클래스
```python
class LLMBasedRAG:
    """LLM이 문서를 직접 선택하는 RAG 시스템"""
    
    def __init__(self, docs_path="docs7_export"):
        self.docs_path = docs_path
        self.doc_metadata = self.analyze_documents()
        self.llm = get_llm_client()
    
    def process_query(self, question: str, selection_method="llm_direct"):
        """
        selection_method options:
        - "llm_direct": LLM이 직접 문서 선택
        - "hybrid": 벡터 검색 + LLM 선택
        - "vector_baseline": 기존 벡터 검색 (비교용)
        """
        
        if selection_method == "llm_direct":
            selected_docs = self.llm_select_documents(question)
        elif selection_method == "hybrid":
            selected_docs = self.hybrid_select_documents(question)
        else:
            selected_docs = self.vector_select_documents(question)
        
        # 선택된 문서들로 컨텍스트 구성
        context = self.build_context(selected_docs)
        
        # 최종 답변 생성
        answer = self.generate_answer(question, context)
        
        return {
            'answer': answer,
            'selected_documents': selected_docs,
            'selection_method': selection_method
        }
```

### Step 3: 성능 비교 실험 설계
```python
def compare_selection_methods():
    """3가지 문서 선택 방법 성능 비교"""
    
    methods = [
        "vector_baseline",  # 기존 방식
        "llm_direct",      # LLM 직접 선택
        "hybrid"           # 하이브리드
    ]
    
    results = {}
    
    for method in methods:
        print(f"Testing {method}...")
        
        method_results = []
        for question, ground_truth in test_dataset:
            # 각 방법으로 답변 생성
            result = rag_system.process_query(question, method)
            
            # 성능 평가
            metrics = evaluate_answer(result['answer'], ground_truth)
            metrics['method'] = method
            metrics['num_docs_used'] = len(result['selected_documents'])
            
            method_results.append(metrics)
        
        results[method] = method_results
    
    return results
```

## 🎯 예상 성능 개선 효과

### 가설
1. **정확도 향상**: 5-15% 개선 (BERT Score 기준)
2. **컨텍스트 품질**: 더 관련성 높은 문서 선택
3. **설명 가능성**: LLM이 선택한 이유를 설명 가능

### 측정 지표
- **Document Relevance Score**: 선택된 문서의 실제 유용성
- **Context Utilization Rate**: 컨텍스트 정보 활용도  
- **Selection Consistency**: 같은 질문에 대한 선택 일관성

## 🔧 실제 구현을 위한 코드 수정

### 1. enhanced_benchmark_runner.py 수정
```python
# 새로운 RAG 모드 추가
"experiments": {
    "rag_llm_select": {
        "description": "LLM 기반 문서 선택 RAG",
        "use_rag": true,
        "selection_method": "llm_direct",
        "max_iterations": 1,
        "top_k_contexts": 10
    }
}
```

### 2. 새로운 파이프라인 파일 생성
```bash
# pipeline_4_llm_selection.py 생성
# LLM 기반 문서 선택 구현
```

### 3. 비교 실험 설정
```python
def run_selection_method_comparison():
    """문서 선택 방법별 성능 비교"""
    methods = ["vector", "llm_direct", "hybrid"]
    
    for method in methods:
        experiment_id = f"selection_{method}_{timestamp}"
        run_experiment_with_method(experiment_id, method)
    
    # 결과 비교 분석
    generate_selection_comparison_report()
```

## 📋 구현 우선순위

### Phase 1: 기본 구현 (1-2일)
- [ ] 문서 메타데이터 분석 코드
- [ ] 기본 LLM 선택 로직
- [ ] 소규모 테스트 (10개 질문)

### Phase 2: 최적화 (2-3일)  
- [ ] 하이브리드 방식 구현
- [ ] 성능 비교 실험
- [ ] 프롬프트 최적화

### Phase 3: 통합 (1일)
- [ ] 기존 벤치마크 시스템에 통합
- [ ] 전체 데이터셋 테스트
- [ ] 결과 분석 및 리포트

## 💰 비용 및 성능 고려사항

### 비용 증가 요인
- **추가 LLM 호출**: 문서 선택을 위한 별도 API 호출
- **긴 프롬프트**: 문서 목록을 포함한 더 긴 입력

### 최적화 방안
- **문서 요약 캐싱**: 한 번 생성한 요약 재사용
- **배치 선택**: 여러 질문에 대해 한 번에 문서 선택
- **후보군 축소**: 벡터 검색으로 1차 필터링

이 방식을 구현하면 "RAG 성능이 안 좋다"는 문제를 근본적으로 해결할 수 있을 것 같습니다!
