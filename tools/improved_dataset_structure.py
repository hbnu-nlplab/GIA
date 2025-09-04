"""
개선된 데이터셋 구조 예시
EM/F1 + BERT-score 평가에 최적화
"""

# === 개선 전 (문제가 있는 예시) ===
before_example = {
    "question": "AS 그룹 내 라우터들의 BGP 설정에서 일관성 문제가 있는지 확인하려면 어떤 메트릭을 주로 살펴봐야 할까요?",
    "ground_truth": ["bgp_local_as_numeric", "ibgp_fullmesh_ok"],  # 내부 메트릭명!
    "explanation": "BGP 설정의 일관성 문제를 확인하기 위해서는 'bgp_local_as_numeric'와 'ibgp_fullmesh_ok' 메트릭을 주로 살펴봐야 합니다."  # 중복!
}

# === 개선 후 (EM/F1 + BERT-score 최적화) ===
after_example = {
    "question": "AS 그룹 내 라우터들의 BGP 설정에서 일관성 문제가 있는지 확인하려면 어떤 메트릭을 주로 살펴봐야 할까요?",
    
    # EM/F1 평가용 - 정확한 매칭이 가능한 자연스러운 답변
    "ground_truth": ["BGP Local AS 번호", "iBGP Full-Mesh 구성 상태"],
    
    # BERT-score 평가용 - 추가적인 맥락과 설명
    "explanation": "네트워크 전체의 BGP 설정 일관성을 검증하기 위해서는 먼저 각 라우터의 AS 번호가 올바르게 설정되어 있는지 확인해야 하며, 동시에 내부 BGP 피어링이 완전한 Full-Mesh 구조로 구성되어 있는지 점검해야 합니다. 이 두 가지 요소가 일치하지 않으면 라우팅 불일치나 경로 수렴 문제가 발생할 수 있습니다.",
    
    # 평가 메타데이터
    "evaluation": {
        "ground_truth_type": "list",
        "em_f1_suitable": True,
        "bert_score_suitable": True,
        "difficulty": "medium"
    }
}

# === 다양한 답변 형태별 최적화 예시 ===

# 1. 단일 값 답변 (EM 평가에 최적)
single_value_example = {
    "question": "SSH 접속이 불가능한 장비는 총 몇 대입니까?",
    "ground_truth": "0",  # 숫자 답변
    "explanation": "현재 네트워크에서 SSH가 활성화되지 않은 장비는 없습니다. 모든 6개 장비(CE1, CE2, sample7, sample8, sample9, sample10)에서 SSH 서비스가 정상적으로 구성되어 있어 원격 관리가 가능한 상태입니다."
}

# 2. 명령어 답변 (정확한 매칭 필요)
command_example = {
    "question": "sample7 장비에서 BGP 피어 상태를 확인하는 명령어는 무엇입니까?",
    "ground_truth": "show bgp summary",  # 정확한 명령어
    "explanation": "BGP 피어의 상태를 종합적으로 확인하기 위해서는 'show bgp summary' 명령어를 사용합니다. 이 명령어는 모든 BGP 이웃의 연결 상태, AS 번호, 수신된 경로 수 등의 핵심 정보를 한 번에 보여주어 네트워크 상태를 신속하게 파악할 수 있게 해줍니다."
}

# 3. 복합 분석 답변 (BERT-score에 최적)
complex_analysis_example = {
    "question": "iBGP의 풀메시 구성 누락이 경로 수렴 시간에 어떻게 영향을 미칠 수 있으며, 이러한 영향이 다른 경로 프로토콜과 상호작용할 때 어떤 결과를 초래할 수 있을까요?",
    
    # 핵심 답변 (EM/F1용)
    "ground_truth": "경로 수렴 지연 및 프로토콜 간 불일치로 인한 네트워크 성능 저하",
    
    # 상세 설명 (BERT-score용)
    "explanation": "iBGP Full-Mesh 구성이 누락되면 내부 BGP 라우터들 간의 경로 정보 교환이 불완전해져 경로 수렴 시간이 현저히 증가합니다. 특히 OSPF와 같은 IGP(Interior Gateway Protocol)와의 상호작용에서 문제가 발생하는데, BGP가 전달하는 외부 경로 정보와 OSPF가 계산하는 내부 경로 정보 간의 동기화가 어긋나게 됩니다. 이로 인해 일시적인 라우팅 루프, 패킷 손실, 그리고 최적이 아닌 경로 선택이 발생하여 전체 네트워크의 성능과 안정성이 저하될 수 있습니다."
}

# === 평가 매트릭별 적합성 가이드라인 ===
evaluation_guidelines = {
    "EM_F1_suitable": {
        "answer_types": ["단일 값", "명령어", "장비명", "IP 주소", "설정값"],
        "characteristics": ["정확한 매칭 가능", "객관적 답변", "명확한 정답"],
        "examples": ["3", "show bgp summary", "sample7", "192.168.1.1"]
    },
    
    "BERT_score_suitable": {
        "answer_types": ["분석 답변", "설명형 답변", "절차 기술", "영향 분석"],
        "characteristics": ["의미적 유사성 평가", "다양한 표현 허용", "추론 과정 포함"],
        "min_length": 50,  # 최소 50자 이상
        "complexity": ["원인 분석", "영향 예측", "해결 방안", "비교 분석"]
    }
}

print("=== 데이터셋 구조 개선 가이드 ===")
print("EM/F1 평가: 정확한 매칭이 가능한 객관적 답변")
print("BERT-score 평가: 의미적 유사성을 평가할 수 있는 설명형 답변")
print("Ground Truth: 핵심 정답만 간결하게")
print("Explanation: 추가적인 맥락과 상세한 설명")
