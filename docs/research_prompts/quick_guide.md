## 🎯 AI 조사 프롬프트 활용 가이드

### 📝 각 프롬프트 결과 요약

#### 1️⃣ benchmark_survey.md → 관련 논문 조사
**AI가 제공할 것:**
- 실제 존재하는 네트워크/코드 이해 데이터셋 목록
- 각 데이터셋의 크기, 도메인, 평가 방법
- 우리 데이터셋과의 차이점 분석

**논문에 활용:**
- Related Work 섹션 작성
- 가짜 벤치마크를 실제 데이터셋으로 교체
- Citation 목록 생성

#### 2️⃣ detailed_comparison.md → 비교표 생성  
**AI가 제공할 것:**
- LaTeX 형식의 벤치마크 비교표
- 우리 데이터셋의 차별점 분석 텍스트
- CSV 형식 데이터

**논문에 활용:**
- Table 2로 직접 삽입
- Dataset Description 섹션에 분석 활용

#### 3️⃣ paper_positioning.md → 논문 작성
**AI가 제공할 것:**
- Abstract, Introduction 초안
- 5개 주요 Contribution 정리
- Related Work 섹션 텍스트

**논문에 활용:**
- 논문 전체 구조 확정
- 핵심 메시지 정립

#### 4️⃣ evaluation_protocol.md → 실험 설계
**AI가 제공할 것:**
- 평가할 모델 목록 (GPT-4, CodeBERT 등)
- 실험 설계 상세 계획
- Results 표 템플릿

**논문에 활용:**
- Experiments 섹션 작성
- 실제 실험 실행 가이드

#### 5️⃣ visualization_improvement.md → 그래프 개선
**AI가 제공할 것:**
- 기존 Figure 개선 제안
- 새로운 Figure 아이디어
- Publication-ready 캡션

**논문에 활용:**
- 현재 그래프 개선
- 추가 시각화 제작

---

### 🚀 실제 사용 순서

1. **benchmark_survey.md**를 ChatGPT에 입력
2. 받은 논문 목록에서 **실제 존재하는 것들 확인**
3. **detailed_comparison.md**로 비교표 생성
4. **paper_positioning.md**로 논문 초안 작성
5. **evaluation_protocol.md**로 실험 계획 수립
6. **실제 실험 실행** 후 결과 분석
7. **visualization_improvement.md**로 그래프 최종 다듬기

### 💡 주의사항

- AI 응답은 **초안**으로만 사용, 반드시 **fact-check** 필요
- **실제 논문들 확인**하여 정확한 citation 정보 수집
- **여러 AI 플랫폼 조합** 사용 권장 (ChatGPT + Claude + Perplexity)

### 📊 예상 최종 결과

이 프롬프트들을 활용하면 다음과 같은 **고품질 논문 요소**들을 얻을 수 있습니다:

- ✅ **실제 데이터 기반** 벤치마크 비교표
- ✅ **체계적인 Related Work** 섹션
- ✅ **명확한 Contribution** 정의
- ✅ **철저한 실험 설계** 계획
- ✅ **Publication-ready** 시각화

결과적으로 **논문 작성 시간을 70% 단축**하면서도 **학술적 품질을 보장**할 수 있습니다! 🎉
