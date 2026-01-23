# LangSmith 트레이싱 시작 가이드

**최종 업데이트**: 2026-01-14

---

## 🎯 LangSmith란?

LangChain 공식 관찰성(Observability) 플랫폼으로, 모든 에이전트 실행을 자동으로 추적하고 시각화합니다.

**무료 티어**: 매월 5,000 traces (우리 프로젝트에 충분)

---

## 📋 설정 방법 (5분)

### Step 1: 계정 생성 (무료)

1. https://smith.langchain.com 접속
2. Sign Up (GitHub 계정으로 가능)
3. 이메일 인증 완료

### Step 2: API 키 발급

1. 로그인 후 Settings > API Keys
2. "Create API Key" 클릭
3. 키 이름: `NetConfigQA3` (선택사항)
4. 생성된 키 복사: `ls-...`

### Step 3: 환경변수 설정

`config/.env` 파일을 열고 주석을 해제하세요:

```bash
# === LangSmith (무료 트레이싱) ===
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=ls-your-actual-key-here  # 여기에 발급받은 키 붙여넣기
LANGCHAIN_PROJECT=NetConfigQA3-Agent
LANGCHAIN_ENDPOINT=https://api.smith.langchain.com
```

---

## 🚀 사용 방법

### 즉시 사용 (코드 변경 없음!)

환경변수만 설정하면 **모든 에이전트 실행이 자동으로 추적됩니다**.

```bash
# 일반 에이전트 실행
python3 -m agent.core

# 또는 데모 스크립트
python3 test_with_langsmith.py
```

질문을 입력하면:
1. ✅ 자동으로 LangSmith에 기록됨
2. ✅ https://smith.langchain.com에서 실시간 확인 가능

---

## 📊 LangSmith에서 볼 수 있는 정보

### 1. 실행 타임라인

```
User Query: "네트워크에 어떤 장비가 있어?"
│
├─ [LLM Call] OpenAI gpt-4o-mini
│  ├─ Latency: 876ms
│  ├─ Tokens: 234 (input) + 156 (output)
│  └─ Cost: $0.0003
│
├─ [Tool] scan_network_devices
│  ├─ Input: {}
│  ├─ Output: []
│  └─ Duration: 45ms
│
└─ [LLM Call] OpenAI gpt-4o-mini (w/ tool result)
   ├─ Latency: 894ms
   ├─ Tokens: 340
   └─ Final Answer: "장비 목록이 없습니다"
```

### 2. 토큰 사용량 분석

- 프롬프트 토큰 vs 완성 토큰
- 누적 비용 (USD)
- 시간대별 사용량 그래프

### 3. 도구 실행 통계

- 가장 많이 호출된 도구
- 평균 실행 시간
- 성공/실패율

### 4. 에러 추적

- 에러 발생 지점 정확히 표시
- 스택 트레이스 자동 캡처
- 재현 가능한 입력 데이터 저장

---

## 🔍 LangSmith UI 사용법

### Traces 페이지

1. https://smith.langchain.com/traces 접속
2. 프로젝트 선택: `NetConfigQA3-Agent`
3. 각 trace를 클릭하면 상세 정보 표시

### 필터링

- **날짜**: 최근 1시간, 24시간, 7일
- **상태**: Success, Error
- **태그**: 사용자 정의 태그 추가 가능

### 비교 기능

두 개의 trace를 선택하여:
- 실행 시간 비교
- 토큰 사용량 비교
- 도구 호출 차이 분석

---

## 💡 고급 기능

### 1. 커스텀 메타데이터 추가

```python
from langsmith import traceable

@traceable(
    name="custom_analysis",
    metadata={"task_type": "bgp_troubleshooting"}
)
def analyze_bgp(device):
    # ...
```

### 2. 데이터셋 생성

LangSmith에서 실제 trace를 데이터셋으로 저장:
1. 좋은 응답을 골라 "Add to Dataset" 클릭
2. 회귀 테스트에 사용

### 3. Feedback 수집

```python
from langsmith import Client

client = Client()
client.create_feedback(
    run_id=run.id,
    key="user_satisfaction",
    score=0.9
)
```

---

## 🐛 문제 해결

### "Unauthorized" 에러

→ API 키 확인:
```bash
echo $LANGCHAIN_API_KEY  # ls-로 시작해야 함
```

### Trace가 안 보임

→ 프로젝트 이름 확인:
```bash
echo $LANGCHAIN_PROJECT  # NetConfigQA3-Agent
```

### 연결 속도가 느림

→ 비활성화 (선택사항):
```bash
export LANGCHAIN_TRACING_V2=false
```

---

## 📊 로컬 로그 vs LangSmith

| 기능 | 로컬 로그 | LangSmith |
|------|-----------|-----------|
| 도구 호출 기록 | ✅ | ✅ |
| LLM 요청/응답 | ❌ | ✅ |
| 시각화 | ❌ | ✅ |
| 토큰 추적 | ❌ | ✅ |
| 검색/필터 | ❌ | ✅ |
| 비용 분석 | ❌ | ✅ |
| 팀 공유 | ❌ | ✅ |

**추천**: LangSmith + 로컬 로그 병행 사용

---

## 🎓 학습 자료

- **공식 문서**: https://docs.smith.langchain.com
- **YouTube**: [LangSmith Tutorial](https://www.youtube.com/watch?v=...)
- **예제**: https://github.com/langchain-ai/langsmith-cookbook

---

## 💰 가격 정책 (2024년 기준)

| 플랜 | 가격 | Traces/월 | 데이터 보관 |
|------|------|-----------|-------------|
| Free | $0 | 5,000 | 14일 |
| Plus | $39 | 50,000 | 90일 |
| Pro | Custom | Unlimited | Custom |

**우리 프로젝트**: Free 티어로 충분 (연구용)

---

## ✅ 체크리스트

- [ ] LangSmith 계정 생성
- [ ] API 키 발급
- [ ] `config/.env`에 설정 추가
- [ ] `test_with_langsmith.py` 실행
- [ ] https://smith.langchain.com에서 trace 확인

---

**다음 단계**: LangSmith Studio도 사용해보세요 (LangGraph 전용 IDE)
