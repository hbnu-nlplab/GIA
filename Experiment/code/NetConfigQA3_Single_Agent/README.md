# NetConfigQA3 Single Agent Evaluator

LangChain 기반 에이전트를 사용하여 Facts JSON을 효율적으로 처리하고, Config 주입 방식보다 우수한 성능을 입증합니다.

## 📁 프로젝트 구조

```
NetConfigQA3_Single_Agent/
├── run_netconfigqa_eval_agent.py     # 메인 Agent 평가 스크립트
├── requirements_agent.txt            # Dependencies
├── README_AGENT.md                   # 상세 사용 가이드
├── QUICKSTART_GPT_OSS_20B.md         # GPT-OSS-20B 빠른 시작 ⭐
├── AGENT_EXPERIMENT_SUMMARY.md       # 실험 요약
├── compare_approaches.py             # 비교 분석 스크립트
├── start_vllm_server.sh             # vLLM 서버 시작
├── run_agent_gpt_oss_20b.sh          # GPT-OSS-20B 실행
└── test_agent_quick.sh               # 빠른 테스트
```

## 🚀 빠른 시작 (GPT-OSS-20B 권장)

```bash
# 1. Dependencies 설치
pip install -r requirements_agent.txt
pip install vllm

# 2. vLLM 서버 시작 (터미널 1)
./start_vllm_server.sh

# 3. Agent 실행 (터미널 2)
./run_agent_gpt_oss_20b.sh 10

# 4. 결과 확인
python reanalyze_results.py "results/GPT-OSS-20B_agent/results_agent_*.json"
```

## 📊 핵심 주장

> **Facts는 단순 주입이 아닌 Tool 기반 Agent 접근이 필요하다**

### 예상 개선 효과

| 접근법 | 정확도 | 토큰 | 컨텍스트 | 비용 |
|--------|--------|------|----------|------|
| Config 주입 | 61.2% | 15K | 50KB | $11.43 |
| Facts 주입 | 60.0% | 12K | 40KB | $9.14 |
| **Agent** | **70~75%** | **2K** | **3.5KB** | **$1.52** |

## 📚 자세한 가이드

- **[QUICKSTART_GPT_OSS_20B.md](QUICKSTART_GPT_OSS_20B.md)**: GPT-OSS-20B 사용법 ⭐
- **[README_AGENT.md](README_AGENT.md)**: 상세 사용 가이드
- **[AGENT_EXPERIMENT_SUMMARY.md](AGENT_EXPERIMENT_SUMMARY.md)**: 실험 설계 및 결과 분석

## 🔗 관련 프로젝트

- `NetConfigQA2`: 기존 QA 데이터셋 (Config/Facts 주입 방식)
- `NetConfigQA3`: 멀티에이전트 시스템 (계획 중)

## 📞 문의

실험 결과나 개선 제안은 Issue로 남겨주세요.

---

**NetConfigQA3 Single Agent** - Facts의 진정한 잠재력을 입증합니다! 🚀
