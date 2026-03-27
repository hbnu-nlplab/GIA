# agents_netally — MAS + MCP Tool Integration

agents_v3(팀원 MAS)를 기반으로 MCP 도구 호출을 통합한 NetAlly 전용 Multi-Agent System.

## Architecture

```
User Question + level + answer_type
        |
[Collector] -- LLM이 도구 카탈로그 보고 MCP 도구 자율 선택/호출
        |      (nso_get_device_info, batfish_traceroute 등)
        v
[Verifier]  -- 도구 결과면 bypass (이미 구조화), static context면 필터링
        |
        v
[Synthesizer] -- passage + answer_type 포맷 힌트로 답변 생성
        |
        v
[Supporter] <-> [Skeptic] -- 적대적 토론 (ACCEPT/CONTINUE/NEED_MORE_INFO)
        |
        v
final_answer
```

## vs agents_v3 (원본)

| 항목 | agents_v3 | agents_netally |
|------|-----------|----------------|
| Collector 입력 | static config 텍스트 | **MCP 도구 호출** |
| 도구 선택 | 없음 | LLM 프롬프트 기반 자율 선택 |
| Verifier | LLM 필터링 | 도구 결과면 bypass |
| Synthesizer | 기본 | answer_type 포맷 힌트 추가 |
| Skeptic | config 텍스트 검증 | 도구 결과도 유효한 evidence로 인정 |
| 5-agent 구조 | 동일 | **동일** |
| debate loop | inner 3, outer 3 | inner 2, outer 2 |

## Files

| File | Description |
|------|-------------|
| `state.py` | NetAgentState + tool fields (tool_calls_log, tool_results_raw, tool_catalog) |
| `model_loader.py` | OpenRouter/OpenAI dual-model (A: synthesis, B: collection/critique) |
| `tool_dispatch.py` | LLM tool planning + async MCP execution + result formatting |
| `debate1.py` | Collector(MCP도구), Verifier(bypass), Synthesizer(포맷힌트) |
| `debate2.py` | Supporter, Skeptic(도구 관대화 프롬프트) |
| `main_netally.py` | Entry point: build_graph() + init_models() |

## Usage

### Web UI (NetAlly 서버 경유)
```bash
# .env 설정
NETALLY_AGENT_BACKEND=team_multi_adapter
NETALLY_TEAM_MULTI_MODULE=agents_netally.main_netally
NETALLY_TEAM_MULTI_ROOT=/path/to/NetAlly

./scripts/demo_up_local.sh
```

### Direct Evaluation (서버 없이)
```bash
# MCP 서버만 필요 (NSO/Batfish 도구용)
python scripts/run_netally_eval_direct.py \
  --dataset ../Data/Pnetlab/LabB_.../en.json \
  --lab Lab-B --limit 100

# 레벨 필터링
python scripts/run_netally_eval_direct.py \
  --dataset ... --include-levels L4 L5

# 결과 채점 (analyze_results.py 호환)
python ../Experiment/code/NetConfigQA2_2/analyze_results.py results/netally_eval_direct_*.json
```

### 병렬 실행 (프로세스 분할)
```bash
python scripts/run_netally_eval_direct.py --include-levels L1 &
python scripts/run_netally_eval_direct.py --include-levels L2 &
python scripts/run_netally_eval_direct.py --include-levels L3 &
python scripts/run_netally_eval_direct.py --include-levels L4 L5 &
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| OPENROUTER_API_KEY | - | OpenRouter API 키 (우선) |
| OPENAI_API_KEY | - | OpenAI 직접 키 (fallback) |
| NETALLY_MAS_MODEL_A | gpt-4o-mini | Synthesizer/Verifier/Supporter 모델 |
| NETALLY_MAS_MODEL_B | (=Model A) | Collector/Skeptic 모델 |
| NETALLY_MCP_SERVER_URL | http://127.0.0.1:8811/mcp | MCP 서버 주소 |

## Evaluation Metrics

| Metric | Field | Description |
|--------|-------|-------------|
| TA-Acc | analyze_results.py | answer_type별 맞춤 비교 |
| Latency | latency_ms | 질문당 응답 시간 |
| Tool calls | mas_tool_calls | MCP 도구 호출 이력 |
| Debate rounds | mas_outer_loops, mas_inner_turns | MAS debate 깊이 |
| Skeptic verdict | mas_status | ACCEPT/CONTINUE/NEED_MORE_INFO |
| Format stability | format_parseable, format_completeness | 답변 포맷 파싱 성공률 |
| NOT_CONFIGURED | answer_status | 할루시네이션 탐지 (Negative testing) |
