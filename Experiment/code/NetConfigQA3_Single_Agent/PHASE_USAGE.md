# Phase 옵션 사용 가이드

## Phase 개요

NetConfigQA Agent는 실험 단계에 따라 도구 구성을 다르게 설정할 수 있습니다.

### Phase 3: Evidence-only Tools (기본값, 현재 단계)

**목표**: LLM이 Facts를 직접 조회하여 추론하도록 함. 도구는 **정보만 제공**하고, 경로 계산/분석 결과는 제공하지 않음.

**사용 도구**:
- `query_device`: 장비의 특정 필드 조회
- `list_all_devices`: 모든 장비 목록 조회
- `interface_status_map`: 인터페이스 상태 맵 조회
- `calculate_routing_entries`: 라우팅 엔트리 개수 계산
- `ip_owner_evidence`: IP 소유자 정보 조회 (Evidence only)
- `subnet_members_evidence`: 서브넷 멤버 조회 (Evidence only)
- `device_interfaces_evidence`: 장비 인터페이스 목록 조회 (Evidence only)
- `device_routing_evidence`: 장비 라우팅 정보 조회 (Evidence only)

**특징**:
- L4/L5 (Traceroute/Reachability) 질문도 **LLM이 직접 추론**해야 함
- 도구는 "이 IP는 누가 갖고 있어?", "이 서브넷에 누가 있어?" 같은 **근거만 제공**
- 경로 계산, 도달성 판단은 **LLM의 몫**

**실행 예시**:
```bash
# Phase 3 (기본값)
./run_agent_gpt_oss_20b.sh 50

# 명시적으로 Phase 3 지정
./run_agent_gpt_oss_20b.sh 50 3

# 또는 직접 실행
python3 run_netconfigqa_eval_agent.py \
  --facts <facts_file> \
  --questions <questions_file> \
  --backend vllm_server \
  --model GPT-OSS-20B \
  --phase 3 \
  --sample 50
```

### Phase 5: Analysis Tools (향후 Batfish 통합용)

**목표**: 분석 엔진(예: Batfish)과 통합하여 **도구가 경로/도달성 분석 결과를 직접 반환**하도록 함.

**사용 도구** (예정):
- Phase 3의 모든 도구 +
- `batfish_traceroute`: Batfish를 통한 경로 추적
- `batfish_reachability`: Batfish를 통한 도달성 분석
- `batfish_policy_check`: Batfish를 통한 정책 검증

**특징**:
- L4/L5 질문에서 **도구가 정답에 가까운 분석 결과를 반환**
- LLM은 주로 **결과 요약/설명** 역할

**실행 예시**:
```bash
# Phase 5
./run_agent_gpt_oss_20b.sh 50 5

# 또는 직접 실행
python3 run_netconfigqa_eval_agent.py \
  --facts <facts_file> \
  --questions <questions_file> \
  --backend vllm_server \
  --model GPT-OSS-20B \
  --phase 5 \
  --sample 50
```

**주의**: Phase 5는 현재 도구 구현이 완료되지 않았습니다. Batfish 통합 후 사용 가능합니다.

## Phase 비교 실험

Phase 3과 Phase 5의 성능을 비교하려면:

```bash
# 1. Phase 3 실행 (Evidence-only)
./run_agent_gpt_oss_20b.sh 200 3

# 2. Phase 5 실행 (Analysis tools, 향후)
./run_agent_gpt_oss_20b.sh 200 5

# 3. 결과 비교
python3 analyze_results_netconfigqa_agent.py \
  results/GPT-OSS-20B_agent/results_agent_<timestamp_phase3>.json

python3 analyze_results_netconfigqa_agent.py \
  results/GPT-OSS-20B_agent/results_agent_<timestamp_phase5>.json
```

## 실험 목표별 권장 Phase

| 실험 목표 | 권장 Phase | 이유 |
|----------|-----------|------|
| LLM 추론 능력 평가 | Phase 3 | 도구는 정보만 제공, LLM이 직접 추론 |
| Facts vs Config 비교 | Phase 3 | 공정한 비교를 위해 동일한 입력 방식 사용 |
| Batfish vs LLM 비교 | Phase 5 | 분석 엔진의 정확도를 LLM과 비교 |
| Level1 Map + Evidence Pack 실험 | Phase 4 (예정) | 입력 방식 최적화 실험 |

## FAQ

**Q: Phase 3에서 L4/L5 질문의 정확도가 낮은데, Phase 5로 바꾸면 좋아지나요?**

A: 네, Phase 5에서는 Batfish가 경로/도달성을 계산해주므로 L4/L5 정확도가 크게 향상될 것으로 예상됩니다. 하지만 이는 "LLM 추론"이 아니라 "분석 엔진 활용"이므로, 실험 목표에 따라 선택해야 합니다.

**Q: Phase 3에서 `max_iterations=25`인데도 "Agent stopped" 오류가 나요.**

A: L4/L5 질문은 여러 장비를 거쳐야 하므로 25회로도 부족할 수 있습니다. 필요시 `run_netconfigqa_eval_agent.py`의 `max_iterations` 값을 늘리거나, 프롬프트를 개선하여 LLM이 더 효율적으로 도구를 사용하도록 유도하세요.

**Q: Phase 4는 어디 있나요?**

A: Phase 4는 "Level1 Map + Level2 Evidence Pack" 실험을 위한 단계로, 아직 구현되지 않았습니다. `AGENT_EXPERIMENT_SUMMARY.md`에 템플릿이 준비되어 있습니다.

