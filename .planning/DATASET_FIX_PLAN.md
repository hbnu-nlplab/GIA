# 데이터셋 파이프라인 수정 계획

**작성일:** 2026-03-18
**근거:** 5개 병렬 에이전트 심층 분석
**영향 범위:** policies.json + builder_core.py + main_batfish.py
**데이터셋 재생성 필요:** YES (수정 후 Lab-B/C/D 재생성)

---

## Phase 1: answer_type 통일 (CRITICAL) — 1시간

### Task 1.1: policies.json 비표준 타입 수정
```
"number"   → "scalar_int"  (5개: static_route_count 등)
"edge_set" → "set_str"     (1개: l2vpn_pairs)
"json"     → "set_str"     (1개: ospf_compatibility_check)
```

### Task 1.2: builder_core.py 반환 타입 통일
```
"numeric" → "scalar_int"  (19개 메트릭)
"set"     → "set_str"     (45개 메트릭)
"map"     → "map_str_int" / "map_str_str" (4개 메트릭)
```

### Task 1.3: policies.json level 수정
```
ospf_area0_routers:       L5 → L2
ospf_area0_if_count:      L2 → L1
vrf_interface_bind_count: L3 → L1
serial/tunnel/port/vlan_interface_devices: L1 → L2
```

---

## Phase 2: 로직 버그 수정 (CRITICAL/HIGH) — 2시간

### Task 2.1: devices_in_as 타입 비교 수정
파일: builder_core.py:1272-1276
```python
# 현재: int(65000) != str("65000")
# 수정: str(las) == str(asn)
```

### Task 2.2: iBGP fullmesh loopback 검증 개선
파일: builder_core.py:237-239
```
CE에 loopback 없는 경우 → 물리 IP 기반 peering도 확인
```

### Task 2.3: ibgp_under_peered_devices 비교 통일
파일: builder_core.py:251-259
```
expected (loopback 수) vs peers (raw IP 수) → 동일 기준으로 비교
```

### Task 2.4: vrf_without_rt_pairs 소스 통일
파일: builder_core.py:265-271
```
_services_vrf → _merged_bgp_vrfs_for_rt 로 통일
```

### Task 2.5: compute() bare except 로그 추가
파일: builder_core.py:361-378
```python
except Exception as e:
    logger.error("compute(%s) failed: %s", metric, e)
    return {"answer_type": "error", "value": None}
```

---

## Phase 3: 파이프라인 조립 수정 (HIGH) — 1시간

### Task 3.1: oracle_source 동적 할당
파일: main_batfish.py:984
```python
oracle_source = infer_oracle_source(metric_name, level)
```

### Task 3.2: scope JSON 직렬화
파일: main_batfish.py:967
```python
json.dumps(scope, ensure_ascii=False)  # repr() 대신
```

### Task 3.3: L4/L5 예외 카운터 + 로그
파일: main_batfish.py:810-814
```python
except Exception as e:
    l45_errors += 1
    logger.error("L4/L5 %s failed: %s", metric, e, exc_info=True)
```

### Task 3.4: L4/L5 answer_status 전파
파일: main_batfish.py:1061
```python
answer_status = q.get("answer_status", "OK")  # 무조건 OK 대신
```

---

## Phase 4: L4-L5 안정성 (MEDIUM) — 30분

### Task 4.1: SPOF 감지 과보고 문서화
→ 논문 methodology에 "single-path SPOF만 감지" 명시

### Task 4.2: link_failure_impact 경로 결정론
```python
sorted(accepted_paths, key=lambda p: (len(p), str(p)))[0]  # 길이+이름 정렬
```

---

## 실행 후: 데이터셋 재생성

```bash
# Lab-B 재생성
python Make_Dataset/src/main_batfish.py \
  --lab-path Data/Pnetlab/LabB_NCN_Basic_SP_20nodes \
  --policies Make_Dataset/policies.json

# 품질 검증
python Make_Dataset/src/validate_dataset_quality.py \
  Data/Pnetlab/LabB_NCN_Basic_SP_20nodes/Dataset/
```

---

## 예상 시간

| Phase | 시간 | 효과 |
|-------|------|------|
| Phase 1 | 1시간 | TA-Acc 채점 정상화 |
| Phase 2 | 2시간 | 정답 정확성 보장 |
| Phase 3 | 1시간 | 파이프라인 무결성 |
| Phase 4 | 30분 | L5 결정론 + 문서화 |
| 재생성 | 30분 | Lab-B 새 데이터셋 |
| **총** | **~5시간** | |

---
*5개 병렬 에이전트 분석 기반 — 2026-03-18*
