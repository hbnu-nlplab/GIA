# Method 3 — PNETLab 실환경 검증 가이드

> **목적**: Batfish 시뮬레이션 결과를 실제 Cisco IOS 라우터에서 검증
> **대상**: L4-L5 계층화 표본 44개 QA
> **소요 시간**: 약 4-6시간 (환경 구축 1h + L4 1.5h + L5 2.5h)
> **필요**: PNETLab 서버 + Cisco IOSv 15.7 이미지

---

## 전체 검증 흐름 (3가지 Method)

```
┌─────────────────────────────────────────────────────────────────────┐
│               NetConfigQA2.0 Ground Truth Verification              │
├─────────────────────┬──────────────────┬────────────────────────────┤
│  Method 1           │  Method 2        │  Method 3                  │
│  독립 파서 (자동)   │  사람 검토 (수동)│  PNETLab 실환경 (수동)     │
│                     │                  │                            │
│  L1-L3 전수         │  L1-L3 표본      │  L4-L5 표본                │
│  Python+Regex       │  눈+.cfg+체크리스트│  CLI: traceroute/ping     │
└─────────────────────┴──────────────────┴────────────────────────────┘
```

---
## Phase 0: PNETLab 환경 준비

### 토폴로지: LabA_Research_Institute_DC_10nodes (10 nodes)

장비 목록: leaf1, leaf2, leaf3, leaf4, p1, p2, p3, p4, pe1, pe2

### Config 적용 방법
1. PNETLab 웹 UI에서 토폴로지 시작
2. 각 노드 콘솔 접속 → `configs/*.cfg` 내용 copy/paste
3. 프로토콜 수렴 대기 (약 2분)

### 수렴 확인 명령
```
# show ip ospf neighbor           ! 모두 FULL 상태여야 함
# show ip bgp vpnv4 all summary   ! Established 확인
# show mpls ldp neighbor           ! LDP 세션 확인
```

---
## Phase 1: L4 검증 (23개)

### L4-1. ACL_BLOCKING_leaf4_leaf3
- **메트릭**: `acl_blocking_point`
- **질문**: 172.16.4.2에서 172.16.3.2로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
LEAF4# traceroute 172.16.3.2
LEAF4# show ip access-lists
! LEAF3 장비도 확인: LEAF3# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-2. ACL_BLOCKING_leaf4_p2
- **메트릭**: `acl_blocking_point`
- **질문**: 172.16.4.2에서 10.0.0.1로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
LEAF4# traceroute 10.0.0.1
LEAF4# show ip access-lists
! P2 장비도 확인: P2# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-3. ACL_BLOCKING_leaf4_pe2
- **메트릭**: `acl_blocking_point`
- **질문**: 172.16.4.2에서 10.0.1.3로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
LEAF4# traceroute 10.0.1.3
LEAF4# show ip access-lists
! PE2 장비도 확인: PE2# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-4. ASYMMETRIC_leaf1_p1
- **메트릭**: `asymmetric_path_comparison`
- **질문**: leaf1과 p1 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: leaf1 -> pe1, Reverse: p1"`

```
! 양방향 경로 확인:
LEAF1# traceroute <P1 loopback IP>
P1# traceroute <LEAF1 loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-5. ASYMMETRIC_pe2_leaf3
- **메트릭**: `asymmetric_path_comparison`
- **질문**: pe2와 leaf3 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: pe2, Reverse: leaf3 -> pe2"`

```
! 양방향 경로 확인:
PE2# traceroute <LEAF3 loopback IP>
LEAF3# traceroute <PE2 loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-6. ASYMMETRIC_pe2_pe1
- **메트릭**: `asymmetric_path_comparison`
- **질문**: pe2와 pe1 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: pe2 -> p3 -> p2 -> pe1, Reverse: pe1 -> p2 -> p3 -> pe2"`

```
! 양방향 경로 확인:
PE2# traceroute <PE1 loopback IP>
PE1# traceroute <PE2 loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-7. BLACKHOLE_DETECTION_GLOBAL
- **메트릭**: `blackhole_destination_list`
- **질문**: 네트워크에서 블랙홀이 발생하는 목적지 prefix 목록을 알려주세요. [답변 형식: prefix 목록 (예: ["10.0.0.0/8", "192.168.1.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! Blackhole 목적지 확인:
! 각 장비에서 목적지로 ping/traceroute:
# ping <target_ip>
# traceroute <target_ip>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-8. BOUNDED_PATH_leaf2_leaf4
- **메트릭**: `bounded_path_length`
- **질문**: leaf2에서 172.16.4.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `2`

```
! LEAF2에서 LEAF4까지 홉 수 확인:
LEAF2# traceroute LEAF4
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-9. BOUNDED_PATH_leaf4_p4
- **메트릭**: `bounded_path_length`
- **질문**: leaf4에서 10.0.0.5로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `2`

```
! LEAF4에서 P4까지 홉 수 확인:
LEAF4# traceroute P4
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-10. BOUNDED_PATH_p1_p3
- **메트릭**: `bounded_path_length`
- **질문**: p1에서 10.0.0.3로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `3`

```
! P1에서 P3까지 홉 수 확인:
P1# traceroute P3
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-11. ISOLATION_VRF_AI_VRF_BIO
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_AI와 VRF_BIO 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! VRF 간 경로 누출 확인:
# show ip route vrf <vrf_name>
# show ip bgp vpnv4 vrf <vrf_name>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-12. ISOLATION_VRF_AI_VRF_HPC
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_AI와 VRF_HPC 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! VRF 간 경로 누출 확인:
# show ip route vrf <vrf_name>
# show ip bgp vpnv4 vrf <vrf_name>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-13. ISOLATION_VRF_AI_default
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_AI와 default 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! VRF 간 경로 누출 확인:
# show ip route vrf <vrf_name>
# show ip bgp vpnv4 vrf <vrf_name>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-14. LOOP_DETECTION_GLOBAL
- **메트릭**: `loop_detection`
- **질문**: 네트워크에 포워딩 루프가 존재합니까? [답변 형식: 'NONE' 또는 'Found: A→B→C→A']
- **데이터셋 정답**: `"NONE"`

```
! 루프 탐지:
# traceroute <target_ip>
! 동일 홉이 반복되면 루프 존재
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-15. REACH_leaf1_p4_TCP
- **메트릭**: `reachability_status`
- **질문**: 172.16.1.2에서 10.0.0.5(22/TCP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: leaf1 -> pe1; REACHABLE: FALSE; REASON: NO_ROUTE"`

```
! LEAF1에서 10.0.0.5 도달성 확인:
LEAF1# ping 10.0.0.5
LEAF1# traceroute 10.0.0.5
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-16. REACH_leaf2_p4_ICMP
- **메트릭**: `reachability_status`
- **질문**: 172.16.2.2에서 10.0.0.5(0/ICMP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: leaf2 -> pe1; REACHABLE: FALSE; REASON: NO_ROUTE"`

```
! LEAF2에서 10.0.0.5 도달성 확인:
LEAF2# ping 10.0.0.5
LEAF2# traceroute 10.0.0.5
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-17. REACH_p4_p3_ICMP
- **메트릭**: `reachability_status`
- **질문**: 10.0.0.5에서 10.0.0.3(0/ICMP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: p4 -> p3; REACHABLE: TRUE"`

```
! P4에서 10.0.0.3 도달성 확인:
P4# ping 10.0.0.3
P4# traceroute 10.0.0.3
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-18. TRACEROUTE_leaf4_leaf3
- **메트릭**: `traceroute_path`
- **질문**: 172.16.4.2에서 172.16.3.2까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"leaf4 -> pe2"`

```
! LEAF4에서 LEAF3으로 경로 추적:
LEAF4# traceroute LEAF3
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-19. TRACEROUTE_leaf4_p4
- **메트릭**: `traceroute_path`
- **질문**: 172.16.4.2에서 10.0.0.5까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"leaf4 -> pe2"`

```
! LEAF4에서 P4으로 경로 추적:
LEAF4# traceroute P4
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-20. TRACEROUTE_pe2_leaf3
- **메트릭**: `traceroute_path`
- **질문**: 10.0.1.3에서 172.16.3.2까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"pe2"`

```
! PE2에서 LEAF3으로 경로 추적:
PE2# traceroute LEAF3
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-21. WAYPOINT_leaf1_p3_leaf1
- **메트릭**: `waypoint_traversal_path`
- **질문**: 172.16.1.2에서 10.0.0.3로 가는 트래픽이 leaf1를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"leaf1 -> pe1"`

```
! Waypoint 경유 확인:
172.16.1.2# traceroute 10.0.0.3
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-22. WAYPOINT_leaf1_p3_leaf2
- **메트릭**: `waypoint_traversal_path`
- **질문**: 172.16.1.2에서 10.0.0.3로 가는 트래픽이 leaf2를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"NOT_TRAVERSED"`

```
! Waypoint 경유 확인:
172.16.1.2# traceroute 10.0.0.3
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-23. WAYPOINT_leaf1_p3_leaf4
- **메트릭**: `waypoint_traversal_path`
- **질문**: 172.16.1.2에서 10.0.0.3로 가는 트래픽이 leaf4를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"NOT_TRAVERSED"`

```
! Waypoint 경유 확인:
172.16.1.2# traceroute 10.0.0.3
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

---
## Phase 2: L5 검증 (21개)

> **주의**: L5는 failure injection 후 반드시 **원복(no shutdown)**해야 합니다!

### L5-1. CONFIG_CHANGE_BASELINE
- **메트릭**: `config_change_impact`
- **질문**: 설정 변경 후 leaf1에서 p3까지의 경로/도달성 변경 여부를 알려주세요. [답변 형식: 'NO_CHANGE' 또는 'CHANGED (N건: 흐름1, 흐름2, ...)']
- **데이터셋 정답**: `"CHANGED (25 entries: 10.10.1.1 -> 10.10.10.32, 172.16.1.3 -> 10.10.10.32, 192.168.100.2 -> 10.10.10.32)"`

```
! 메트릭: config_change_impact
! scope: {"type": "SNAPSHOT_DIFF", "src": "leaf1", "dst": "p3"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-2. DIFF_REACH_BASELINE
- **메트릭**: `differential_reachability`
- **질문**: 변경 전후 leaf1에서 p3로의 도달성에 차이가 있습니까? [답변 형식: 'NO_DIFF' 또는 'DIFF (N건: 흐름1, 흐름2, ...)']
- **데이터셋 정답**: `"NO_DIFF"`

```
! 메트릭: differential_reachability
! scope: {"type": "SNAPSHOT_DIFF", "src": "leaf1", "dst": "p3"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-3. DUAL_FAILURE_leaf1_leaf2
- **메트릭**: `redundancy_verification`
- **질문**: leaf1과 leaf2가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"15"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-4. DUAL_FAILURE_leaf3_leaf4
- **메트릭**: `redundancy_verification`
- **질문**: leaf3과 leaf4가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"18"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-5. DUAL_FAILURE_p1_p2
- **메트릭**: `redundancy_verification`
- **질문**: p1과 p2가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"17"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-6. K_FAILURE_leaf1_p3
- **메트릭**: `redundant_paths_list`
- **질문**: leaf1에서 10.0.0.3로 가는 대체 경로들을 모두 나열해주세요. [답변 형식: 경로 목록 (예: ["A→B→C", "A→D→C"])]
- **데이터셋 정답**: `["leaf1 → pe1", "leaf1"]`

```
! 이중화 경로 확인:
LEAF1# show ip route ?
LEAF1# traceroute ?
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-7. MULTI_FAIL_leaf1_p1_leaf2_p4
- **메트릭**: `multi_link_failure_reachability`
- **질문**: (시나리오) 'leaf1-p1' 링크와 'leaf2-p4' 링크가 동시에 다운되었습니다. 이 상황에서 'leaf4'에서 'p3'로의 트래픽 전달이 가능합니까? [답변 형식: 'REROUTED (path: A→B→C)' 또는 'DISCONNECTED (reason: ...)']
- **데이터셋 정답**: `"DISCONNECTED (reason: NO_ROUTE at pe2)"`

```
! 다중 링크 장애 시뮬레이션:
! === 원복 ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-8. MULTI_FAIL_leaf1_pe1_leaf2_leaf3
- **메트릭**: `multi_link_failure_reachability`
- **질문**: (시나리오) 'leaf1-pe1' 링크와 'leaf2-leaf3' 링크가 동시에 다운되었습니다. 이 상황에서 'leaf4'에서 'p3'로의 트래픽 전달이 가능합니까? [답변 형식: 'REROUTED (path: A→B→C)' 또는 'DISCONNECTED (reason: ...)']
- **데이터셋 정답**: `"DISCONNECTED (reason: NO_ROUTE at pe2)"`

```
! 다중 링크 장애 시뮬레이션:
! === 원복 ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-9. MULTI_FAIL_leaf1_pe2_leaf3_p4
- **메트릭**: `multi_link_failure_reachability`
- **질문**: (시나리오) 'leaf1-pe2' 링크와 'leaf3-p4' 링크가 동시에 다운되었습니다. 이 상황에서 'leaf2'에서 'p3'로의 트래픽 전달이 가능합니까? [답변 형식: 'REROUTED (path: A→B→C)' 또는 'DISCONNECTED (reason: ...)']
- **데이터셋 정답**: `"DISCONNECTED (reason: NO_ROUTE at pe1)"`

```
! 다중 링크 장애 시뮬레이션:
! === 원복 ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-10. NEGATIVE_TEST_FAKE_NODE
- **메트릭**: `non_existent_node_check`
- **질문**: non_existent_router_999 장비가 다운되면 몇 개의 트래픽 흐름이 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `0`

```
! 존재하지 않는 노드 확인:
# show ip ospf neighbor
# show ip bgp summary
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-11. NODE_FAILURE_leaf1
- **메트릭**: `node_failure_impact`
- **질문**: leaf1 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `16`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-12. NODE_FAILURE_leaf2
- **메트릭**: `node_failure_impact`
- **질문**: leaf2 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `17`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-13. NODE_FAILURE_leaf4
- **메트릭**: `node_failure_impact`
- **질문**: leaf4 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `18`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-14. OSPF_AREA0_ROUTERS_GLOBAL
- **메트릭**: `ospf_area0_routers`
- **질문**: OSPF Backbone Area(Area 0)에 속한 라우터 목록은 무엇입니까? [답변 형식: 라우터 이름 목록 (예: ["spine1", "spine2", "p1"])]
- **데이터셋 정답**: `["p1", "p2", "p3", "p4", "pe1"]`

```
! OSPF Area 0 라우터 확인:
# show ip ospf neighbor
# show ip ospf interface brief
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-15. POLICY_COMPLIANCE_leaf1
- **메트릭**: `policy_compliance_check`
- **질문**: 'MANDATORY_WAYPOINT_leaf1' 정책 준수 여부와 위반 사례를 알려주세요. [답변 형식: 'COMPLIANT' 또는 'VIOLATION: 흐름1, 흐름2, ...']
- **데이터셋 정답**: `"VIOLATION: 10.10.1.1 -> 8.8.8.8, 172.16.1.3 -> 8.8.8.8, 192.168.100.2 -> 8.8.8.8"`

```
! 메트릭: policy_compliance_check
! scope: {"type": "POLICY", "policy_name": "MANDATORY_WAYPOINT_leaf1", "src": "leaf1"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-16. ROOT_CAUSE_leaf4_leaf3
- **메트릭**: `root_cause_analysis`
- **질문**: leaf4에서 leaf3로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe2"`

```
! 장애 원인 분석:
# show ip ospf neighbor
# show ip bgp summary
# show ip route
! 장애 적용 후 위 명령으로 영향 범위 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-17. ROOT_CAUSE_leaf4_p4
- **메트릭**: `root_cause_analysis`
- **질문**: leaf4에서 p4로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe2"`

```
! 장애 원인 분석:
# show ip ospf neighbor
# show ip bgp summary
# show ip route
! 장애 적용 후 위 명령으로 영향 범위 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-18. ROOT_CAUSE_pe2_leaf3
- **메트릭**: `root_cause_analysis`
- **질문**: pe2에서 leaf3로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe2"`

```
! 장애 원인 분석:
# show ip ospf neighbor
# show ip bgp summary
# show ip route
! 장애 적용 후 위 명령으로 영향 범위 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-19. SPOF_DETECTION_GLOBAL
- **메트릭**: `spof_detection`
- **질문**: 단일 장비 장애 시 통신이 두절되는 구간(SPOF: Single Point of Failure)이 존재합니까? [답변 형식: SPOF 장비 목록 (예: ["p1", "pe1"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! Single Point of Failure 탐지:
! 각 링크/노드를 하나씩 다운시키며 전체 도달성 확인
! 1개 장애로 전체 통신 불가 → SPOF
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-20. TRIPLE_FAILURE_leaf1_leaf2_leaf3
- **메트릭**: `triple_node_failure`
- **질문**: leaf1, leaf2, leaf3가 동시에 다운되면 네트워크가 완전히 분리됩니까? [답변 형식: 'YES' 또는 'NO (affected_flows: N)']
- **데이터셋 정답**: `"NO (affected_flows: 15)"`

```
! 다중 노드 장애: []
! 장애 적용 후 도달성 확인
! === 원복 ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-21. WORST_CASE_FAILURE
- **메트릭**: `worst_case_failure_analysis`
- **질문**: 단일 장비 장애 시 가장 큰 영향을 주는 장비는? [답변 형식: 'device_name (N)']
- **데이터셋 정답**: `"p2(19)"`

```
! 최악 시나리오 분석:
! 주요 백본 링크를 순차적으로 다운
! 각 단계에서 도달성 변화 관찰
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE
