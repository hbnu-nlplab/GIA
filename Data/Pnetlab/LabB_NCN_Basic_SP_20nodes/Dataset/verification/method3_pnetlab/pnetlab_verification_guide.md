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

### 토폴로지: LabB_NCN_Basic_SP_20nodes (20 nodes)

장비 목록: leaf1, leaf2, leaf3, leaf4, leaf5, leaf6, leaf7, leaf8, p1, p2, p3, p4, p5, p6, p7, p8, pe1, pe2, pe3, pe4

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

### L4-1. ACL_BLOCKING_leaf2_p6
- **메트릭**: `acl_blocking_point`
- **질문**: 172.16.2.2에서 10.0.12.1로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
LEAF2# traceroute 10.0.12.1
LEAF2# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-2. ACL_BLOCKING_leaf7_p6
- **메트릭**: `acl_blocking_point`
- **질문**: 172.17.3.2에서 10.0.12.1로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
?# traceroute 10.0.12.1
?# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-3. ACL_BLOCKING_p2_p7
- **메트릭**: `acl_blocking_point`
- **질문**: 10.0.2.1에서 10.0.15.1로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
P2# traceroute 10.0.15.1
P2# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-4. ASYMMETRIC_leaf7_leaf1
- **메트릭**: `asymmetric_path_comparison`
- **질문**: leaf7과 leaf1 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: leaf7 -> pe4, Reverse: leaf1 -> pe1"`

```
! 양방향 경로 확인:
LEAF1# traceroute <? loopback IP>
?# traceroute <LEAF1 loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-5. ASYMMETRIC_p3_pe3
- **메트릭**: `asymmetric_path_comparison`
- **질문**: p3과 pe3 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: p3 -> p5 -> pe3, Reverse: pe3 -> p5 -> p3"`

```
! 양방향 경로 확인:
P3# traceroute <? loopback IP>
?# traceroute <P3 loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-6. ASYMMETRIC_pe3_leaf4
- **메트릭**: `asymmetric_path_comparison`
- **질문**: pe3과 leaf4 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: pe3, Reverse: leaf4 -> pe2"`

```
! 양방향 경로 확인:
LEAF4# traceroute <? loopback IP>
?# traceroute <LEAF4 loopback IP>
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

### L4-8. BOUNDED_PATH_leaf2_p6
- **메트릭**: `bounded_path_length`
- **질문**: leaf2에서 10.0.12.1로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `2`

```
! LEAF2에서 P6까지 홉 수 확인:
LEAF2# traceroute P6
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-9. BOUNDED_PATH_leaf2_pe1
- **메트릭**: `bounded_path_length`
- **질문**: leaf2에서 10.0.1.0로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `2`

```
! LEAF2에서 PE1까지 홉 수 확인:
LEAF2# traceroute PE1
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-10. BOUNDED_PATH_p2_leaf7
- **메트릭**: `bounded_path_length`
- **질문**: p2에서 172.17.3.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `1`

```
! P2에서 LEAF7까지 홉 수 확인:
P2# traceroute LEAF7
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-11. ISOLATION_VRF_EDU_VRF_GOV
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_EDU와 VRF_GOV 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! VRF 간 경로 누출 확인:
# show ip route vrf <vrf_name>
# show ip bgp vpnv4 vrf <vrf_name>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-12. ISOLATION_VRF_EDU_VRF_RND
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_EDU와 VRF_RND 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! VRF 간 경로 누출 확인:
# show ip route vrf <vrf_name>
# show ip bgp vpnv4 vrf <vrf_name>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-13. ISOLATION_VRF_EDU_default
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_EDU와 default 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
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

### L4-15. REACH_leaf5_leaf3_ICMP
- **메트릭**: `reachability_status`
- **질문**: 172.17.1.2에서 172.16.3.2(0/ICMP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: leaf5 -> pe3; REACHABLE: FALSE; REASON: NO_ROUTE"`

```
! LEAF3에서 172.16.3.2 도달성 확인:
LEAF3# ping 172.16.3.2
LEAF3# traceroute 172.16.3.2
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-16. REACH_leaf5_pe4_ICMP
- **메트릭**: `reachability_status`
- **질문**: 172.17.1.2에서 10.0.14.1(0/ICMP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: leaf5 -> pe3; REACHABLE: FALSE; REASON: NO_ROUTE"`

```
! ?에서 10.0.14.1 도달성 확인:
?# ping 10.0.14.1
?# traceroute 10.0.14.1
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-17. REACH_p8_leaf2_TCP
- **메트릭**: `reachability_status`
- **질문**: 10.0.16.1에서 172.16.2.2(22/TCP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: p8; REACHABLE: FALSE; REASON: EXTERNAL"`

```
! LEAF2에서 172.16.2.2 도달성 확인:
LEAF2# ping 172.16.2.2
LEAF2# traceroute 172.16.2.2
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-18. TRACEROUTE_leaf6_p3
- **메트릭**: `traceroute_path`
- **질문**: 172.17.2.2에서 10.0.3.1까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"leaf6 -> pe3"`

```
! LEAF6에서 P3으로 경로 추적:
LEAF6# traceroute P3
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-19. TRACEROUTE_leaf6_pe1
- **메트릭**: `traceroute_path`
- **질문**: 172.17.2.2에서 10.0.1.0까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"leaf6 -> pe3"`

```
! LEAF6에서 PE1으로 경로 추적:
LEAF6# traceroute PE1
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-20. TRACEROUTE_p3_p6
- **메트릭**: `traceroute_path`
- **질문**: 10.0.3.1에서 10.0.12.1까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"p3 -> p5 -> p6"`

```
! P3에서 P6으로 경로 추적:
P3# traceroute P6
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-21. WAYPOINT_leaf6_p7_leaf5
- **메트릭**: `waypoint_traversal_path`
- **질문**: 172.17.2.2에서 10.0.15.1로 가는 트래픽이 leaf5를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"NOT_TRAVERSED"`

```
! Waypoint 경유 확인:
172.17.2.2# traceroute 10.0.15.1
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-22. WAYPOINT_leaf6_p7_leaf6
- **메트릭**: `waypoint_traversal_path`
- **질문**: 172.17.2.2에서 10.0.15.1로 가는 트래픽이 leaf6를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"leaf6 -> pe3"`

```
! Waypoint 경유 확인:
172.17.2.2# traceroute 10.0.15.1
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-23. WAYPOINT_leaf6_p7_p2
- **메트릭**: `waypoint_traversal_path`
- **질문**: 172.17.2.2에서 10.0.15.1로 가는 트래픽이 p2를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"NOT_TRAVERSED"`

```
! Waypoint 경유 확인:
172.17.2.2# traceroute 10.0.15.1
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

---
## Phase 2: L5 검증 (21개)

> **주의**: L5는 failure injection 후 반드시 **원복(no shutdown)**해야 합니다!

### L5-1. CONFIG_CHANGE_BASELINE
- **메트릭**: `config_change_impact`
- **질문**: 설정 변경 후 leaf6에서 p7까지의 경로/도달성 변경 여부를 알려주세요. [답변 형식: 'NO_CHANGE' 또는 'CHANGED (N건: 흐름1, 흐름2, ...)']
- **데이터셋 정답**: `"CHANGED (47 entries: 10.10.10.31 -> 10.10.10.35, 172.16.1.3 -> 10.10.10.35, 10.10.10.1 -> 10.10.10.35)"`

```
! 메트릭: config_change_impact
! scope: {"type": "SNAPSHOT_DIFF", "src": "leaf6", "dst": "p7", "base_snapshot": "baseline", "changed_snapshot": "cfg_change_leaf5_1773019079", "change_desc": "node_down:leaf5", "failure_node": "leaf5"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-2. DIFF_REACH_BASELINE
- **메트릭**: `differential_reachability`
- **질문**: 변경 전후 leaf6에서 p7로의 도달성에 차이가 있습니까? [답변 형식: 'NO_DIFF' 또는 'DIFF (N건: 흐름1, 흐름2, ...)']
- **데이터셋 정답**: `"NO_DIFF"`

```
! 메트릭: differential_reachability
! scope: {"type": "SNAPSHOT_DIFF", "src": "leaf6", "dst": "p7", "base_snapshot": "baseline", "changed_snapshot": "cfg_change_leaf5_1773019079", "change_desc": "node_down:leaf5", "failure_node": "leaf5", "dst_ip": "10.0.15.1"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-3. DUAL_FAILURE_leaf1_leaf2
- **메트릭**: `redundancy_verification`
- **질문**: leaf1과 leaf2가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"29"`

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
- **데이터셋 정답**: `"29"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-5. DUAL_FAILURE_leaf5_leaf6
- **메트릭**: `redundancy_verification`
- **질문**: leaf5와 leaf6가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"29"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-6. K_FAILURE_leaf6_p7
- **메트릭**: `redundant_paths_list`
- **질문**: leaf6에서 10.0.15.1로 가는 대체 경로들을 모두 나열해주세요. [답변 형식: 경로 목록 (예: ["A→B→C", "A→D→C"])]
- **데이터셋 정답**: `["leaf6 → pe3"]`

```
! 이중화 경로 확인:
LEAF6# show ip route ?
LEAF6# traceroute ?
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-7. MULTI_FAIL_leaf1_leaf7_leaf2_leaf3
- **메트릭**: `multi_link_failure_reachability`
- **질문**: (시나리오) 'leaf1-leaf7' 링크와 'leaf2-leaf3' 링크가 동시에 다운되었습니다. 이 상황에서 'leaf6'에서 'p7'로의 트래픽 전달이 가능합니까? [답변 형식: 'REROUTED (path: A→B→C)' 또는 'DISCONNECTED (reason: ...)']
- **데이터셋 정답**: `"DISCONNECTED (reason: NO_ROUTE at pe3)"`

```
! 다중 링크 장애 시뮬레이션:
! === 원복 ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-8. MULTI_FAIL_leaf1_pe1_leaf2_leaf7
- **메트릭**: `multi_link_failure_reachability`
- **질문**: (시나리오) 'leaf1-pe1' 링크와 'leaf2-leaf7' 링크가 동시에 다운되었습니다. 이 상황에서 'leaf6'에서 'p7'로의 트래픽 전달이 가능합니까? [답변 형식: 'REROUTED (path: A→B→C)' 또는 'DISCONNECTED (reason: ...)']
- **데이터셋 정답**: `"DISCONNECTED (reason: NO_ROUTE at pe3)"`

```
! 다중 링크 장애 시뮬레이션:
! === 원복 ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-9. MULTI_FAIL_leaf1_pe3_leaf2_leaf4
- **메트릭**: `multi_link_failure_reachability`
- **질문**: (시나리오) 'leaf1-pe3' 링크와 'leaf2-leaf4' 링크가 동시에 다운되었습니다. 이 상황에서 'leaf6'에서 'p7'로의 트래픽 전달이 가능합니까? [답변 형식: 'REROUTED (path: A→B→C)' 또는 'DISCONNECTED (reason: ...)']
- **데이터셋 정답**: `"DISCONNECTED (reason: NO_ROUTE at pe3)"`

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

### L5-11. NODE_FAILURE_leaf6
- **메트릭**: `node_failure_impact`
- **질문**: leaf6 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `29`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-12. NODE_FAILURE_p3
- **메트릭**: `node_failure_impact`
- **질문**: p3 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `30`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-13. NODE_FAILURE_p5
- **메트릭**: `node_failure_impact`
- **질문**: p5 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `30`

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
- **데이터셋 정답**: `["p1", "p4", "p7", "pe1", "pe2"]`

```
! OSPF Area 0 라우터 확인:
# show ip ospf neighbor
# show ip ospf interface brief
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-15. POLICY_COMPLIANCE_leaf6
- **메트릭**: `policy_compliance_check`
- **질문**: 'MANDATORY_WAYPOINT_leaf6' 정책 준수 여부와 위반 사례를 알려주세요. [답변 형식: 'COMPLIANT' 또는 'VIOLATION: 흐름1, 흐름2, ...']
- **데이터셋 정답**: `"VIOLATION: 10.10.10.31 -> 10.10.10.0, 172.16.1.3 -> 10.10.10.0, 10.10.10.1 -> 10.10.10.0"`

```
! 메트릭: policy_compliance_check
! scope: {"type": "POLICY", "policy_name": "MANDATORY_WAYPOINT_leaf6"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-16. ROOT_CAUSE_leaf1_p4
- **메트릭**: `root_cause_analysis`
- **질문**: leaf1에서 p4로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe1"`

```
! 장애 원인 분석:
# show ip ospf neighbor
# show ip bgp summary
# show ip route
! 장애 적용 후 위 명령으로 영향 범위 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-17. ROOT_CAUSE_leaf6_p3
- **메트릭**: `root_cause_analysis`
- **질문**: leaf6에서 p3로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe3"`

```
! 장애 원인 분석:
# show ip ospf neighbor
# show ip bgp summary
# show ip route
! 장애 적용 후 위 명령으로 영향 범위 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-18. ROOT_CAUSE_leaf6_pe1
- **메트릭**: `root_cause_analysis`
- **질문**: leaf6에서 pe1로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe3"`

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
- **데이터셋 정답**: `["pe3", "leaf6"]`

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
- **데이터셋 정답**: `"NO (affected_flows: 29)"`

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
- **데이터셋 정답**: `"p3(30)"`

```
! 최악 시나리오 분석:
! 주요 백본 링크를 순차적으로 다운
! 각 단계에서 도달성 변화 관찰
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE
