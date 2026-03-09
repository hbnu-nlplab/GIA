# Method 3 — PNETLab 실환경 검증 가이드

> **목적**: Batfish 시뮬레이션 결과를 실제 Cisco IOS 라우터에서 검증
> **대상**: L4-L5 계층화 표본 47개 QA
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

### 토폴로지: LabC_NCN_Security_L2VPN_30nodes (30 nodes)

장비 목록: asbr1, asbr2, leaf1, leaf10, leaf11, leaf12, leaf2, leaf3, leaf4, leaf5, leaf6, leaf7, leaf8, leaf9, p1, p10, p2, p3, p4, p5, p6, p7, p8, p9, pe1, pe2, pe3, pe4, pe5, pe6

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
## Phase 1: L4 검증 (26개)

### L4-1. ACL_BLOCKING_leaf7_leaf3
- **메트릭**: `acl_blocking_point`
- **질문**: 172.17.3.2에서 172.16.3.2로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
LEAF3# traceroute 172.16.3.2
LEAF3# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-2. ACL_BLOCKING_p10_asbr2
- **메트릭**: `acl_blocking_point`
- **질문**: 10.0.32.1에서 10.0.30.3로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
?# traceroute 10.0.30.3
?# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-3. ACL_BLOCKING_pe6_leaf11
- **메트릭**: `acl_blocking_point`
- **질문**: 10.0.32.3에서 172.18.3.2로 트래픽이 차단된다면 차단 지점을 알려주세요. [답변 형식: 차단 장비명 또는 'ALLOWED']
- **데이터셋 정답**: `"ALLOWED"`

```
! ACL 차단 지점 확인:
?# traceroute 172.18.3.2
?# show ip access-lists
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-4. ASYMMETRIC_leaf11_asbr2
- **메트릭**: `asymmetric_path_comparison`
- **질문**: leaf11과 asbr2 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: leaf11 -> pe6, Reverse: asbr2"`

```
! 양방향 경로 확인:
?# traceroute <? loopback IP>
?# traceroute <? loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-5. ASYMMETRIC_leaf12_leaf9
- **메트릭**: `asymmetric_path_comparison`
- **질문**: leaf12와 leaf9 사이의 Forward/Reverse 경로를 비교해주세요. [답변 형식: 'Forward: A→B→C, Reverse: C→D→A' 형식]
- **데이터셋 정답**: `"Forward: leaf12 -> pe6, Reverse: leaf9 -> pe5"`

```
! 양방향 경로 확인:
?# traceroute <? loopback IP>
?# traceroute <? loopback IP>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-6. ASYMMETRIC_leaf1_p1
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

### L4-8. BOUNDED_PATH_leaf10_leaf8
- **메트릭**: `bounded_path_length`
- **질문**: leaf10에서 172.17.4.2로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `2`

```
! LEAF10에서 LEAF8까지 홉 수 확인:
LEAF10# traceroute LEAF8
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-9. BOUNDED_PATH_p10_pe2
- **메트릭**: `bounded_path_length`
- **질문**: p10에서 10.0.4.1로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `10`

```
! P10에서 PE2까지 홉 수 확인:
P10# traceroute PE2
! 홉 수를 세어 max_hops와 비교
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-10. BOUNDED_PATH_pe6_pe2
- **메트릭**: `bounded_path_length`
- **질문**: pe6에서 10.0.4.1로 가는 경로의 홉 수는 몇 개입니까? [답변 형식: 숫자]
- **데이터셋 정답**: `10`

```
! PE6에서 PE2까지 홉 수 확인:
PE6# traceroute PE2
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

### L4-12. ISOLATION_VRF_EDU_VRF_MIL
- **메트릭**: `leaked_prefixes_list`
- **질문**: VRF_EDU와 VRF_MIL 사이에 누수된 prefix 목록은 무엇입니까? [답변 형식: prefix 목록 (예: ["10.10.10.0/24"]) 또는 빈 목록 []]
- **데이터셋 정답**: `[]`

```
! VRF 간 경로 누출 확인:
# show ip route vrf <vrf_name>
# show ip bgp vpnv4 vrf <vrf_name>
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-13. ISOLATION_VRF_EDU_VRF_RND
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

### L4-15. REACH_leaf10_leaf8_TCP
- **메트릭**: `reachability_status`
- **질문**: 172.18.2.2에서 172.17.4.2(22/TCP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: leaf10 -> pe5; REACHABLE: FALSE; REASON: NO_ROUTE"`

```
! ?에서 172.17.4.2 도달성 확인:
?# ping 172.17.4.2
?# traceroute 172.17.4.2
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-16. REACH_p10_pe2_ICMP
- **메트릭**: `reachability_status`
- **질문**: 10.0.32.1에서 10.0.4.1(0/ICMP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: p10 -> asbr2 -> p8 -> p7 -> p6 -> p5 -> p3 -> p1 -> p2 -> pe2; REACHABLE: TRUE"`

```
! PE2에서 10.0.4.1 도달성 확인:
PE2# ping 10.0.4.1
PE2# traceroute 10.0.4.1
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-17. REACH_p10_pe4_TCP
- **메트릭**: `reachability_status`
- **질문**: 10.0.32.1에서 10.0.14.1(22/TCP)로의 트래픽 경로와 도달 여부를 알려주세요. [답변 형식: '경로: A → B → C, 도달: 가능' 또는 '경로: ..., 도달: 불가 (원인: NO_ROUTE, ACL_DENY, EXTERNAL 중 택1)']
- **데이터셋 정답**: `"PATH: p10 -> asbr2 -> p8 -> pe4; REACHABLE: TRUE"`

```
! ?에서 10.0.14.1 도달성 확인:
?# ping 10.0.14.1
?# traceroute 10.0.14.1
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-18. SEC_BYPASS_p7_p8_p10
- **메트릭**: `security_policy_bypass_check`
- **질문**: 보안 정책상 'p7'에서 'p8'로 가는 모든 트래픽은 반드시 'p10' 장비를 경유해야 합니다. 현재 구성에서 이 정책을 우회하는 경로가 존재합니까? [답변 형식: 'BYPASS (path: A→B→C)' 또는 'COMPLIANT']
- **데이터셋 정답**: `"VIOLATION (path: p7 -> p8)"`

```
! 메트릭: security_policy_bypass_check
! scope: {"type": "SECURITY_POLICY", "src": "p7", "dst": "p8", "waypoint": "p10"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-19. SEC_BYPASS_p7_p8_pe1
- **메트릭**: `security_policy_bypass_check`
- **질문**: 보안 정책상 'p7'에서 'p8'로 가는 모든 트래픽은 반드시 'pe1' 장비를 경유해야 합니다. 현재 구성에서 이 정책을 우회하는 경로가 존재합니까? [답변 형식: 'BYPASS (path: A→B→C)' 또는 'COMPLIANT']
- **데이터셋 정답**: `"VIOLATION (path: p7 -> p8)"`

```
! 메트릭: security_policy_bypass_check
! scope: {"type": "SECURITY_POLICY", "src": "p7", "dst": "p8", "waypoint": "pe1"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-20. SEC_BYPASS_p8_p7_p10
- **메트릭**: `security_policy_bypass_check`
- **질문**: 보안 정책상 'p8'에서 'p7'로 가는 모든 트래픽은 반드시 'p10' 장비를 경유해야 합니다. 현재 구성에서 이 정책을 우회하는 경로가 존재합니까? [답변 형식: 'BYPASS (path: A→B→C)' 또는 'COMPLIANT']
- **데이터셋 정답**: `"VIOLATION (path: p8 -> p7)"`

```
! 메트릭: security_policy_bypass_check
! scope: {"type": "SECURITY_POLICY", "src": "p8", "dst": "p7", "waypoint": "p10"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-21. TRACEROUTE_leaf10_leaf5
- **메트릭**: `traceroute_path`
- **질문**: 172.18.2.2에서 172.17.1.2까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"leaf10 -> pe5"`

```
! LEAF10에서 LEAF5으로 경로 추적:
LEAF10# traceroute LEAF5
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-22. TRACEROUTE_leaf10_leaf6
- **메트릭**: `traceroute_path`
- **질문**: 172.18.2.2에서 172.17.2.2까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"leaf10 -> pe5"`

```
! LEAF10에서 LEAF6으로 경로 추적:
LEAF10# traceroute LEAF6
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-23. TRACEROUTE_p10_p4
- **메트릭**: `traceroute_path`
- **질문**: 10.0.32.1에서 10.0.5.1까지의 네트워크 경로(장비 순서)를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록(IP 주소 아님)]
- **데이터셋 정답**: `"p10 -> asbr2 -> p8 -> p7 -> p6 -> p5 -> p3 -> p4"`

```
! P10에서 P4으로 경로 추적:
P10# traceroute P4
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-24. WAYPOINT_p10_pe5_p10
- **메트릭**: `waypoint_traversal_path`
- **질문**: 10.0.32.1에서 10.0.31.3로 가는 트래픽이 p10를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"p10 -> pe5"`

```
! Waypoint 경유 확인:
10.0.32.1# traceroute 10.0.31.3
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-25. WAYPOINT_p10_pe5_pe1
- **메트릭**: `waypoint_traversal_path`
- **질문**: 10.0.32.1에서 10.0.31.3로 가는 트래픽이 pe1를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"NOT_TRAVERSED"`

```
! Waypoint 경유 확인:
10.0.32.1# traceroute 10.0.31.3
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L4-26. WAYPOINT_p10_pe5_pe6
- **메트릭**: `waypoint_traversal_path`
- **질문**: 10.0.32.1에서 10.0.31.3로 가는 트래픽이 pe6를 경유할 때의 전체 경로는 무엇입니까? [답변 형식: 'A → B → C' 형식 또는 '경유하지 않음']
- **데이터셋 정답**: `"NOT_TRAVERSED"`

```
! Waypoint 경유 확인:
10.0.32.1# traceroute 10.0.31.3
! 경로에 waypoint가 포함되는지 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

---
## Phase 2: L5 검증 (21개)

> **주의**: L5는 failure injection 후 반드시 **원복(no shutdown)**해야 합니다!

### L5-1. CONFIG_CHANGE_BASELINE
- **메트릭**: `config_change_impact`
- **질문**: 설정 변경 후 p7에서 p8까지의 경로/도달성 변경 여부를 알려주세요. [답변 형식: 'NO_CHANGE' 또는 'CHANGED (N건: 흐름1, 흐름2, ...)']
- **데이터셋 정답**: `"CHANGED (70 entries: 10.0.30.1 -> 10.0.32.1, 10.10.10.1 -> 10.0.32.1, 10.0.30.3 -> 10.0.32.1)"`

```
! 메트릭: config_change_impact
! scope: {"type": "SNAPSHOT_DIFF", "src": "p7", "dst": "p8", "base_snapshot": "baseline", "changed_snapshot": "cfg_change_p10_1773019515", "change_desc": "node_down:p10", "failure_node": "p10"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-2. DIFF_REACH_BASELINE
- **메트릭**: `differential_reachability`
- **질문**: 변경 전후 p7에서 p8로의 도달성에 차이가 있습니까? [답변 형식: 'NO_DIFF' 또는 'DIFF (N건: 흐름1, 흐름2, ...)']
- **데이터셋 정답**: `"NO_DIFF"`

```
! 메트릭: differential_reachability
! scope: {"type": "SNAPSHOT_DIFF", "src": "p7", "dst": "p8", "base_snapshot": "baseline", "changed_snapshot": "cfg_change_p10_1773019515", "change_desc": "node_down:p10", "failure_node": "p10", "dst_ip": "10.0.16.1"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-3. DUAL_FAILURE_p1_p2
- **메트릭**: `redundancy_verification`
- **질문**: p1과 p2가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"43"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-4. DUAL_FAILURE_p3_p4
- **메트릭**: `redundancy_verification`
- **질문**: p3과 p4가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"43"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-5. DUAL_FAILURE_p5_p6
- **메트릭**: `redundancy_verification`
- **질문**: p5와 p6가 동시에 다운되면 고립되는 흐름이 있습니까? 몇 개입니까? [답변 형식: 'NONE' 또는 숫자]
- **데이터셋 정답**: `"43"`

```
! 이중화 검증:
! 1) 장애 적용 전 ping 확인
! 2) 장애 적용 (shutdown)
! 3) 수렴 대기 후 ping 재확인
! 4) 원복 (no shutdown)
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-6. K_FAILURE_p7_p8
- **메트릭**: `redundant_paths_list`
- **질문**: p7에서 10.0.16.1로 가는 대체 경로들을 모두 나열해주세요. [답변 형식: 경로 목록 (예: ["A→B→C", "A→D→C"])]
- **데이터셋 정답**: `["p7 → p8"]`

```
! 이중화 경로 확인:
P7# show ip route ?
P7# traceroute ?
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-7. LINK_FAILURE_asbr1_p7
- **메트릭**: `link_failure_impact`
- **질문**: 'asbr1-p7' 링크가 다운될 경우, 'p7→p8' 트래픽에 어떤 영향이 발생합니까? [답변 형식: 'NONE', 'REROUTED', 'DISCONNECTED']
- **데이터셋 정답**: `"NONE"`

```
! 메트릭: link_failure_impact
! scope: {"type": "LINK_FAILURE", "link": "asbr1-p7", "node1": "asbr1", "node2": "p7", "src": "p7", "dst": "p8"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-8. LINK_FAILURE_asbr1_p9
- **메트릭**: `link_failure_impact`
- **질문**: 'asbr1-p9' 링크가 다운될 경우, 'p7→p8' 트래픽에 어떤 영향이 발생합니까? [답변 형식: 'NONE', 'REROUTED', 'DISCONNECTED']
- **데이터셋 정답**: `"NONE"`

```
! 메트릭: link_failure_impact
! scope: {"type": "LINK_FAILURE", "link": "asbr1-p9", "node1": "asbr1", "node2": "p9", "src": "p7", "dst": "p8"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-9. LINK_FAILURE_asbr1_pe5
- **메트릭**: `link_failure_impact`
- **질문**: 'asbr1-pe5' 링크가 다운될 경우, 'p7→p8' 트래픽에 어떤 영향이 발생합니까? [답변 형식: 'NONE', 'REROUTED', 'DISCONNECTED']
- **데이터셋 정답**: `"NONE"`

```
! 메트릭: link_failure_impact
! scope: {"type": "LINK_FAILURE", "link": "asbr1-pe5", "node1": "asbr1", "node2": "pe5", "src": "p7", "dst": "p8"}
! 적절한 show/ping/traceroute 명령으로 검증
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

### L5-11. NODE_FAILURE_p10
- **메트릭**: `node_failure_impact`
- **질문**: p10 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `43`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-12. NODE_FAILURE_pe1
- **메트릭**: `node_failure_impact`
- **질문**: pe1 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `43`

```
! 노드 장애 시뮬레이션 (?):
! ?의 모든 인터페이스 shutdown
! 다른 장비에서 도달성 확인:
# ping <target_ip>
! === 원복: 모든 인터페이스 no shutdown ===
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-13. NODE_FAILURE_pe6
- **메트릭**: `node_failure_impact`
- **질문**: pe6 장비가 다운되면 몇 개의 트래픽 흐름이 새로 차단됩니까? [답변 형식: 숫자]
- **데이터셋 정답**: `45`

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
- **데이터셋 정답**: `["asbr1", "asbr2", "p6", "p7", "p8"]`

```
! OSPF Area 0 라우터 확인:
# show ip ospf neighbor
# show ip ospf interface brief
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-15. POLICY_COMPLIANCE_p10
- **메트릭**: `policy_compliance_check`
- **질문**: 'MANDATORY_WAYPOINT_p10' 정책 준수 여부와 위반 사례를 알려주세요. [답변 형식: 'COMPLIANT' 또는 'VIOLATION: 흐름1, 흐름2, ...']
- **데이터셋 정답**: `"VIOLATION: 10.0.30.1 -> 8.8.8.8, 10.10.10.1 -> 8.8.8.8, 10.0.30.3 -> 8.8.8.8"`

```
! 메트릭: policy_compliance_check
! scope: {"type": "POLICY", "policy_name": "MANDATORY_WAYPOINT_p10"}
! 적절한 show/ping/traceroute 명령으로 검증
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-16. ROOT_CAUSE_leaf10_leaf6
- **메트릭**: `root_cause_analysis`
- **질문**: leaf10에서 leaf6로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"pe5"`

```
! 장애 원인 분석:
# show ip ospf neighbor
# show ip bgp summary
# show ip route
! 장애 적용 후 위 명령으로 영향 범위 확인
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-17. ROOT_CAUSE_leaf5_p5
- **메트릭**: `root_cause_analysis`
- **질문**: leaf5에서 p5로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
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

### L5-18. ROOT_CAUSE_p10_leaf6
- **메트릭**: `root_cause_analysis`
- **질문**: p10에서 leaf6로의 통신이 실패할 때, 어느 장비에서 차단됩니까? [답변 형식: 장비명]
- **데이터셋 정답**: `"p10"`

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
- **데이터셋 정답**: `["p7"]`

```
! Single Point of Failure 탐지:
! 각 링크/노드를 하나씩 다운시키며 전체 도달성 확인
! 1개 장애로 전체 통신 불가 → SPOF
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE

### L5-20. TRIPLE_FAILURE_p1_p2_p3
- **메트릭**: `triple_node_failure`
- **질문**: p1, p2, p3가 동시에 다운되면 네트워크가 완전히 분리됩니까? [답변 형식: 'YES' 또는 'NO (affected_flows: N)']
- **데이터셋 정답**: `"NO (affected_flows: 42)"`

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
- **데이터셋 정답**: `"pe6(45)"`

```
! 최악 시나리오 분석:
! 주요 백본 링크를 순차적으로 다운
! 각 단계에서 도달성 변화 관찰
```
- **내 결과**: ________________
- **판정**: [ ] AGREE  [ ] DISAGREE
