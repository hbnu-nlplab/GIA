🚀 NIKA Best Practices for NetConfigQA3
Goal: NIKA(SIGCOMM '25)의 핵심 장점인 **"Traffic-based Analysis"**와 **"Process-oriented Grading"**을 NetConfigQA3(Cisco/PNETLab 환경)에 맞게 최적화하여 적용하는 가이드입니다.

1. 🛠️ NIKA Tool Adaptation (도구 벤치마킹)
NIKA는 Linux 에이전트를 통해 
ping
, 
iperf
, 
curl
 등의 결과를 Text Report 형태로 에이전트에게 제공합니다. 우리도 Cisco IOS 및 PNETLab End-host 환경에서 이를 모사해야 합니다.

A. Connectivity & Performance (연결성 및 성능)
NIKA Tool (Linux)	기능 설명	NetConfigQA3 적용 방안 (Cisco/PNETLab)	Output Format Example (Text Report)
get_reachability
Mesh Ping (전수 조사)	Batfish Reachability Check (Software)
OR Python Script Loop (Real PNETLab)	[Report] Reachability Analysis
- Total Pairs: 50
- Failed: 2 (R1->R3, R2->R3)
- Success Rate: 96%
ping_pair
Latency Check	Cisco IOS Extended Ping (Repeat/Size 옵션 활용)	[Report] Ping Statistics
- Source: R1, Dest: 10.1.1.2
- Success Rate: 100% (100/100)
- Latency: min=1ms, avg=2ms, max=5ms
- Jitter: Low
iperf_test
Bandwidth/Jitter	PNETLab Linux/Docker Node 활용
(라우터는 
iperf
 불가하므로 종단 호스트 제어 필요)	[Report] Bandwidth Test (Iperf3)
- Status: Degraded
- Throughput: 5.2 Mbps (Expected: 10 Mbps)
- Retransmits: 120 (High Congestion)
curl_web_test
Service Probe	PNETLab Linux Node - HTTP Get	[Report] Service Availability
- Target: http://web-server:80
- HTTP Code: 502 Bad Gateway
- Response Time: 0.05s
B. Telemetry & Inspection (상태 확인)
NIKA Tool (Linux)	기능 설명	NetConfigQA3 적용 방안 (Cisco/PNETLab)	Output Format Example (Text Report)
netstat -tuln	Port Open Check	Cisco IOS show control-plane host open-ports	[Report] Open Ports
- TCP 179 (BGP): Listening
- TCP 22 (SSH): Listening
- UDP 161 (SNMP): Listening
get_host_net_config
Interface/IP Check	Cisco IOS show ip int brief + show run int	[Report] Interface Status
- Gi0/0: 10.1.1.1/24 (UP/UP)
- Gi0/1: Unassigned (ADMIN DOWN)
💡 Key Insight: 에이전트에게 Raw Output (!!!!! 등)을 그대로 던지는 대신, 파이썬 래퍼(Wrapper)가 이를 파싱하여 **"의미 있는 요약본(Structured Text)"**을 제공해야 추론 능력이 향상됩니다.