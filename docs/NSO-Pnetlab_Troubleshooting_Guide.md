# NSO-Pnetlab Troubleshooting Guide (Sync Failure)

이 문서는 Pnetlab VM 재부팅 후 NSO와 장비 간의 `sync-from` 이 실패하는 문제를 진단하고 해결하기 위한 가이드입니다.

## 1. 문제 증상
- NSO에서 `sync-from` 시 `connection refused` 또는 `No route to host` 에러 발생.
- 사용자는 NSO PC에서 장비 콘솔(Telnet)로 접속은 가능함.

## 2. 체크리스트 및 해결 방법

### 1단계: 네트워크 연결성 확인 (Host PC 기준)
NSO PC(호스트)에서 장비의 OOB IP로 핑이 가는지 확인합니다.
```bash
ping 10.10.10.11  # vIOS10
ping 10.10.10.12  # vIOS11
```
> [!IMPORTANT]
> **핑이 실패할 경우**: Tailscale 서브넷 라우팅이나 Pnetlab VM 내부의 브릿지 설정이 유실된 것입니다.

### 2단계: Pnetlab VM 내부 설정 복구
VM 재부팅 시 가상 스위치(브릿지)의 IP와 상태가 초기화될 수 있습니다. 다음 명령어를 Pnetlab VM에서 다시 수행하세요.

1. **브릿지 활성화 및 IP 할당**:
   ```bash
   sudo ip link set pnet2 up
   sudo ip addr add 10.10.10.1/24 dev pnet2
   ```
2. **IP 포워딩 활성화**:
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=1
   ```
3. **Tailscale 라우트 광고**:
   ```bash
   sudo tailscale up --advertise-routes=10.10.10.0/24
   ```

### 3단계: Pnetlab 토폴로지 연결 확인
장비의 망 관리 인터페이스(예: Gi0/0)가 올바른 Cloud 노드에 연결되어 있는지 확인하십시오.
- **vIOS10**: CloudA (`pnet2` 브릿지 매핑 확인)
- **vIOS11**: CloudB (`pnet3`? 브릿지 매핑 확인)

> [!TIP]
> 모든 장비가 동일한 `10.10.10.1` 게이트웨이를 사용한다면, 동일한 `pnet2` 망에 연결되어야 합니다.

### 4단계: 장비 내 인터페이스, 라우팅, SSH 상태 확인
장비가 관리 대역(`10.10.10.x`)에 있더라도 인터페이스가 꺼져 있거나, 게이트웨이가 없거나, SSH가 비활성 상태면 NSO가 접속할 수 없습니다.

각 장비 콘솔(Telnet)에서 다음을 확인하십시오:
```ios
show ip interface brief
show ip route
show ip ssh
```

> [!CAUTION]
> **Check 1: Interface Status**
> `GigabitEthernet0/0`이 `administratively down` 이라면 활성화가 필요합니다.
>
> **Check 2: Default Gateway**
> `Gateway of last resort is not set` 이라면 외부 통신이 불가능합니다.
>
> **Check 3: SSH Status**
> `SSH Disabled` 또는 `Please create RSA keys` 메시지가 보인다면 SSH를 켜야 합니다.

**해결 방법 (장비 콘솔에서)**:
```ios
conf t
! 1. 인터페이스 활성화
interface Gi0/0
 no shutdown
 exit

! 2. 기본 게이트웨이 추가
ip route 0.0.0.0 0.0.0.0 10.10.10.1

! 3. SSH 활성화 (도메인 네임과 RSA 키 필수)
ip domain name local
crypto key generate rsa modulus 2048
ip ssh version 2

! 4. 로컬 계정 생성 (NSO 접속용)
username admin privilege 15 secret admin

end
write memory
```

### 6단계: NSO WebUI 가시성 문제 (장비가 리스트에 안 보일 때)
NSO DB에는 등록되어 있으나 WebUI 리스트에 장비가 보이지 않는 경우, NSO 엔진의 일시적인 상태 오류일 수 있습니다.

**해결 방법 (NSO PC에서)**:
NSO 컨테이너를 재시작하여 상태를 동기화합니다.
```bash
docker restart cisco-nso-dev
```
이후 1~2분 정도 대기 후 WebUI에 접속하여 확인하십시오.

---

## 3. 요약: 왜 vIOS11은 되고 vIOS10은 안 되었나?
- **진단 결과**: 본체 PC에서 `10.10.10.12`는 핑이 가지만, `10.10.10.11`은 핑이 가지 않았습니다.
- **원인**: `vIOS10`이 연결된 `CloudA`가 Pnetlab VM의 관리 브릿지(`pnet2`, 10.10.10.1)와 정상적으로 연결되지 않았거나, `vIOS10` 내부 설정에서 게이트웨이(`ip route 0.0.0.0 0.0.0.0 10.10.10.1`)가 누락되었을 가능성이 큽니다.
