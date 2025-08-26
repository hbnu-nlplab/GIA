# 🚀 XML 설정 빠른 참조 치트시트

## 📋 자주 찾는 정보들

### 🏷️ 1. 장비 기본 정보
| 찾고 싶은 것 | XML 경로 | 예시 |
|-------------|---------|------|
| 장비 이름 | `<device><name>` | CE1, sample7 |
| 관리 IP | `<device><address>` | 172.16.1.40 |
| 호스트네임 | `<hostname xmlns="urn:ios">` | CE1 |
| IOS 버전 | `<version xmlns="urn:ios">` | 15.4 |

### 🔌 2. 인터페이스 정보
| 인터페이스 유형 | XML 패턴 | IP 주소 위치 |
|----------------|----------|-------------|
| 이더넷 (CE) | `<Ethernet><name>0/1</name>` | `<address><primary><address>` |
| 기가비트 (샘플) | `<GigabitEthernet><id>0/0/0/2</id>` | `<ipv4><address><ip>` |
| 루프백 | `<Loopback><id>0</id>` | `<ipv4><address><ip>` |
| 관리 인터페이스 | `<MgmtEth><id>0/RP0/CPU0/0</id>` | `<ipv4><address><ip>` |

### 🌍 3. BGP 정보
| 찾고 싶은 것 | XML 경로 | 비고 |
|-------------|---------|------|
| 자신의 AS 번호 | `<bgp><as-no>` 또는 `<bgp-no-instance><id>` | 65001, 65000 등 |
| 네이버 IP | `<neighbor><id>` | 연결 상대방 |
| 네이버 AS | `<neighbor><remote-as>` | 상대방 AS 번호 |

---

## 🎯 XML 구조별 찾기 가이드

### 📄 CE 파일 (ce1.xml, ce2.xml) 구조
```
<config>
  <devices>
    <device>
      <name>          ← 장비명
      <address>       ← 관리 IP
      <config>
        <hostname>    ← 호스트네임 ⭐
        <version>     ← IOS 버전 ⭐
        <interface>   ← 인터페이스 설정들 ⭐
          <Ethernet>
        <router>      ← 라우팅 설정 ⭐
          <bgp>
```

### 📄 Sample 파일 (sample7~10.xml) 구조
```
<config>
  <devices>
    <device>
      <name>          ← 장비명
      <address>       ← 관리 IP
      <config>
        <interface>   ← 인터페이스 설정들 ⭐
          <Loopback>
          <GigabitEthernet>
        <router>      ← 라우팅 설정 ⭐
          <bgp>
            <bgp-no-instance>
```

---

## ⚡ 빠른 검색 키워드

### 🔍 Ctrl+F로 찾기
| 찾고 싶은 것 | 검색 키워드 |
|-------------|------------|
| 장비 이름 | `<name>` |
| IP 주소 | `<address>` 또는 `<ip>` |
| BGP AS | `<as-no>` 또는 `bgp-no-instance><id>` |
| 인터페이스 | `<Ethernet>` 또는 `<GigabitEthernet>` |
| 루프백 | `<Loopback>` |
| BGP 네이버 | `<neighbor>` |

---

## 📊 우리 파일들의 핵심 정보 요약

### 🏢 AS 번호 맵핑
- **AS 65000**: 서비스 제공업체 (sample 시리즈)
- **AS 65001**: 고객사 1 (CE1)
- **AS 65003**: 고객사 2 (CE2)

### 📍 관리 IP 주소들
- **CE1**: 172.16.1.40
- **CE2**: 172.16.1.41  
- **sample7**: 172.16.1.130
- **sample8**: 172.16.1.131
- **sample9**: 172.16.1.132
- **sample10**: 172.16.1.133

### 🔄 루프백 주소들 (sample 시리즈)
- **sample7**: 1.1.1.1
- **sample8**: 2.2.2.2 (추정)
- **sample9**: 3.3.3.3 (추정)
- **sample10**: 4.4.4.4 (추정)

---

## 💡 프로 팁

### ✅ 빠른 정보 확인 순서
1. **파일명**으로 어떤 장비인지 파악
2. **상단 5줄** 내에서 이름과 관리 IP 확인
3. **`<interface>` 섹션**에서 포트 설정 확인
4. **`<bgp>` 섹션**에서 AS 번호와 네이버 확인

### 🎨 XML 읽기 꿀팁
- **들여쓰기**를 따라가면 구조를 쉽게 파악할 수 있음
- **같은 레벨의 태그**들은 보통 비슷한 성격의 설정
- **xmlns** 속성은 태그의 네임스페이스 (무시해도 됨)

---

*⚡ 이 치트시트를 옆에 두고 XML 파일을 분석해보세요!* 