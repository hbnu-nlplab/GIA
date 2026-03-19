"""
NetConfigQA 벤치마크용 데이터 모델 및 유틸리티

데이터 클래스:
- AnswerResult: 벤치마크 정답 결과 구조체
- FlowSpec: 트래픽 흐름 정의
- L4Result: L4 메트릭 결과
- L5Result: L5 메트릭 결과

유틸리티 함수:
- _build_evidence: 증거 메타데이터 생성
- _canonicalize: 정답 값 정규화
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from typing import NamedTuple

logger = logging.getLogger(__name__)


# ============================================================================
# 예외 클래스
# ============================================================================

class CanonicalizationError(Exception):
    """정규화(Canonicalization) 과정에서 발생하는 오류"""
    pass


# ============================================================================
# 데이터 클래스
# ============================================================================

class AnswerResult(NamedTuple):
    """
    벤치마크 정답 결과 구조체
    
    Attributes:
        status: 정답 상태 (OK, NOT_CONFIGURED, NOT_APPLICABLE, UNKNOWN)
        value: 정답 값 (Python object: list, dict, str, int, bool, None)
        answer_type: 정답 데이터 타입 (set_str, edge_set, map_str_int, path, enum, scalar_str, scalar_int, bool)
        evidence: 정답 생성 근거 (JSON 직렬화 가능한 dict)
        unknown_reason: UNKNOWN 상태의 원인 코드 (OK일 경우 빈 문자열)
    """
    status: str           # "OK" | "NOT_CONFIGURED" | "NOT_APPLICABLE" | "UNKNOWN"
    value: Any            # Python object
    answer_type: str      # "set_str" | "edge_set" | "map_str_int" | "path" | ...
    evidence: Dict        # {"query": "...", "params": {...}, "snapshot": "..."}
    unknown_reason: str   # "" | "SCHEMA_VIOLATION" | "BATFISH_QUERY_ERROR" | ...


@dataclass
class FlowSpec:
    """트래픽 흐름 정의"""
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    protocol: str = "TCP"
    src_location: str = ""
    dst_location: str = ""


@dataclass 
class L4Result:
    """L4 메트릭 결과"""
    reachable: bool
    path: List[str]
    blocking_point: Optional[str] = None
    blocking_reason: Optional[str] = None


@dataclass
class L5Result:
    """L5 메트릭 결과"""
    has_impact: bool
    affected_flows: List[str]
    description: str = ""


# ============================================================================
# 상수 정의
# ============================================================================

# Batfish Disposition 우선순위 (낮을수록 더 중요한 실패 원인)
DISPOSITION_PRIORITY = {
    'NO_ROUTE': 1,              # 최우선: 명확한 라우팅 실패
    'NULL_ROUTED': 2,           # 의도적으로 버림 (Null0)
    'ACL_DENY': 3,              # 정규화된 ACL 차단 상태
    'ACL_IN_DENIED': 3,         # ACL 차단 (Ingress)
    'ACL_OUT_DENIED': 3,        # ACL 차단 (Egress)
    'DENIED': 3,                # 일반 ACL 차단
    'DENIED_IN': 3,             # ACL 차단 변형
    'DENIED_OUT': 3,            # ACL 차단 변형
    'NEIGHBOR_UNREACHABLE': 4,  # 이웃 도달 불가
    'LOOP': 5,                  # 라우팅 루프
    'EXTERNAL': 6,              # 네트워크 외부/정보부족 계열 정규화
    'EXITS_NETWORK': 6,         # 낮은 우선순위: 네트워크를 벗어남 (성공일 수도 있음)
    'INSUFFICIENT_INFO': 6,     # 낮은 우선순위: 정보 불충분 (성공일 수도 있음)
    'UNKNOWN': 7                # 알 수 없는 상태
}


def normalize_disposition(raw: str) -> str:
    """
    Batfish disposition 문자열을 데이터셋 계약용 라벨로 정규화합니다.
    - 성공: ACCEPTED
    - 실패: NO_ROUTE / ACL_DENY / EXTERNAL 등
    """
    d = str(raw or "").upper()
    if "ACCEPTED" in d or "DELIVERED" in d:
        return "ACCEPTED"
    if "NO_ROUTE" in d:
        return "NO_ROUTE"
    if "NULL_ROUTED" in d:
        return "NULL_ROUTED"
    if "DENIED" in d or "BLOCK" in d:
        return "ACL_DENY"
    if "NEIGHBOR_UNREACHABLE" in d:
        return "NEIGHBOR_UNREACHABLE"
    if "LOOP" in d:
        return "LOOP"
    if "EXITS_NETWORK" in d or "INSUFFICIENT_INFO" in d:
        return "EXTERNAL"
    return "UNKNOWN"


# 각 프로토콜의 "Configured" 판정 기준
CONFIGURED_RULES = {
    "OSPF": "router ospf 프로세스 존재 여부 (via ospfProcessConfiguration)",
    "BGP": "router bgp 프로세스 존재 여부 (via bgpProcessConfiguration)",
    "VRF": "vrf definition 정의 존재 여부 (via vrfProperties)",
    "MPLS": "인터페이스에 mpls ip 명령 존재 여부 (via mplsInterfaces)",
    "ACL": "ip access-list 정의 존재 여부 (via ipAccessLists)",
    "NTP": "ntp server 또는 ntp peer 명령 존재 여부 (via ntpServers)",
    "SYSLOG": "logging host 명령 존재 여부 (via syslogServers)",
}

# UNKNOWN 상태의 원인 코드
UNKNOWN_REASONS = {
    "SCHEMA_VIOLATION": "정답 값이 JSON Schema를 위반함",
    "BATFISH_QUERY_ERROR": "Batfish 쿼리 실행 중 예외 발생",
    "BATFISH_EMPTY_RESULT": "Batfish 쿼리가 예상치 못한 빈 결과 반환",
    "CANONICALIZE_ERROR": "정규화(canonicalize) 과정에서 오류 발생",
    "TYPE_MISMATCH": "반환 값의 타입이 answer_type과 불일치",
    "PARSE_ERROR": "Configuration 파싱 실패",
}


# ============================================================================
# 유틸리티 함수
# ============================================================================

def build_evidence(query_name: str, params: Dict, snapshot_name: str = "") -> Dict:
    """
    재현 가능한 증거 메타데이터 생성
    
    Args:
        query_name: Batfish 쿼리 이름 (예: "ospfSessionCompatibility")
        params: 쿼리 파라미터 (예: {"nodes": "leaf1"})
        snapshot_name: 스냅샷 이름
    
    Returns:
        JSON 직렬화 가능한 evidence 딕셔너리
    """
    return {
        "query": query_name,
        "params": params,
        "snapshot": snapshot_name
    }


def canonicalize(value: Any, answer_type: str) -> Any:
    """
    정답 값을 정규화하여 비교 안정성 확보
    
    Args:
        value: 정규화할 값
        answer_type: 정답 타입
    
    Returns:
        정규화된 값
    
    Raises:
        CanonicalizationError: 정규화 실패 시
    """
    if value is None:
        return None
    
    try:
        if answer_type == "set_str":
            # 중복 제거 + 알파벳순 정렬
            return sorted(list(set(value)))
        
        elif answer_type == "edge_set":
            # 각 edge를 정렬(무방향 통일) + edge 목록 정렬
            normalized = [tuple(sorted(edge)) for edge in value]
            return sorted([list(e) for e in set(normalized)])
        
        elif answer_type in ("map_str_int", "map_str_str"):
            # 키 정렬된 딕셔너리
            return dict(sorted(value.items()))
        
        elif answer_type == "path":
            # 경로는 순서가 중요하므로 정렬하지 않음
            return list(value) if not isinstance(value, list) else value
        
        elif answer_type in ("scalar_str", "scalar_int", "bool", "enum"):
            # 스칼라 값은 그대로 반환
            return value
        
        else:
            # 알 수 없는 타입은 그대로 반환
            return value
    
    except Exception as e:
        raise CanonicalizationError(f"정규화 실패 (type={answer_type}): {e}")


# Backward compatibility aliases
_build_evidence = build_evidence
_canonicalize = canonicalize
