"""
Inventory Builder
PNETLab 토폴로지를 NSO 등록용 device_info.json 형식으로 변환합니다.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
import json

logger = logging.getLogger(__name__)


@dataclass
class GlobalSettings:
    """전역 설정"""
    pnetlab_vm_ip: str
    gateway_ip: str = "10.10.10.1"
    enable_password: str = ""
    admin_password: str = "admin"
    domain_name: str = "mylab.local"
    nso_authgroup: str = "default"
    nso_ned_id: str = "cisco-ios-cli-6.110"
    nso_username: str = "admin"
    nso_password: str = "admin"
    batfish_output_dir: str = "Data/Batfish"


@dataclass
class DeviceInfo:
    """장비 정보"""
    name: str
    oob_ip: str
    telnet_port: int
    GigabitEthernet: str = "0/2"  # OOB 인터페이스 번호
    oob_intf: str = "GigabitEthernet0/2"  # 전체 인터페이스 이름
    device_group: str = "default"
    device_type: str = "iol"  # PNETLab 장비 타입
    template: str = "iol"  # PNETLab 템플릿


@dataclass
class LabInventory:
    """Lab 인벤토리"""
    global_settings: GlobalSettings
    devices: List[DeviceInfo] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            "global_settings": asdict(self.global_settings),
            "devices": [asdict(d) for d in self.devices]
        }
    
    def to_json(self, indent: int = 2) -> str:
        """JSON 문자열로 변환"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    def save(self, filepath: str) -> None:
        """파일로 저장"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
        logger.info(f"Inventory saved to {filepath}")


class InventoryBuilder:
    """
    PNETLab 토폴로지를 device_info.json으로 변환하는 빌더
    
    사용 예:
        builder = InventoryBuilder(
            pnetlab_vm_ip="100.66.240.82",
            lab_name="Research_Institute_Internal_DC"
        )
        
        # PNETLab 노드 추가
        for node in pnetlab_nodes:
            builder.add_node(node)
        
        # 인벤토리 생성
        inventory = builder.build()
        inventory.save("device_info.json")
    """
    
    def __init__(
        self,
        pnetlab_vm_ip: str,
        lab_name: str = "default",
        base_oob_subnet: str = "10.10.10.0/24",
        base_oob_ip_start: int = 11
    ):
        """
        Args:
            pnetlab_vm_ip: PNETLab VM IP 주소
            lab_name: Lab 이름 (NSO authgroup 등에 사용)
            base_oob_subnet: OOB 관리 서브넷
            base_oob_ip_start: OOB IP 시작 번호 (10.10.10.{start})
        """
        self.pnetlab_vm_ip = pnetlab_vm_ip
        self.lab_name = lab_name
        self.base_oob_subnet = base_oob_subnet
        self.base_oob_ip_start = base_oob_ip_start
        
        self.devices: List[DeviceInfo] = []
        self._next_ip_offset = 0
        
        logger.info(f"InventoryBuilder initialized for lab '{lab_name}'")
    
    def add_node(
        self,
        node: Dict[str, Any],
        oob_ip: Optional[str] = None,
        telnet_port: Optional[int] = None
    ) -> None:
        """
        PNETLab 노드를 인벤토리에 추가합니다.
        
        Args:
            node: PNETLab 노드 정보 (name, type, template, console 등)
            oob_ip: OOB 관리 IP (없으면 자동 할당)
            telnet_port: Telnet 포트 (없으면 노드에서 추출)
        """
        name = node.get('name', 'unknown')
        device_type = node.get('type', 'iol')
        template = node.get('template', 'iol')
        
        # OOB IP 자동 할당
        if not oob_ip:
            oob_ip = self._allocate_oob_ip()
        
        # Telnet 포트 추출
        if not telnet_port:
            # 1. 노드 정보에 telnet_port 필드가 있으면 사용
            telnet_port = node.get('telnet_port', 0)
            
            # 2. telnet_port가 없으면 url에서 추출
            if not telnet_port:
                url = node.get('url', '')
                if url and ':' in url:
                    try:
                        # url 형식: "telnet://100.66.240.82:30037"
                        telnet_port = int(url.split(':')[-1])
                    except (ValueError, IndexError):
                        pass
            
            # 3. 그래도 없으면 console에서 추출
            if not telnet_port:
                console = node.get('console', '')
                if console and ':' in console:
                    try:
                        telnet_port = int(console.split(':')[-1])
                    except (ValueError, IndexError):
                        pass
            
            # 4. 최종적으로 0
            if not telnet_port:
                telnet_port = 0
        
        # OOB 인터페이스 결정 (장비 타입에 따라)
        oob_intf_num = self._get_oob_interface(device_type, template)
        
        device_info = DeviceInfo(
            name=name,
            oob_ip=oob_ip,
            telnet_port=telnet_port,
            GigabitEthernet=oob_intf_num,
            oob_intf=f"GigabitEthernet{oob_intf_num}",
            device_group=self.lab_name,
            device_type=device_type,
            template=template
        )
        
        self.devices.append(device_info)
        logger.debug(f"Added device: {name} ({device_type}) - {oob_ip}:{telnet_port}")
    
    def _allocate_oob_ip(self) -> str:
        """다음 OOB IP 주소를 할당합니다."""
        # 10.10.10.0/24 서브넷에서 순차적으로 할당
        base_parts = self.base_oob_subnet.split('/')[0].split('.')
        ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{self.base_oob_ip_start + self._next_ip_offset}"
        self._next_ip_offset += 1
        return ip
    
    def _get_oob_interface(self, device_type: str, template: str) -> str:
        """
        장비 타입에 따라 OOB 인터페이스를 결정합니다.
        
        Args:
            device_type: PNETLab 장비 타입 (iol, qemu, dynamips 등)
            template: 템플릿 이름
        
        Returns:
            인터페이스 번호 (예: "0/2", "0/3")
        """
        # 기본적으로 마지막 인터페이스를 OOB로 사용
        # TODO: 실제 장비 설정에서 인터페이스 개수를 확인하여 결정
        if device_type == 'iol':
            return "0/3"  # IOL은 보통 0/3을 OOB로 사용
        elif device_type == 'qemu':
            return "0/0"  # QEMU는 Gi0/0 사용
        else:
            return "0/2"  # 기본값
    
    def build(self) -> LabInventory:
        """
        최종 인벤토리를 생성합니다.
        
        Returns:
            LabInventory 객체
        """
        global_settings = GlobalSettings(
            pnetlab_vm_ip=self.pnetlab_vm_ip,
            gateway_ip=self.base_oob_subnet.rsplit('.', 1)[0] + ".1",
            nso_authgroup=self.lab_name,
            batfish_output_dir=f"Data/Batfish/{self.lab_name}"
        )
        
        inventory = LabInventory(
            global_settings=global_settings,
            devices=self.devices
        )
        
        logger.info(f"Built inventory: {len(self.devices)} devices")
        return inventory
    
    def add_nodes_from_topology(self, topology: Dict[str, Any]) -> None:
        """
        PNETLab 토폴로지 전체에서 노드를 추출하여 추가합니다.
        
        Args:
            topology: PNETLab API에서 가져온 토폴로지 데이터
        """
        # 토폴로지에서 노드 추출
        nodes = topology.get('data', {}).get('nodes', {})
        
        if not nodes:
            logger.warning("No nodes found in topology")
            return
        
        # 각 노드를 인벤토리에 추가
        for node_id, node_data in nodes.items():
            self.add_node(node_data)
        
        logger.info(f"Added {len(nodes)} nodes from topology")


def build_inventory_from_pnetlab(
    pnetlab_vm_ip: str,
    topology: Dict[str, Any],
    lab_name: str = "default"
) -> LabInventory:
    """
    PNETLab 토폴로지에서 인벤토리를 생성하는 헬퍼 함수
    
    Args:
        pnetlab_vm_ip: PNETLab VM IP
        topology: PNETLab 토폴로지 데이터
        lab_name: Lab 이름
    
    Returns:
        LabInventory 객체
    """
    builder = InventoryBuilder(pnetlab_vm_ip, lab_name)
    builder.add_nodes_from_topology(topology)
    return builder.build()
