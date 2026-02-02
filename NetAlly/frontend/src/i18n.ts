// i18n.ts - Translation system for Korean/English support
import { useAppStore } from './store';

export type Language = 'en' | 'ko';

export const translations = {
  en: {
    // Header
    header: {
      lab: 'LAB',
      snapshot: 'SNAPSHOT',
      active: 'ACTIVE',
    },
    // View Toggle
    view: {
      dashboard: 'Dashboard',
      map: 'Map View',
    },
    // Theme & Settings
    settings: {
      theme: 'Theme',
      light: 'Light',
      dark: 'Dark',
      language: 'Language',
      english: 'English',
      korean: '한국어',
    },
    // Dashboard
    dashboard: {
      title: 'Network Health Dashboard',
      healthScore: 'Health Score',
      labMode: 'Lab Mode',
      productionMode: 'Production Mode',
      deviceStatus: 'Device Status',
      online: 'Online',
      offline: 'Offline',
      protocols: {
        bgp: 'BGP Status',
        ospf: 'OSPF Status',
        up: 'Up',
        down: 'Down',
      },
      compliance: {
        routing: 'Routing Hygiene',
        security: 'Security Compliance',
        alwaysChecked: 'Always Checked',
        activeInProd: 'Active',
        disabledInLab: 'Disabled (Lab Mode)',
        routingDesc: 'MTU, Router ID, OSPF Area',
        securityDesc: 'NTP, SNMP, AAA, Passwords',
      },
      insights: {
        title: 'Active Insights',
        whatIsThis: 'What is this?',
        noIssues: 'All Systems Operational',
        noIssuesDesc: 'No critical issues detected.',
        severity: {
          critical: 'Critical',
          warning: 'Warning',
          info: 'Info',
        },
      },
      modal: {
        sessionDetails: 'Session Details',
        fetchingDetails: 'Fetching details...',
        noData: 'No detailed data available',
        status: 'Status',
      },
      complianceModal: {
        routing: {
          title: '🛣️ Routing Hygiene',
          description: 'Ensures that routing protocols are correctly configured and follow best practices.',
          checks: [
            { name: 'MTU Consistency', desc: 'All interfaces have matching MTU values to prevent fragmentation.' },
            { name: 'Router ID Uniqueness', desc: 'Each router has a unique Router ID for OSPF and BGP.' },
            { name: 'OSPF Area Configuration', desc: 'OSPF areas are correctly defined and backbone area (Area 0) exists.' },
            { name: 'Subnet Alignment', desc: 'Interface IPs are properly aligned with routing announcements.' },
          ],
        },
        security: {
          title: '🔒 Security Compliance',
          description: 'Validates that security best practices are implemented across the network.',
          checks: [
            { name: 'NTP Configuration', desc: 'Network Time Protocol is configured for accurate logging.' },
            { name: 'SNMP Security', desc: 'SNMPv3 is used or SNMPv2 communities are non-default.' },
            { name: 'AAA Authentication', desc: 'Authentication, Authorization, and Accounting is enabled.' },
            { name: 'Strong Passwords', desc: 'Enable secret and line passwords meet complexity requirements.' },
          ],
        },
        insights: {
          title: '📊 Active Insights',
          description: 'Real-time issues detected by Batfish deterministic analysis.',
          checks: [
            { name: 'BGP Session Down', desc: 'BGP peering sessions that are not in ESTABLISHED state.' },
            { name: 'OSPF Adjacency Issues', desc: 'OSPF neighbors not in FULL state.' },
            { name: 'Unreachable Networks', desc: 'Networks that cannot be reached from core routers.' },
            { name: 'Configuration Drift', desc: 'Devices with configs that differ from intended baseline.' },
          ],
        },
        verificationChecks: 'Verification Checks:',
      },
    },
    // Topology
    topology: {
      title: 'Network Topology',
      layers: {
        physical: 'Physical',
        logical: 'Logical',
      },
      reachability: 'Reachability Analysis',
      legend: 'Legend',
      loading: 'Fetching topology...',
      error: 'Failed to load topology',
    },
  },
  ko: {
    // Header
    header: {
      lab: '랩',
      snapshot: '스냅샷',
      active: '활성',
    },
    // View Toggle
    view: {
      dashboard: '대시보드',
      map: '맵 뷰',
    },
    // Theme & Settings
    settings: {
      theme: '테마',
      light: '라이트',
      dark: '다크',
      language: '언어',
      english: 'English',
      korean: '한국어',
    },
    // Dashboard
    dashboard: {
      title: '네트워크 헬스 대시보드',
      healthScore: '헬스 점수',
      labMode: '랩 모드',
      productionMode: '프로덕션 모드',
      deviceStatus: '장비 상태',
      online: '온라인',
      offline: '오프라인',
      protocols: {
        bgp: 'BGP 상태',
        ospf: 'OSPF 상태',
        up: '활성',
        down: '비활성',
      },
      compliance: {
        routing: '라우팅 위생',
        security: '보안 컴플라이언스',
        alwaysChecked: '항상 확인',
        activeInProd: '활성',
        disabledInLab: '비활성 (랩 모드)',
        routingDesc: 'MTU, Router ID, OSPF Area',
        securityDesc: 'NTP, SNMP, AAA, 비밀번호',
      },
      insights: {
        title: '활성 인사이트',
        whatIsThis: '무엇인가요?',
        noIssues: '모든 시스템 정상',
        noIssuesDesc: '심각한 문제가 감지되지 않았습니다.',
        severity: {
          critical: '심각',
          warning: '경고',
          info: '정보',
        },
      },
      modal: {
        sessionDetails: '세션 상세정보',
        fetchingDetails: '세부 정보 가져오는 중...',
        noData: '사용 가능한 세부 데이터가 없습니다',
        status: '상태',
      },
      complianceModal: {
        routing: {
          title: '🛣️ 라우팅 위생',
          description: '라우팅 프로토콜이 올바르게 구성되고 모범 사례를 따르는지 확인합니다.',
          checks: [
            { name: 'MTU 일관성', desc: '모든 인터페이스가 일치하는 MTU 값을 가져 단편화를 방지합니다.' },
            { name: 'Router ID 고유성', desc: '각 라우터가 OSPF 및 BGP에 대해 고유한 Router ID를 갖습니다.' },
            { name: 'OSPF Area 구성', desc: 'OSPF 영역이 올바르게 정의되고 백본 영역(Area 0)이 존재합니다.' },
            { name: '서브넷 정렬', desc: '인터페이스 IP가 라우팅 공고와 적절하게 정렬됩니다.' },
          ],
        },
        security: {
          title: '🔒 보안 컴플라이언스',
          description: '네트워크 전반에 보안 모범 사례가 구현되었는지 검증합니다.',
          checks: [
            { name: 'NTP 구성', desc: '정확한 로깅을 위해 네트워크 시간 프로토콜이 구성되었습니다.' },
            { name: 'SNMP 보안', desc: 'SNMPv3이 사용되거나 SNMPv2 커뮤니티가 기본값이 아닙니다.' },
            { name: 'AAA 인증', desc: '인증, 권한 부여 및 계정이 활성화되었습니다.' },
            { name: '강력한 비밀번호', desc: 'Enable secret 및 라인 비밀번호가 복잡성 요구사항을 충족합니다.' },
          ],
        },
        insights: {
          title: '📊 활성 인사이트',
          description: 'Batfish 결정론적 분석으로 감지된 실시간 문제입니다.',
          checks: [
            { name: 'BGP 세션 다운', desc: 'ESTABLISHED 상태가 아닌 BGP 피어링 세션입니다.' },
            { name: 'OSPF 인접성 문제', desc: 'FULL 상태가 아닌 OSPF 이웃입니다.' },
            { name: '도달 불가능한 네트워크', desc: '코어 라우터에서 도달할 수 없는 네트워크입니다.' },
            { name: '구성 드리프트', desc: '의도한 베이스라인과 다른 구성을 가진 장비입니다.' },
          ],
        },
        verificationChecks: '검증 체크 항목:',
      },
    },
    // Topology
    topology: {
      title: '네트워크 토폴로지',
      layers: {
        physical: '물리',
        logical: '논리',
      },
      reachability: '도달성 분석',
      legend: '범례',
      loading: '토폴로지 가져오는 중...',
      error: '토폴로지 로드 실패',
    },
  },
};

// Type-safe translation hook
export const useTranslation = () => {
  const language = useAppStore((state) => state. language);
  
  const t = (key: string): any => {
    const keys = key.split('.');
    let value: any = translations[language];
    
    for (const k of keys) {
      value = value?.[k];
      if (value === undefined) {
        console.warn(`Translation key not found: ${key}`);
        return key;
      }
    }
    
    return value;
  };
  
  return { t, language };
};
