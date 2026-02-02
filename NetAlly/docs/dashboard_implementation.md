# Verification Dashboard Implementation Specifications

## 1. API Spec: `/api/dashboard/summary`

### Response Format (JSON)
```json
{
  "health_score": number, // 0-100
  "protocols": {
    "bgp": { "total": number, "up": number, "down": number, "status": "healthy" | "warning" | "critical" },
    "ospf": { "total": number, "up": number, "down": number, "status": "string" }
  },
  "issues": [
    {
      "id": "uuid",
      "severity": "critical" | "warning",
      "type": "BGP_SESSION_DOWN" | "OSPF_MISMATCH" | "CONFIG_ERROR",
      "title": "Title of the issue",
      "message": "Detailed human-readable explanation",
      "affected_nodes": ["node1", "node2"]
    }
  ],
  "device_status": {
    "hostname": "status" // "healthy" | "warning" | "critical"
  }
}
```

---

## 2. Backend Logic (Batfish Integration)

### BGP Analysis
- Query: `bf.q.bgpSessionStatus().answer().frame()`
- Logic: `Established`가 아닌 모든 세션을 추출하여 `issues`에 추가.

### OSPF Analysis
- Query: `bf.q.ospfSessionCompatibility().answer().frame()`
- Logic: `SESSION_COMPATIBLE`이 아닌 항목을 분석하여 타이머 불일치, 구역 불일치 등을 인사이트로 변환.

### Configuration Compliance (Hygiene)
- Query: `bf.q.nodeProperties()`
- Logic: NTP 설정 유무, SNMP 설정 유무 등을 체크하여 점수에 반영.

---

## 3. Frontend Architecture

### DashboardPanel (New)
- **Location**: `frontend/src/components/DashboardPanel.tsx`
- **Main Layout**: Grid system using Tailwind CSS.
- **Components**:
  - `StatusCard`: Summary of a specific protocol or area.
  - `InsightList`: Scrollable list of actionable messages.

### State Management (Zustand)
- Store `dashboardData` and provide `refreshDashboard()` function.
- Auto-refresh mechanism (optional or triggered by chat events).

---

## 4. Transition Plan
1. Implement `BatfishClient.get_dashboard_data()` in Python.
2. Create FastAPI endpoint.
3. Replace `TopologyPanel` usage in `App.tsx` with `DashboardPanel`.
4. Add "View Map" overlay/modal for the existing topology visualization.
