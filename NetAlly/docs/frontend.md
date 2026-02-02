# Frontend Specification

NetAlly's frontend is built with **React**, **TypeScript**, and **Tailwind CSS**, emphasizing a fast, responsive "DevUI" aesthetic.

---

## 1. Design System

### Aesthetic: Zinc & Emerald
- **Primary Palette**: `Zinc` (Slate-like grays) for the base, `Emerald` for accents and success states.
- **Dark Mode**: High-contrast dark background (`#09090b`) with subtle borders (`#27272a`).
- **Typography**: Interface-focused sans-serif (Inter/Geist) with monospace for logs and configuration snippets.

### Key Components
- **Dashboard Sidebar (Floating)**: Evidence cards with glassmorphism effects (`backdrop-blur`).
- **Slide-over Inspector**: Comprehensive detail view for nodes and evidence logs, entering from the left.
- **Glass-morphic Chat**: Semi-transparent sidebar to maintain visual continuity with the topology.

---

## 2. State Management (Zustand)

Global state is managed via [store.ts](file:///home/kilab_pyj/codespace/GIA/NetAlly/frontend/src/store.ts).

### Store Structure
```typescript
interface AppState {
  selectedNode: string | null;      // Currently clicked node in Topology
  evidenceList: Evidence[];         // Cumulative tool results from SSE
  detailView: {                     // Inspector visibility state
    isOpen: boolean;
    type: 'node' | 'evidence' | 'device' | null;
    id: string | null;
  };
  
  // UI Settings
  theme: 'light' | 'dark';
  language: 'en' | 'ko';
  topologySource: 'batfish' | 'pnetlab';  // NEW: Toggle between auto-layout and PNETLab positions
  viewMode: 'dashboard' | 'topology';
  
  // Actions
  addEvidence: (e: Omit<Evidence, 'id'>) => void;
  openDetail: (type, id) => void;
  setTopologySource: (source) => void;
}
```

---

## 3. Topology Visualization (React Flow)

Managed in [TopologyPanel.tsx](file:///home/kilab_pyj/codespace/GIA/NetAlly/frontend/src/components/TopologyPanel.tsx).

- **Custom Nodes**: `DeviceNode.tsx` renders icons based on device type (Router, Switch, Server).
- **L1/L3 Edges**: Animated lines representing Layer 1 (physical) or Layer 3 (IP) paths.
- **Topology Sources**:
  - **Batfish**: Auto-layout with dagre (hierarchical arrangement)
  - **PNETLab**: Real positions from Lab (matches Lab.png layout)
- **Interactions**: 
  - `Click`: Select node and open DeviceDetailPanel.
  - `Pan/Zoom`: Exploration of large topologies.

---

## 4. Real-time Streaming (SSE)

The `ChatPanel` handles the Server-Sent Events stream from the backend.

### Stream Parsing
1. **Chunks**: Received as text stream.
2. **Event Mapping**:
    - `event: tool_call`: Displays "Executing [Tool]..." in chat.
    - `event: tool_output`: Automatically triggers `addEvidence()` in the Zustand store.
    - `event: answer`: Displays final AI response.

---

## 5. New Features

### DeviceDetailPanel
Slide-in panel from the right when clicking topology nodes showing:
- **Config Tab**: Full device configuration
- **Routes Tab**: Routing table entries
- **Interfaces Tab**: Interface status and IPs

### Multi-language Support (i18n)
- Language selector in Settings menu
- Full EN/KO translations via `i18n.ts`
- Translations cover Dashboard, Topology, Compliance modals

---

## 6. Directory Structure
```
frontend/src/
  ├── components/          # Functional UI units
  │   ├── DashboardPanel.tsx       # Main dashboard view
  │   ├── TopologyPanel.tsx        # React Flow topology
  │   ├── DeviceDetailPanel.tsx    # NEW: Device detail slide-in
  │   ├── ChatPanel.tsx            # SSE chat interface
  │   └── EvidencePanel.tsx        # Evidence cards
  ├── store.ts             # Zustand global state
  ├── i18n.ts              # Translation system
  ├── App.tsx              # Main layout and routing
  ├── index.css            # Tailwind directives and global styles
  └── main.tsx             # Root entry point
```
