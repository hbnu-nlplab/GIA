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
    type: 'node' | 'evidence' | null;
    id: string | null;
  };
  // Actions
  addEvidence: (e: Omit<Evidence, 'id'>) => void;
  openDetail: (type, id) => void;
}
```

---

## 3. Topology Visualization (React Flow)

Managed in [TopologyPanel.tsx](file:///home/kilab_pyj/codespace/GIA/NetAlly/frontend/src/components/TopologyPanel.tsx).

- **Custom Nodes**: `DeviceNode.tsx` renders icons based on device type (Router, Switch, Server).
- **L3 Edges**: Animated lines representing active Layer 3 paths discovered by Batfish.
- **Interactions**: 
  - `Click`: Select node (focus in Chat).
  - `Double Click`: Open Node Inspector.
  - `Pan/Zoom`: Exploration of large topologies.

---

## 4. Real-time Streaming (SSE)

The `ChatPanel` handles the Server-Sent Events stream from the backend.

### Stream Parsing
1.  **Chunks**: Received as text stream.
2.  **Event Mapping**:
    - `event: tool_call`: Displays "Executing [Tool]..." in chat.
    - `event: tool_output`: Automatically triggers `addEvidence()` in the Zustand store.
    - `event: answer`: Displays final AI response.

---

## 5. Directory Structure
```
frontend/src/
  ├── components/      # Functional UI units
  ├── store.ts         # Zustand global state
  ├── App.tsx          # Main layout and routing
  ├── index.css        # Tailwind directives and global styles
  └── main.tsx         # Root entry point
```
