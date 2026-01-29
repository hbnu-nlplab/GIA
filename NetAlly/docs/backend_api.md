# Backend API Specification

NetAlly's backend is a specialized FastAPI server designed for high-concurrency network analysis and real-time streaming.

---

## 1. Chat API (SSE)

**Endpoint**: `POST /api/chat`

Handles conversational intent and orchestrates tool execution. Uses **Server-Sent Events (SSE)** to stream the reasoning process and tool outputs.

### Request Body
```json
{
  "message": "Verify reachability between PE1 and PE2",
  "history": [],
  "answer_type": "text"
}
```

### Event Stream Format
| Event Type | Data Payload Example | Description |
|------------|----------------------|-------------|
| `planning` | `{"reasoning": "...", "skills": [...]}` | Initial plan from Orchestrator. |
| `tool_call`| `{"tool": "execute_reachability", "args": {...}}`| Notification before tool execution. |
| `tool_output`| `{"content": "Reachability: SUCCESS", ...}`| Raw result from tool (e.g., Batfish/NSO). |
| `answer` | `{"content": "..."}` | Final AI summary. |
| `complete` | `{"type": "complete"}` | End of stream signal. |

---

## 2. Topology API

**Endpoint**: `GET /api/topology`

Provides real-time network topology by reconciling PNETLab nodes and NSO registered devices.

### Response Format
```json
{
  "nodes": [
    {
      "id": "PE1",
      "type": "router",
      "data": { "mgmt_ip": "10.0.0.1", "platform": "ios" },
      "position": { "x": 100, "y": 100 }
    }
  ],
  "edges": [
    {
      "id": "e-PE1-PE2",
      "source": "PE1",
      "target": "PE2",
      "label": "Gi0/0 ↔ Gi0/0",
      "animated": true
    }
  ]
}
```

---

## 3. Agent Architecture (LangGraph)

The backend utilizes a **state-graph** to manage multi-step reasoning:

1.  **Orchestrator**: Analyzes user input and selects necessary "skills" (groups of tools).
2.  **Executor**: A loop that performs tool calls and handles exceptions.
3.  **Refiner**: (Optional) Summarizes intermediate outputs into a coherent final answer.

### Integrated Tools
- `network_query`: Fetch data from NSO.
- `network_verify`: Perform Batfish analysis.
- `lab_manage`: Interaction with PNETLab API.
- `onboard_device`: Auto-register PNETLab nodes to NSO.

---

## 4. Evidence Persistence

Tool results are captured as **Evidence Packs** and can be persisted (via `/api/evidence/{run_id}`) for later review or audit trails.
