# Setup and Deployment Guide

Follow these steps to deploy and configure NetAlly in your environment.

---

## 1. Prerequisites

- **Docker & Docker Compose**: Installed and running.
- **NSO (Cisco Network Services Orchestrator)**: Must be reachable via RESTCONF.
- **PNETLab**: Environment for hosting the virtual network nodes.
- **OpenAI API Key**: Required for the agentic reasoning layer.

---

## 2. Environment Variables

Create a `.env` file in the `NetAlly` root directory:

```env
# AI Agent Configuration
OPENAI_API_KEY=sk-...

# NSO Configuration
NSO_BASE_URL=http://<nso-host>:8080/restconf
NSO_USERNAME=admin
NSO_PASSWORD=admin

# Batfish Configuration
BATFISH_HOST=batfish

# Backend Configuration
PORT=8000
```

---

## 3. Deployment (Docker Compose)

NetAlly uses a multi-stage Docker build to package both the React frontend and Python backend.

```bash
cd NetAlly
docker-compose up --build -d
```

### Services
- **NetAlly (`localhost:8000`)**: The main application.
- **Batfish (`localhost:9997`)**: The analysis engine (used internally by NetAlly).

---

## 4. Local Development

### Backend (Python)
```bash
cd NetAlly
pip install -e .
uvicorn main:app --reload --port 8000
```

### Frontend (React)
```bash
cd NetAlly/frontend
npm install
npm run dev # Runs on localhost:3000
```

---

## 5. Verification

1.  Open `http://localhost:8000` in your browser.
2.  Check the **Topology Panel** to ensure nodes are discovered.
3.  Type a query in the **Chat Panel** (e.g., "Check OSPF status on PE1").
4.  Observe real-time **Evidence Cards** appearing in the floating dashboard.
