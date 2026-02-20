"""
NetAlly FastAPI Backend
- SSE 스트리밍 채팅 API
- 토폴로지 API
- Evidence(검증 결과) API
"""

import os
import json
import asyncio
from typing import List, Optional, Any, Dict, Set, Tuple
from contextlib import asynccontextmanager
from pathlib import Path
import re
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv
import logging

load_dotenv()

# Logger Config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetAlly")

# Runtime settings keys that can be persisted/restored across container restarts.
RUNTIME_SETTINGS_ALLOWED_KEYS = {
    "OPENAI_API_KEY",
    "NSO_BASE_URL",
    "NSO_USERNAME",
    "NSO_PASSWORD",
    "PNETLAB_URL",
    "PNETLAB_INVENTORY_BACKEND",
    "PNETLAB_LAB_NAME",
    "PNETLAB_NSO_NODE",
    "PNETLAB_EXCLUDE_NODE_NAMES",
    "BATFISH_HOST",
    "BATFISH_SNAPSHOT",
    "BATFISH_NETWORK",
    "AUTO_PREPARE_ON_CHAT",
    "AUTO_INIT_BATFISH",
    "NETALLY_TOOL_BACKEND",
    "NETALLY_AGENT_BACKEND",
    "NETALLY_EXECUTOR_SYSTEM_PROMPT",
    "NETALLY_TEAM_MULTI_MODULE",
    "NETALLY_TEAM_MULTI_DATASET_TYPE",
    "NETALLY_TEAM_MULTI_ROOT",
    "NETALLY_TEAM_MULTI_CONTEXT_PATH",
    "NETALLY_MCP_SERVER_URL",
    "NETALLY_MCP_ALLOW_MUTATIONS",
    "PNETLAB_COOKIES",
    "PNETLAB_AUTO_LOGIN",
    "PNETLAB_USERNAME",
    "PNETLAB_PASSWORD",
}


def _runtime_settings_path() -> Path:
    raw = str(os.getenv("NETALLY_RUNTIME_SETTINGS_PATH", "")).strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (Path(__file__).resolve().parent / p).resolve()
        return p
    return Path(__file__).resolve().parent / ".runtime" / "settings.runtime.json"


def _read_runtime_settings_file() -> Dict[str, str]:
    path = _runtime_settings_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        out: Dict[str, str] = {}
        for key, value in payload.items():
            if not isinstance(key, str):
                continue
            if key not in RUNTIME_SETTINGS_ALLOWED_KEYS:
                continue
            if value is None:
                continue
            out[key] = str(value)
        return out
    except Exception as e:
        logger.warning("Failed to read runtime settings file: %s (%s)", path, e)
        return {}


def _write_runtime_settings_file(payload: Dict[str, str]) -> None:
    path = _runtime_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _load_runtime_settings_from_file() -> Dict[str, str]:
    """
    Load persisted settings and apply them to process env.
    Values from runtime file intentionally override .env defaults.
    """
    payload = _read_runtime_settings_file()
    for key, value in payload.items():
        os.environ[key] = value
    return payload


def _persist_runtime_env() -> None:
    payload = _read_runtime_settings_file()
    for key in RUNTIME_SETTINGS_ALLOWED_KEYS:
        value = os.environ.get(key)
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = str(value)
    _write_runtime_settings_file(payload)


# =============================================================================
# Pydantic Models
# =============================================================================

class ChatMessage(BaseModel):
    """채팅 메시지"""
    role: str  # "user" | "assistant"
    content: str


class ChatAttachment(BaseModel):
    """Chat image attachment metadata."""
    name: str = Field(..., description="Original filename")
    mime_type: str = Field(default="image/png", description="MIME type")
    size: int = Field(default=0, description="File size in bytes")
    data_url: Optional[str] = Field(default=None, description="Data URL (optional)")


class ChatDeviceContext(BaseModel):
    """Device context pinned from topology click or slash-command picker."""
    id: str
    label: Optional[str] = None
    platform: Optional[str] = None
    device_type: Optional[str] = None


class ChatRequest(BaseModel):
    """채팅 요청"""
    message: str = Field(..., description="사용자 질문")
    history: List[ChatMessage] = Field(default_factory=list, description="대화 기록")
    answer_type: str = Field(default="text", description="답변 형식: text, numeric, set, map, boolean")
    context_device: Optional[ChatDeviceContext] = Field(
        default=None,
        description="Optional device context pinned from topology UI",
    )
    attachments: List[ChatAttachment] = Field(
        default_factory=list,
        description="Optional image attachments",
    )


class LabRefreshRequest(BaseModel):
    """Lab refresh 요청"""
    config_path: Optional[str] = Field(default=None, description="device_info.json 경로")
    overrides: Optional[Dict[str, Any]] = Field(default=None, description="device_info.json 생성 오버라이드")


class LabPrepareRequest(BaseModel):
    """Lab prepare 요청"""
    auto_init_batfish: Optional[bool] = Field(default=None, description="Batfish init 자동 수행")


class PnetlabAuthRequest(BaseModel):
    """PNETLab 인증 설정"""
    cookies: Optional[str] = Field(default=None, description="PNETLab 쿠키 문자열")
    auto_login: Optional[bool] = Field(default=None, description="자동 로그인 사용")
    username: Optional[str] = Field(default=None, description="PNETLab 계정")
    password: Optional[str] = Field(default=None, description="PNETLab 비밀번호")


class SettingsRequest(BaseModel):
    """런타임 설정 업데이트 (웹 UI에서 변경 가능)"""
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API 키")
    nso_base_url: Optional[str] = Field(default=None, description="NSO RESTCONF URL")
    nso_username: Optional[str] = Field(default=None, description="NSO 계정")
    nso_password: Optional[str] = Field(default=None, description="NSO 비밀번호")
    pnetlab_url: Optional[str] = Field(default=None, description="PNETLab URL")
    pnetlab_inventory_backend: Optional[str] = Field(
        default=None,
        description="PNETLab inventory backend: labfs_local | labfs_ssh | api",
    )
    pnetlab_lab_name: Optional[str] = Field(default=None, description="PNETLab lab name")
    pnetlab_nso_node: Optional[str] = Field(default=None, description="PNETLab NSO node name")
    pnetlab_exclude_node_names: Optional[str] = Field(
        default=None,
        description="Comma-separated onboarding exclude node names",
    )
    batfish_host: Optional[str] = Field(default=None, description="Batfish 호스트")
    batfish_snapshot: Optional[str] = Field(default=None, description="Batfish snapshot/network name")
    auto_prepare_on_chat: Optional[bool] = Field(default=None, description="Auto prepare Batfish on chat")
    auto_init_batfish: Optional[bool] = Field(default=None, description="Auto init Batfish on prepare")
    tool_backend: Optional[str] = Field(default=None, description="Tool backend: mcp | legacy")
    agent_backend: Optional[str] = Field(
        default=None,
        description="Agent backend: single_executor | team_multi_adapter | legacy_graph",
    )
    executor_system_prompt: Optional[str] = Field(
        default=None,
        description="Prompt override for single_executor runtime",
    )
    team_multi_module: Optional[str] = Field(
        default=None,
        description="Python module for team multi-agent adapter (e.g. agents.main_netconfig)",
    )
    team_multi_dataset_type: Optional[str] = Field(
        default=None,
        description="Dataset type for team multi-agent adapter",
    )
    team_multi_root: Optional[str] = Field(
        default=None,
        description="Filesystem root path of external MultiAgent project",
    )
    team_multi_context_path: Optional[str] = Field(
        default=None,
        description="Optional context file path passed to team multi-agent adapter",
    )
    mcp_server_url: Optional[str] = Field(default=None, description="MCP server URL")
    mcp_allow_mutations: Optional[bool] = Field(default=None, description="Allow mutating MCP tools")

    @field_validator("tool_backend")
    @classmethod
    def validate_tool_backend(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip().lower()
        if normalized not in {"mcp", "legacy"}:
            raise ValueError("tool_backend must be one of: mcp, legacy")
        return normalized

    @field_validator("agent_backend")
    @classmethod
    def validate_agent_backend(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip().lower()
        if normalized not in {"single_executor", "team_multi_adapter", "legacy_graph"}:
            raise ValueError(
                "agent_backend must be one of: single_executor, team_multi_adapter, legacy_graph"
            )
        return normalized

    @field_validator("team_multi_dataset_type")
    @classmethod
    def validate_team_multi_dataset_type(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip().lower()
        if not normalized:
            return None
        allowed = {"netconfig", "descriptive", "multiple_choice", "short_answer"}
        if normalized not in allowed:
            raise ValueError(
                "team_multi_dataset_type must be one of: netconfig, descriptive, multiple_choice, short_answer"
            )
        return normalized

    @field_validator("pnetlab_inventory_backend")
    @classmethod
    def validate_inventory_backend(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip().lower()
        if not normalized:
            return None
        if normalized not in {"labfs_local", "labfs_ssh", "api"}:
            raise ValueError("pnetlab_inventory_backend must be one of: labfs_local, labfs_ssh, api")
        return normalized


class TopologyNode(BaseModel):
    """토폴로지 노드"""
    id: str
    type: str = "router"  # "router" | "switch" | "server"
    data: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    """토폴로지 엣지"""
    source: str
    target: str
    label: Optional[str] = None


class TopologyResponse(BaseModel):
    """토폴로지 응답"""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]


# =============================================================================
# Lifespan (startup/shutdown)
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """앱 시작/종료 시 실행"""
    # Startup
    print("[NetAlly] Starting up...")

    app.state.tool_backend = os.getenv("NETALLY_TOOL_BACKEND", TOOL_BACKEND_DEFAULT).lower()
    app.state.agent_backend = os.getenv("NETALLY_AGENT_BACKEND", AGENT_BACKEND_DEFAULT).lower()
    app.state.mcp_health = {"ok": False, "tool_count": 0}
    app.state.runtime_settings_path = str(_runtime_settings_path())
    app.state.runtime_settings_loaded_keys = sorted(_RUNTIME_SETTINGS_BOOT.keys())
    # Agent runtime is intentionally lazy-loaded so the app can boot without LLM creds
    # (topology / settings / PNETLab LabFS features should still work).
    app.state.runtime = None
    app.state.runtime_load_error = None
    app.state.bound_tool_count = 0
    app.state._runtime_lock = asyncio.Lock()
    app.state.batfish_client = None
    # Backward compatibility fields
    app.state.graph = None
    app.state.graph_load_error = None
    app.state._graph_lock = app.state._runtime_lock
    if app.state.tool_backend == "mcp":
        try:
            from agent.mcp_server import start_embedded_mcp_server
            from agent.mcp_client import get_mcp_client

            started = await start_embedded_mcp_server()
            health = await get_mcp_client().health_check()
            app.state.mcp_health = health
            logger.info(f"MCP runtime startup: {started}")
            logger.info(f"MCP health: {health}")
        except Exception as e:
            logger.error(f"MCP runtime startup failed: {e}")

    print("[NetAlly] Startup complete (agent runtime lazy-loaded).")
    
    yield
    
    # Shutdown
    if getattr(app.state, "tool_backend", TOOL_BACKEND_DEFAULT) == "mcp":
        try:
            from agent.mcp_server import stop_embedded_mcp_server
            await stop_embedded_mcp_server()
        except Exception as e:
            logger.warning(f"MCP runtime shutdown warning: {e}")
    print("[NetAlly] Shutting down...")


# =============================================================================
# App Initialization
# =============================================================================

app = FastAPI(
    title="NetAlly",
    description="Multi-Agent System for Network Configuration Management",
    version="0.1.0",
    lifespan=lifespan,
)

# Restore persisted runtime settings (if any) before computing module defaults.
_RUNTIME_SETTINGS_BOOT = _load_runtime_settings_from_file()

# Snapshot name (Batfish)
BATFISH_SNAPSHOT = (
    os.getenv("BATFISH_SNAPSHOT")
    or os.getenv("BATFISH_NETWORK")
    or "default"
)
AUTO_PREPARE_ON_CHAT = os.getenv("AUTO_PREPARE_ON_CHAT", "false").lower() == "true"
AUTO_INIT_BATFISH = os.getenv("AUTO_INIT_BATFISH", "false").lower() == "true"
TOOL_BACKEND_DEFAULT = os.getenv("NETALLY_TOOL_BACKEND", "mcp").lower()
AGENT_BACKEND_DEFAULT = os.getenv("NETALLY_AGENT_BACKEND", "single_executor").lower()
MCP_SERVER_URL_DEFAULT = os.getenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:8811/mcp")


def _parse_bool(raw: Optional[str], default: bool) -> bool:
    if raw is None:
        return default
    return str(raw).strip().lower() == "true"


def get_batfish_snapshot() -> str:
    env_snapshot = str(os.getenv("BATFISH_SNAPSHOT", "")).strip()
    if env_snapshot:
        return env_snapshot
    env_network = str(os.getenv("BATFISH_NETWORK", "")).strip()
    if env_network:
        return env_network
    return BATFISH_SNAPSHOT


def get_auto_prepare_on_chat() -> bool:
    return _parse_bool(os.getenv("AUTO_PREPARE_ON_CHAT"), AUTO_PREPARE_ON_CHAT)


def get_auto_init_batfish() -> bool:
    return _parse_bool(os.getenv("AUTO_INIT_BATFISH"), AUTO_INIT_BATFISH)

# CORS 설정 (개발용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 origin으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 정적 파일 서빙 (프론트엔드 빌드 결과)
# NOTE: Static frontend is mounted *at the end of the file* so it does not
# shadow /api/* routes in Starlette's first-match routing.


# =============================================================================
# MCP / Tool Backend Helpers
# =============================================================================

def get_tool_backend() -> str:
    return os.getenv("NETALLY_TOOL_BACKEND", TOOL_BACKEND_DEFAULT).lower()


def get_agent_backend() -> str:
    return os.getenv("NETALLY_AGENT_BACKEND", AGENT_BACKEND_DEFAULT).lower()


def get_executor_prompt_override() -> Optional[str]:
    raw = os.getenv("NETALLY_EXECUTOR_SYSTEM_PROMPT")
    if raw is None:
        return None
    val = raw.strip()
    return val or None


def _invalidate_runtime() -> None:
    app.state.runtime = None
    app.state.runtime_load_error = None
    app.state.bound_tool_count = 0


def _get_batfish_client():
    from agent.clients.batfish import BatfishClient

    desired_host = os.getenv("BATFISH_HOST", "localhost")
    current = getattr(app.state, "batfish_client", None)
    if current is None or getattr(current, "host", None) != desired_host:
        current = BatfishClient(host=desired_host)
        app.state.batfish_client = current
    return current


async def call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    from agent.mcp_client import get_mcp_client

    res = await get_mcp_client().call_tool(tool_name, arguments)
    if res.get("ok"):
        payload = res.get("result", {})
        if isinstance(payload, dict):
            return payload
        return {"result": payload, "content": res.get("content", [])}

    return {
        "error": res.get("error", "MCP call failed"),
        "code": res.get("code"),
        "tool": tool_name,
        "result": res.get("result"),
        "raw": res,
    }


def _sse_event(event_name: str, payload: Dict[str, Any]) -> str:
    return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


_REFRESH_LOG_PREFIXES = ("agent", "telnetlib3", "NetAlly")


class _RefreshStreamLogHandler(logging.Handler):
    """Capture refresh-related logs and forward them into an asyncio queue."""

    def __init__(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
        super().__init__(level=logging.INFO)
        self._loop = loop
        self._queue = queue

    def emit(self, record: logging.LogRecord) -> None:
        logger_name = str(record.name or "")
        if record.levelno < logging.INFO:
            return
        if not any(logger_name.startswith(prefix) for prefix in _REFRESH_LOG_PREFIXES):
            return

        message = self.format(record) if self.formatter else record.getMessage()
        payload = {
            "ts": datetime.fromtimestamp(record.created).strftime("%H:%M:%S"),
            "level": record.levelname,
            "logger": logger_name,
            "message": message,
        }

        def _enqueue() -> None:
            try:
                self._queue.put_nowait({"type": "log", "data": payload})
            except asyncio.QueueFull:
                # Drop oldest-ish burst logs instead of failing the refresh stream.
                pass

        try:
            self._loop.call_soon_threadsafe(_enqueue)
        except Exception:
            pass


def _extract_mutations_block(payload: Any) -> Optional[Dict[str, str]]:
    """
    Normalize MCP mutation-blocked responses across wrapper shapes.
    """
    if not isinstance(payload, dict):
        return None

    candidates: List[Dict[str, Any]] = [payload]
    raw = payload.get("raw")
    if isinstance(raw, dict):
        candidates.append(raw)
    nested = payload.get("result")
    if isinstance(nested, dict):
        candidates.append(nested)

    for item in candidates:
        if str(item.get("code", "")).strip() != "mutations_blocked":
            continue
        return {
            "tool": str(item.get("tool") or payload.get("tool") or ""),
            "error": str(item.get("error") or payload.get("error") or ""),
        }
    return None


def _mutation_block_hint(tool_name: str) -> str:
    tool_label = tool_name or "requested tool"
    return (
        f"{tool_label} is blocked because MCP mutations are disabled. "
        "Set NETALLY_MCP_ALLOW_MUTATIONS=true for onboarding/init operations."
    )


def _refresh_logical_error(status_code: int, payload: Any) -> bool:
    if status_code >= 400:
        return True
    if isinstance(payload, dict):
        if str(payload.get("status", "")).strip().lower() == "failed":
            return True
        if payload.get("error") is not None:
            return True
        failed = payload.get("failed")
        if isinstance(failed, list) and len(failed) > 0:
            return True
        delete_failed = payload.get("delete_failed")
        if isinstance(delete_failed, list) and len(delete_failed) > 0:
            return True
        nso = payload.get("nso")
        if isinstance(nso, dict):
            nso_failed = nso.get("failed")
            if isinstance(nso_failed, list) and len(nso_failed) > 0:
                return True
        skipped = payload.get("skipped")
        if isinstance(skipped, list) and len(skipped) > 0:
            severe_reasons = {
                "ssh_enable_failed",
                "mgmt_ip_not_discovered",
                "console_unreachable",
                "registration_failed",
            }
            for item in skipped:
                if isinstance(item, dict) and str(item.get("reason", "")).strip() in severe_reasons:
                    return True
    return False


async def _run_lab_refresh(request: LabRefreshRequest) -> Tuple[int, Dict[str, Any]]:
    """
    Shared refresh execution path used by both JSON and stream endpoints.
    Returns (status_code, payload).
    """
    try:
        params: Dict[str, Any] = {}
        if request.config_path:
            params["config_path"] = request.config_path
        if request.overrides:
            params["overrides"] = request.overrides

        if get_tool_backend() == "mcp":
            result = await call_mcp_tool(
                "bootstrap_refresh_onboard",
                {"config_path": params.get("config_path"), "overrides": params.get("overrides")},
            )
            blocked = _extract_mutations_block(result)
            if blocked:
                tool_name = blocked.get("tool") or "bootstrap_refresh_onboard"
                detail = blocked.get("error") or _mutation_block_hint(tool_name)
                return 403, {
                    "detail": detail,
                    "code": "mutations_blocked",
                    "tool": tool_name,
                    "hint": _mutation_block_hint(tool_name),
                }
            return 200, result

        from agent.tools import lab_bootstrap

        result = await asyncio.to_thread(
            lab_bootstrap.invoke,
            {"action": "refresh_onboard", "params": params},
        )
        return 200, result
    except Exception as e:
        logger.error(f"Lab refresh error: {e}")
        return 500, {"detail": str(e)}


# =============================================================================
# Health Check
# =============================================================================

@app.get("/api/health")
async def health():
    """헬스 체크"""
    runtime_loaded = bool(getattr(app.state, "runtime", None))
    runtime_error = getattr(app.state, "runtime_load_error", None)
    return {
        "status": "ok",
        "service": "netally",
        "tool_backend": get_tool_backend(),
        "agent_backend": get_agent_backend(),
        "mcp_health": getattr(app.state, "mcp_health", {"ok": False}),
        "agent_runtime_loaded": runtime_loaded,
        "agent_runtime_error": runtime_error,
        "bound_tool_count": int(getattr(app.state, "bound_tool_count", 0) or 0),
        # backward compatible aliases
        "agent_graph_loaded": runtime_loaded,
        "agent_graph_error": runtime_error,
    }


def _service_health_payload(status: str, severity: str, detail: str = "", extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "status": str(status or "unknown"),
        "severity": str(severity or "warning"),
        "detail": _truncate_text(detail, limit=220) if detail else "",
    }
    if isinstance(extra, dict) and extra:
        payload.update(extra)
    return payload


async def _runtime_health_nso() -> Dict[str, Any]:
    base_url = str(os.getenv("NSO_BASE_URL", "") or "").strip()
    username = str(os.getenv("NSO_USERNAME", "") or "").strip()
    password = str(os.getenv("NSO_PASSWORD", "") or "").strip()
    if not base_url:
        return _service_health_payload(
            "not_configured",
            "warning",
            "NSO_BASE_URL is not configured. Some intent checks may be limited.",
        )

    try:
        from agent.clients.nso import NSOClient

        client = NSOClient(
            base_url=base_url,
            username=username or "admin",
            password=password or "admin",
            timeout=2,
        )
        devices = await asyncio.wait_for(asyncio.to_thread(client.get_devices), timeout=3)
        device_count = len(devices) if isinstance(devices, list) else 0
        return _service_health_payload(
            "ok",
            "ok",
            f"{device_count} device(s) reachable from NSO.",
            {"device_count": device_count},
        )
    except asyncio.TimeoutError:
        return _service_health_payload("timeout", "error", "NSO check timed out.")
    except Exception as e:
        return _service_health_payload("error", "error", f"NSO check failed: {e}")


def _pnetlab_api_auth_enabled() -> bool:
    raw = str(os.getenv("PNETLAB_ENABLE_API_AUTH", "false") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _effective_pnetlab_inventory_backend() -> str:
    explicit = str(os.getenv("PNETLAB_INVENTORY_BACKEND", "") or "").strip().lower()
    if explicit in {"labfs_local", "labfs_ssh", "api"}:
        return explicit
    try:
        from agent.pnetlab_labfs import resolve_inventory_backend

        resolved = str(resolve_inventory_backend() or "").strip().lower()
        if resolved in {"labfs_local", "labfs_ssh", "api"}:
            return resolved
    except Exception:
        pass
    return explicit or "api"


async def _runtime_health_pnetlab() -> Dict[str, Any]:
    backend = _effective_pnetlab_inventory_backend()
    if backend in {"labfs_local", "labfs_ssh"}:
        return _service_health_payload(
            "ok",
            "ok",
            f"PNETLab inventory backend is {backend} (API auth bypassed).",
            {"backend": backend},
        )

    if not _pnetlab_api_auth_enabled():
        return _service_health_payload(
            "disabled",
            "warning",
            "PNETLab API auth is disabled. Use LabFS backend for inventory/refresh.",
            {"backend": backend},
        )

    base_url = str(os.getenv("PNETLAB_URL") or os.getenv("PNETLAB_HOST") or "").strip()
    username = str(os.getenv("PNETLAB_USERNAME", "") or "").strip()
    password = str(os.getenv("PNETLAB_PASSWORD", "") or "").strip()
    if not base_url:
        return _service_health_payload(
            "not_configured",
            "warning",
            "PNETLAB_URL is not configured. Live lab inventory may be limited.",
        )

    try:
        from agent.clients.pnetlab import PnetlabClient

        client = PnetlabClient(base_url=base_url, username=username, password=password, timeout=2)
        if not client.is_authenticated:
            return _service_health_payload(
                "unauthenticated",
                "warning",
                "PNETLab session is not authenticated.",
            )

        topo = await asyncio.wait_for(asyncio.to_thread(client.get_session_topology), timeout=3)
        if isinstance(topo, dict) and topo.get("error"):
            return _service_health_payload("error", "error", str(topo.get("error")))

        node_count = 0
        if isinstance(topo, dict) and isinstance(topo.get("nodes"), dict):
            node_count = len(topo.get("nodes", {}))
        return _service_health_payload(
            "ok",
            "ok",
            f"PNETLab topology reachable ({node_count} node records).",
            {"node_count": node_count},
        )
    except asyncio.TimeoutError:
        return _service_health_payload("timeout", "error", "PNETLab check timed out.")
    except Exception as e:
        return _service_health_payload("error", "error", f"PNETLab check failed: {e}")


def _runtime_health_batfish() -> Dict[str, Any]:
    try:
        batfish = _get_batfish_client()
        snapshot = get_batfish_snapshot()
        if not batfish.is_available:
            return _service_health_payload(
                "unavailable",
                "error",
                "Batfish service is unavailable.",
                {"snapshot": snapshot},
            )
        if batfish._builder:
            return _service_health_payload(
                "ready",
                "ok",
                f"Batfish snapshot is loaded ({snapshot}).",
                {"snapshot": snapshot},
            )
        return _service_health_payload(
            "not_ready",
            "warning",
            "Batfish is running but snapshot is not loaded. Run Prepare.",
            {"snapshot": snapshot},
        )
    except Exception as e:
        return _service_health_payload("error", "error", f"Batfish check failed: {e}")


@app.get("/api/runtime/health")
async def runtime_health():
    """Service-oriented runtime health for degraded-mode UX."""
    batfish = _runtime_health_batfish()
    nso = await _runtime_health_nso()
    pnetlab = await _runtime_health_pnetlab()
    services = {
        "batfish": batfish,
        "nso": nso,
        "pnetlab": pnetlab,
    }

    severities = [str(v.get("severity", "warning")) for v in services.values()]
    has_error = any(s == "error" for s in severities)
    has_warning = any(s == "warning" for s in severities)
    overall = "healthy" if not has_error and not has_warning else "degraded"
    recommended_mode = "full" if overall == "healthy" else "limited"

    notes: List[str] = []
    if batfish.get("status") == "not_ready":
        notes.append("Run Prepare to load Batfish snapshot for full path verification.")
    if batfish.get("status") in {"unavailable", "error", "timeout"}:
        notes.append("Batfish is unavailable. Path-focused checks may fail.")
    if nso.get("status") == "not_configured":
        notes.append("Configure NSO settings for richer device-grounded answers.")
    if pnetlab.get("status") == "unauthenticated":
        notes.append("Authenticate PNETLab to use live inventory and topology API.")
    if pnetlab.get("status") == "disabled":
        notes.append("PNETLab API auth is disabled. Keep using LabFS backend (recommended).")

    return {
        "status": "ok",
        "overall": overall,
        "recommendedMode": recommended_mode,
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "services": services,
        "notes": notes,
    }

# =============================================================================
# PNETLab Icon Proxy (for topology replication)
# =============================================================================

# Allow a narrow set of characters seen in PNETLab icon filenames.
# Keep this strict to prevent traversal or odd filesystem tricks.
_ICON_NAME_RE = re.compile(r"^[A-Za-z0-9_.() -]+$")


def _pnetlab_icon_root() -> Path:
    # When running inside PNETLab (recommended), mount /opt/unetlab read-only.
    return Path(os.getenv("PNETLAB_ICON_ROOT", "/opt/unetlab/html/images/icons"))


def _pnetlab_icon_cache_dir() -> Path:
    # Keep a small on-disk cache so UI stays snappy even if icon_root is remote mount.
    base = os.getenv("NETALLY_CACHE_DIR")
    if base:
        return Path(base).expanduser().resolve() / "pnetlab_icons"
    return Path(__file__).resolve().parent / ".tmp" / "pnetlab_icons"


def _resolve_icon_path(icon_name: str) -> Optional[Path]:
    """
    Resolve an icon file by name, with a case-insensitive fallback.
    Returns a Path under icon_root when found.
    """
    icon_root = _pnetlab_icon_root()
    if not icon_root.exists():
        return None

    direct = icon_root / icon_name
    if direct.exists() and direct.is_file():
        return direct

    # Case-insensitive fallback (PNETLab paths can vary by case).
    target_lower = icon_name.lower()
    try:
        for p in icon_root.iterdir():
            if p.is_file() and p.name.lower() == target_lower:
                return p
    except Exception:
        return None
    return None


@app.get("/api/pnetlab/icon/{icon_name}")
async def get_pnetlab_icon(icon_name: str):
    """
    Serve PNETLab icon images by filename.

    This endpoint intentionally does not accept paths (to prevent traversal).
    """
    if (
        not icon_name
        or icon_name in {".", ".."}
        or icon_name.startswith(".")
        or "/" in icon_name
        or "\\" in icon_name
        or not _ICON_NAME_RE.match(icon_name)
    ):
        raise HTTPException(status_code=400, detail="Invalid icon_name")

    cache_dir = _pnetlab_icon_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / icon_name
    if cached.exists() and cached.is_file():
        return FileResponse(str(cached), media_type="image/png")

    src = _resolve_icon_path(icon_name)
    if src is None:
        raise HTTPException(status_code=404, detail="Icon not found")

    # Copy to cache under requested name to keep the URL stable.
    try:
        cached.write_bytes(src.read_bytes())
    except Exception:
        # If caching fails, serve directly.
        return FileResponse(str(src), media_type="image/png")

    return FileResponse(str(cached), media_type="image/png")


@app.post("/api/lab/refresh")
async def lab_refresh(request: LabRefreshRequest):
    """
    PNETLab -> 신규 장비 부트스트랩 (Refresh 버튼용)
    - device_info.json이 없으면 API로 자동 생성
    """
    status_code, payload = await _run_lab_refresh(request)
    if status_code >= 400:
        return JSONResponse(status_code=status_code, content=payload)
    return payload


@app.post("/api/lab/refresh/stream")
async def lab_refresh_stream(request: LabRefreshRequest):
    """
    Refresh workflow with live progress/log SSE.
    Frontend can open this stream as soon as Refresh starts to show telnet/onboarding progress.
    """
    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }

    async def stream():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
        root_logger = logging.getLogger()
        log_handler = _RefreshStreamLogHandler(loop=loop, queue=queue)
        log_handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(log_handler)

        await queue.put(
            {
                "type": "status",
                "data": {
                    "phase": "started",
                    "message": "Refresh started. Discovering lab topology and onboarding candidates.",
                },
            }
        )

        async def _runner() -> None:
            status_code, payload = await _run_lab_refresh(request)
            failed = _refresh_logical_error(status_code, payload)
            await queue.put(
                {
                    "type": "status",
                    "data": {
                        "phase": "failed" if failed else "completed",
                        "message": (
                            "Refresh finished with errors. Check diagnostics payload."
                            if failed
                            else "Refresh completed successfully."
                        ),
                    },
                }
            )
            await queue.put(
                {
                    "type": "result",
                    "data": {
                        "status_code": status_code,
                        "result": payload,
                    },
                }
            )

        task = asyncio.create_task(_runner())
        result_sent = False
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=0.35)
                except asyncio.TimeoutError:
                    if task.done() and result_sent:
                        break
                    continue

                item_type = str(item.get("type") or "")
                data = item.get("data")
                if not isinstance(data, dict):
                    data = {"message": str(data)}

                if item_type == "status":
                    yield _sse_event("status", data)
                elif item_type == "log":
                    yield _sse_event("log", data)
                elif item_type == "result":
                    result_sent = True
                    yield _sse_event("result", data)
                    yield _sse_event("complete", {"type": "complete"})
                    break

            if task.done() and not result_sent:
                try:
                    exc = task.exception()
                except Exception:
                    exc = None
                if exc is not None:
                    yield _sse_event("error", {"type": "error", "message": str(exc)})
                    yield _sse_event("complete", {"type": "complete"})
        finally:
            root_logger.removeHandler(log_handler)
            if not task.done():
                task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

    return StreamingResponse(stream(), media_type="text/event-stream", headers=headers)


async def ensure_batfish_ready(auto_init: bool) -> Dict[str, Any]:
    batfish = _get_batfish_client()
    snapshot = get_batfish_snapshot()
    if not batfish.is_available:
        return {"status": "unavailable"}

    if batfish._builder:
        return {"status": "ready", "snapshot": snapshot}

    loaded = await asyncio.to_thread(batfish.load_snapshot, snapshot)
    if loaded:
        return {"status": "loaded", "snapshot": snapshot}

    if auto_init:
        init_params = {
            "topology_name": snapshot,
            "output_dir": os.getenv("BATFISH_EXPORT_DIR", "./snapshot"),
        }
        if get_tool_backend() == "mcp":
            result = await call_mcp_tool("lab_init_batfish", init_params)
            blocked = _extract_mutations_block(result)
            if blocked:
                tool_name = blocked.get("tool") or "lab_init_batfish"
                detail = blocked.get("error") or _mutation_block_hint(tool_name)
                return {
                    "status": "blocked",
                    "snapshot": snapshot,
                    "code": "mutations_blocked",
                    "tool": tool_name,
                    "detail": detail,
                    "hint": _mutation_block_hint(tool_name),
                }
        else:
            from agent.tools import lab_manage

            result = await asyncio.to_thread(
                lab_manage.invoke,
                {"action": "init_batfish", "params": init_params}
            )
        return {"status": "initialized", "snapshot": snapshot, "result": result}

    return {"status": "not_ready"}


@app.post("/api/lab/prepare")
async def lab_prepare(request: LabPrepareRequest):
    """
    Batfish 준비 상태를 확인하고 필요 시 초기화합니다.
    """
    try:
        auto_init = request.auto_init_batfish
        if auto_init is None:
            auto_init = get_auto_init_batfish()
        result = await ensure_batfish_ready(auto_init=auto_init)
        if isinstance(result, dict) and result.get("status") == "blocked":
            return JSONResponse(status_code=403, content=result)
        return result
    except Exception as e:
        logger.error(f"Lab prepare error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


@app.get("/api/pnetlab/status")
async def pnetlab_status():
    """
    PNETLab 인증 상태 확인
    """
    try:
        backend = _effective_pnetlab_inventory_backend()
        if backend in {"labfs_local", "labfs_ssh"}:
            return {
                "authenticated": False,
                "disabled": True,
                "mode": backend,
                "detail": "LabFS backend active (PNETLab API auth not required).",
            }
        if not _pnetlab_api_auth_enabled():
            return {
                "authenticated": False,
                "disabled": True,
                "mode": backend,
                "detail": "PNETLab API auth is disabled. Set PNETLAB_ENABLE_API_AUTH=true only for legacy API mode.",
            }

        from agent.tools import get_pnetlab_client
        client = get_pnetlab_client()
        if not client.is_authenticated:
            return {"authenticated": False}
        topo = client.get_session_topology()
        if isinstance(topo, dict) and "error" in topo:
            return {"authenticated": False, "error": topo.get("error")}
        return {"authenticated": True}
    except Exception as e:
        logger.error(f"Pnetlab status error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


@app.post("/api/pnetlab/auth")
async def pnetlab_auth(request: PnetlabAuthRequest):
    """
    PNETLab 인증 정보 설정 (쿠키/자동로그인)
    """
    try:
        if not _pnetlab_api_auth_enabled():
            return JSONResponse(
                status_code=409,
                content={
                    "authenticated": False,
                    "disabled": True,
                    "detail": (
                        "PNETLab API auth is disabled. Use LabFS backend (labfs_local/labfs_ssh). "
                        "Set PNETLAB_ENABLE_API_AUTH=true only if you need legacy cookie/API auth."
                    ),
                },
            )

        if request.cookies is not None:
            os.environ["PNETLAB_COOKIES"] = request.cookies
        if request.auto_login is not None:
            os.environ["PNETLAB_AUTO_LOGIN"] = "true" if request.auto_login else "false"
        if request.username is not None:
            os.environ["PNETLAB_USERNAME"] = request.username
        if request.password is not None:
            os.environ["PNETLAB_PASSWORD"] = request.password

        from agent.tools import reset_pnetlab_client, get_pnetlab_client
        reset_pnetlab_client()
        _persist_runtime_env()
        app.state.runtime_settings_path = str(_runtime_settings_path())
        app.state.runtime_settings_loaded_keys = sorted(_read_runtime_settings_file().keys())
        client = get_pnetlab_client()
        ok = client.is_authenticated
        return {"authenticated": ok}
    except Exception as e:
        logger.error(f"Pnetlab auth error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


# =============================================================================
# Settings API (Runtime Configuration)
# =============================================================================

@app.get("/api/settings")
async def get_settings():
    """
    현재 설정 조회 (민감 정보 마스킹)
    웹 UI Settings Dialog에서 사용
    """
    return {
        "openai_api_key": "****" if os.getenv("OPENAI_API_KEY") else None,
        "nso_base_url": os.getenv("NSO_BASE_URL"),
        "nso_username": os.getenv("NSO_USERNAME"),
        "nso_password": "****" if os.getenv("NSO_PASSWORD") else None,
        "pnetlab_url": os.getenv("PNETLAB_URL"),
        "pnetlab_inventory_backend": os.getenv("PNETLAB_INVENTORY_BACKEND"),
        "pnetlab_api_auth_enabled": _pnetlab_api_auth_enabled(),
        "pnetlab_lab_name": os.getenv("PNETLAB_LAB_NAME"),
        "pnetlab_nso_node": os.getenv("PNETLAB_NSO_NODE", "NSO"),
        "pnetlab_exclude_node_names": os.getenv("PNETLAB_EXCLUDE_NODE_NAMES", "NSO,Docker,NetAlly,Admin"),
        "batfish_host": os.getenv("BATFISH_HOST", "batfish"),
        "batfish_snapshot": get_batfish_snapshot(),
        "auto_prepare_on_chat": get_auto_prepare_on_chat(),
        "auto_init_batfish": get_auto_init_batfish(),
        "runtime_settings_path": str(getattr(app.state, "runtime_settings_path", _runtime_settings_path())),
        "runtime_settings_loaded_keys": list(getattr(app.state, "runtime_settings_loaded_keys", [])),
        "tool_backend": os.getenv("NETALLY_TOOL_BACKEND", TOOL_BACKEND_DEFAULT),
        "agent_backend": os.getenv("NETALLY_AGENT_BACKEND", AGENT_BACKEND_DEFAULT),
        "agent_prompt_mode": "prompt_only",
        "executor_system_prompt": os.getenv("NETALLY_EXECUTOR_SYSTEM_PROMPT"),
        "team_multi_module": os.getenv("NETALLY_TEAM_MULTI_MODULE", "agents.main_netconfig"),
        "team_multi_dataset_type": os.getenv("NETALLY_TEAM_MULTI_DATASET_TYPE", "netconfig"),
        "team_multi_root": os.getenv("NETALLY_TEAM_MULTI_ROOT"),
        "team_multi_context_path": os.getenv("NETALLY_TEAM_MULTI_CONTEXT_PATH"),
        "mcp_server_url": os.getenv("NETALLY_MCP_SERVER_URL", MCP_SERVER_URL_DEFAULT),
        "mcp_allow_mutations": os.getenv("NETALLY_MCP_ALLOW_MUTATIONS", "false").lower() == "true",
        "bound_tool_count": int(getattr(app.state, "bound_tool_count", 0) or 0),
    }


@app.post("/api/settings")
async def update_settings(request: SettingsRequest):
    """
    설정 업데이트 및 클라이언트 재초기화
    웹 UI Settings Dialog에서 Apply 버튼 클릭 시 호출
    """
    try:
        from agent.tools import (
            reset_nso_client, 
            reset_batfish_client, 
            reset_pnetlab_client
        )
        
        updated = []

        def set_or_clear_env(env_key: str, raw_value: Optional[str]) -> bool:
            if raw_value is None:
                return False
            val = str(raw_value).strip()
            if val:
                os.environ[env_key] = val
            else:
                os.environ.pop(env_key, None)
            return True

        if set_or_clear_env("OPENAI_API_KEY", request.openai_api_key):
            updated.append("openai_api_key")

        if set_or_clear_env("NSO_BASE_URL", request.nso_base_url):
            reset_nso_client()
            updated.append("nso_base_url")

        if set_or_clear_env("NSO_USERNAME", request.nso_username):
            reset_nso_client()
            updated.append("nso_username")

        if set_or_clear_env("NSO_PASSWORD", request.nso_password):
            reset_nso_client()
            updated.append("nso_password")

        if set_or_clear_env("PNETLAB_URL", request.pnetlab_url):
            reset_pnetlab_client()
            updated.append("pnetlab_url")

        if set_or_clear_env("PNETLAB_INVENTORY_BACKEND", request.pnetlab_inventory_backend):
            reset_pnetlab_client()
            updated.append("pnetlab_inventory_backend")

        if set_or_clear_env("PNETLAB_LAB_NAME", request.pnetlab_lab_name):
            reset_pnetlab_client()
            updated.append("pnetlab_lab_name")

        if set_or_clear_env("PNETLAB_NSO_NODE", request.pnetlab_nso_node):
            reset_pnetlab_client()
            reset_nso_client()
            updated.append("pnetlab_nso_node")

        if set_or_clear_env("PNETLAB_EXCLUDE_NODE_NAMES", request.pnetlab_exclude_node_names):
            updated.append("pnetlab_exclude_node_names")

        if set_or_clear_env("BATFISH_HOST", request.batfish_host):
            reset_batfish_client()
            app.state.batfish_client = None
            updated.append("batfish_host")

        if request.batfish_snapshot is not None:
            snapshot_val = request.batfish_snapshot.strip()
            if snapshot_val:
                os.environ["BATFISH_SNAPSHOT"] = snapshot_val
                os.environ["BATFISH_NETWORK"] = snapshot_val
            else:
                os.environ.pop("BATFISH_SNAPSHOT", None)
                os.environ.pop("BATFISH_NETWORK", None)
            reset_batfish_client()
            app.state.batfish_client = None
            updated.append("batfish_snapshot")

        if request.auto_prepare_on_chat is not None:
            os.environ["AUTO_PREPARE_ON_CHAT"] = "true" if request.auto_prepare_on_chat else "false"
            updated.append("auto_prepare_on_chat")

        if request.auto_init_batfish is not None:
            os.environ["AUTO_INIT_BATFISH"] = "true" if request.auto_init_batfish else "false"
            updated.append("auto_init_batfish")

        if request.tool_backend:
            os.environ["NETALLY_TOOL_BACKEND"] = request.tool_backend
            app.state.tool_backend = request.tool_backend
            updated.append("tool_backend")

        if request.agent_backend:
            os.environ["NETALLY_AGENT_BACKEND"] = request.agent_backend
            app.state.agent_backend = request.agent_backend
            updated.append("agent_backend")

        if request.executor_system_prompt is not None:
            prompt_val = request.executor_system_prompt.strip()
            if prompt_val:
                os.environ["NETALLY_EXECUTOR_SYSTEM_PROMPT"] = prompt_val
            else:
                os.environ.pop("NETALLY_EXECUTOR_SYSTEM_PROMPT", None)
            updated.append("executor_system_prompt")

        if request.team_multi_module is not None:
            module_val = request.team_multi_module.strip()
            if module_val:
                os.environ["NETALLY_TEAM_MULTI_MODULE"] = module_val
            else:
                os.environ.pop("NETALLY_TEAM_MULTI_MODULE", None)
            updated.append("team_multi_module")

        if request.team_multi_dataset_type is not None:
            dataset_val = request.team_multi_dataset_type.strip()
            if dataset_val:
                os.environ["NETALLY_TEAM_MULTI_DATASET_TYPE"] = dataset_val
            else:
                os.environ.pop("NETALLY_TEAM_MULTI_DATASET_TYPE", None)
            updated.append("team_multi_dataset_type")

        if request.team_multi_root is not None:
            root_val = request.team_multi_root.strip()
            if root_val:
                os.environ["NETALLY_TEAM_MULTI_ROOT"] = root_val
            else:
                os.environ.pop("NETALLY_TEAM_MULTI_ROOT", None)
            updated.append("team_multi_root")

        if request.team_multi_context_path is not None:
            path_val = request.team_multi_context_path.strip()
            if path_val:
                os.environ["NETALLY_TEAM_MULTI_CONTEXT_PATH"] = path_val
            else:
                os.environ.pop("NETALLY_TEAM_MULTI_CONTEXT_PATH", None)
            updated.append("team_multi_context_path")

        if set_or_clear_env("NETALLY_MCP_SERVER_URL", request.mcp_server_url):
            updated.append("mcp_server_url")

        if request.mcp_allow_mutations is not None:
            os.environ["NETALLY_MCP_ALLOW_MUTATIONS"] = "true" if request.mcp_allow_mutations else "false"
            updated.append("mcp_allow_mutations")

        # MCP runtime 재기동 (백엔드/URL 변경 시)
        if "tool_backend" in updated or "mcp_server_url" in updated:
            try:
                from agent.mcp_server import start_embedded_mcp_server, stop_embedded_mcp_server
                from agent.mcp_client import get_mcp_client, reset_mcp_client

                await stop_embedded_mcp_server()
                reset_mcp_client()
                if get_tool_backend() == "mcp":
                    started = await start_embedded_mcp_server()
                    app.state.mcp_health = await get_mcp_client().health_check()
                    logger.info(f"MCP runtime restarted: {started}")
                else:
                    app.state.mcp_health = {"ok": False, "tool_count": 0}
            except Exception as restart_err:
                logger.warning(f"MCP runtime restart warning: {restart_err}")

        runtime_sensitive = {
            "openai_api_key",
            "tool_backend",
            "agent_backend",
            "executor_system_prompt",
            "team_multi_module",
            "team_multi_dataset_type",
            "team_multi_root",
            "team_multi_context_path",
        }
        if runtime_sensitive.intersection(updated):
            _invalidate_runtime()

        _persist_runtime_env()
        app.state.runtime_settings_path = str(_runtime_settings_path())
        app.state.runtime_settings_loaded_keys = sorted(_read_runtime_settings_file().keys())
        
        logger.info(f"Settings updated: {updated}")
        return {"status": "updated", "updated_fields": updated}
        
    except Exception as e:
        logger.error(f"Settings update error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


# =============================================================================
# Chat API (SSE Streaming)
# =============================================================================

def _normalize_node_token(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        return None
    token = str(value).strip().strip("'\"`")
    if not token:
        return None
    if len(token) > 80:
        return None
    if token.lower() in {"none", "null", "unknown", "n/a", "na"}:
        return None
    # Avoid obvious IPs/prefixes in topology node candidates.
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$", token):
        return None
    return token


def _append_node(nodes: List[str], value: Any) -> None:
    token = _normalize_node_token(value)
    if token:
        nodes.append(token)


def _append_edge(nodes: List[str], edges: List[Dict[str, str]], src: Any, dst: Any) -> None:
    s = _normalize_node_token(src)
    t = _normalize_node_token(dst)
    if not s or not t:
        return
    nodes.extend([s, t])
    edges.append({"source": s, "target": t})


def _dedupe_nodes(nodes: List[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for n in nodes:
        key = str(n).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(str(n).strip())
    return out


def _dedupe_edges(edges: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: Set[Tuple[str, str]] = set()
    out: List[Dict[str, str]] = []
    for e in edges:
        s = _normalize_node_token(e.get("source"))
        t = _normalize_node_token(e.get("target"))
        if not s or not t:
            continue
        key = tuple(sorted([s.lower(), t.lower()]))
        if key in seen:
            continue
        seen.add(key)
        out.append({"source": s, "target": t})
    return out


def _extract_viz_candidates(payload: Any) -> Tuple[List[str], List[Dict[str, str]], bool]:
    nodes: List[str] = []
    edges: List[Dict[str, str]] = []
    path_hint = False

    node_keys = {
        "node", "hostname", "device", "src", "dst", "source", "target",
        "from", "to", "peer", "remote_node", "node1", "node2", "waypoint",
        "start", "end",
    }
    path_keys = {"path", "paths", "trace", "traces", "hops", "nodes", "affected_nodes"}

    def add_path_from_list(items: List[Any]) -> bool:
        path_nodes = [_normalize_node_token(x) for x in items]
        path_nodes = [n for n in path_nodes if n]
        if len(path_nodes) < 2:
            return False
        nodes.extend(path_nodes)
        for i in range(len(path_nodes) - 1):
            edges.append({"source": path_nodes[i], "target": path_nodes[i + 1]})
        return True

    def add_path_from_string(text: str) -> bool:
        if not isinstance(text, str):
            return False
        if "->" not in text and "→" not in text and "=>" not in text:
            return False
        parts = re.split(r"\s*(?:->|→|=>)\s*", text)
        tokens = [_normalize_node_token(p) for p in parts]
        tokens = [t for t in tokens if t]
        if len(tokens) < 2:
            return False
        nodes.extend(tokens)
        for i in range(len(tokens) - 1):
            edges.append({"source": tokens[i], "target": tokens[i + 1]})
        return True

    def walk(obj: Any, key_hint: str = "", depth: int = 0) -> None:
        nonlocal path_hint
        if depth > 5 or obj is None:
            return

        if isinstance(obj, dict):
            src = obj.get("source", obj.get("src", obj.get("from", obj.get("node1"))))
            dst = obj.get("target", obj.get("dst", obj.get("to", obj.get("node2"))))
            if src is not None and dst is not None:
                _append_edge(nodes, edges, src, dst)

            if "path" in obj and isinstance(obj.get("path"), list):
                if add_path_from_list(obj.get("path", [])):
                    path_hint = True

            for k, v in obj.items():
                kl = str(k).lower()
                if kl in node_keys:
                    _append_node(nodes, v)
                    continue

                if kl in path_keys:
                    if isinstance(v, list):
                        if add_path_from_list(v):
                            path_hint = True
                        for item in v:
                            walk(item, kl, depth + 1)
                    elif isinstance(v, str):
                        if add_path_from_string(v):
                            path_hint = True
                    else:
                        walk(v, kl, depth + 1)
                    continue

                if isinstance(v, (dict, list)):
                    walk(v, kl, depth + 1)
                elif isinstance(v, str) and kl in {"summary", "message"}:
                    if add_path_from_string(v):
                        path_hint = True

        elif isinstance(obj, list):
            if add_path_from_list(obj):
                path_hint = True
            for item in obj:
                walk(item, key_hint, depth + 1)

        elif isinstance(obj, str):
            if add_path_from_string(obj):
                path_hint = True

    walk(payload)
    return _dedupe_nodes(nodes), _dedupe_edges(edges), path_hint


def _title_for_viz(tool: str, args: Dict[str, Any]) -> str:
    args = args or {}
    params = args.get("params") if isinstance(args.get("params"), dict) else {}
    src = args.get("src", params.get("src"))
    dst = args.get("dst", params.get("dst"))
    device = args.get("device", params.get("device"))
    test_type = args.get("test_type", args.get("analysis_type"))

    if src or dst:
        return f"{tool}: {src} -> {dst}"
    if device:
        return f"{tool}: {device}"
    if test_type:
        return f"{tool}: {test_type}"
    return tool


VIZ_SCHEMA_VERSION = 1
VIZ_MAX_NODES = 40
VIZ_MAX_EDGES = 80


def _truncate_text(value: Any, limit: int = 220) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)]}..."


def _normalize_viz_mode(value: Any) -> str:
    if str(value or "").strip().lower() == "path":
        return "path"
    return "focus"


def _infer_viz_reason(tool: str, args: Dict[str, Any], mode: str, path_hint: bool = False) -> str:
    test_type = str((args or {}).get("test_type", "") or "").lower()
    analysis_type = str((args or {}).get("analysis_type", "") or "").lower()
    if mode == "path":
        if "traceroute" in str(tool or "").lower() or test_type == "traceroute":
            return "Traceroute-style intent detected. Path continuity is prioritized."
        if analysis_type.endswith("_impact"):
            return "Impact analysis detected. Transit relationships are highlighted as a path."
        if path_hint:
            return "Path-like tokens were detected in tool output."
        return "Path mode selected to emphasize end-to-end traversal."
    return "Focus mode selected to highlight directly related entities."


def _coerce_viz_contract(
    raw: Any,
    *,
    tool: str = "",
    args: Optional[Dict[str, Any]] = None,
    query: str = "",
    source: str = "",
    call_id: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None

    args = args or {}
    raw_nodes = raw.get("nodes")
    raw_edges = raw.get("edges")

    nodes: List[str] = []
    edges: List[Dict[str, str]] = []

    if isinstance(raw_nodes, list):
        for n in raw_nodes:
            _append_node(nodes, n)

    if isinstance(raw_edges, list):
        for e in raw_edges:
            if not isinstance(e, dict):
                continue
            _append_edge(nodes, edges, e.get("source"), e.get("target"))

    extra_nodes, extra_edges, path_hint = _extract_viz_candidates(raw)
    nodes = _dedupe_nodes(nodes + extra_nodes)
    edges = _dedupe_edges(edges + extra_edges)

    mode = _normalize_viz_mode(raw.get("mode"))
    if mode == "path" and not edges and len(nodes) >= 2:
        edges = [{"source": nodes[i], "target": nodes[i + 1]} for i in range(len(nodes) - 1)]

    # Ensure nodes include all edge endpoints.
    if edges:
        endpoints: List[str] = []
        for e in edges:
            endpoints.append(str(e.get("source", "")))
            endpoints.append(str(e.get("target", "")))
        nodes = _dedupe_nodes(nodes + endpoints)

    if not nodes and not edges:
        return None

    truncated = False
    if len(nodes) > VIZ_MAX_NODES:
        nodes = nodes[:VIZ_MAX_NODES]
        truncated = True
    if len(edges) > VIZ_MAX_EDGES:
        edges = edges[:VIZ_MAX_EDGES]
        truncated = True

    title = _truncate_text(raw.get("title") or _title_for_viz(tool, args) or "LLM Visualization", limit=120)
    reason = _truncate_text(raw.get("reason") or _infer_viz_reason(tool, args, mode, path_hint), limit=240)

    out: Dict[str, Any] = {
        "schema_version": VIZ_SCHEMA_VERSION,
        "mode": mode,
        "title": title,
        "nodes": nodes,
        "edges": edges,
        "reason": reason,
        "source": str(raw.get("source") or source or "runtime"),
        "diagnostics": {
            "requestedNodes": len(raw_nodes) if isinstance(raw_nodes, list) else 0,
            "requestedEdges": len(raw_edges) if isinstance(raw_edges, list) else 0,
            "normalizedNodes": len(nodes),
            "normalizedEdges": len(edges),
            "truncated": truncated,
        },
    }

    if isinstance(call_id, int):
        out["call_id"] = call_id
    elif isinstance(raw.get("call_id"), int):
        out["call_id"] = int(raw["call_id"])

    q = str(raw.get("query") or query or "").strip()
    if q:
        out["query"] = _truncate_text(q, limit=220)

    return out


def _tool_output_status(output_text: str, structured: Any = None) -> str:
    text = str(output_text or "").strip().lower()
    if isinstance(structured, dict):
        status = str(structured.get("status", "") or "").strip().lower()
        if status in {"error", "failed", "failure"}:
            return "error"
        if status in {"warning", "warn", "degraded", "partial"}:
            return "warning"
        if status in {"ok", "success", "completed", "ready"}:
            return "success"
    if "error" in text or "exception" in text or "failed" in text:
        return "error"
    if "warning" in text or "degraded" in text or "partial" in text:
        return "warning"
    return "success"


def _summarize_tool_payload(tool_name: str, structured: Any, raw_text: str) -> str:
    if isinstance(structured, dict):
        for key in ("summary", "message", "reason", "detail"):
            value = structured.get(key)
            if isinstance(value, str) and value.strip():
                return _truncate_text(value, limit=180)
        keys = [k for k in structured.keys() if isinstance(k, str)]
        if keys:
            return _truncate_text(f"{tool_name} result keys: {', '.join(keys[:6])}", limit=180)
    if isinstance(structured, list):
        return _truncate_text(f"{tool_name} returned list ({len(structured)} items)", limit=180)
    return _truncate_text(raw_text or f"{tool_name} returned output", limit=180)


def _build_answer_citation(
    *,
    call_id: Optional[int],
    tool_name: str,
    tool_input: Dict[str, Any],
    raw_output: str,
    structured_output: Any,
) -> Dict[str, Any]:
    args_preview: Dict[str, Any] = {}
    for k in ("src", "dst", "device", "test_type", "analysis_type"):
        if k in (tool_input or {}):
            args_preview[k] = tool_input.get(k)

    summary = _summarize_tool_payload(tool_name, structured_output, raw_output)
    citation: Dict[str, Any] = {
        "id": f"tool-call-{call_id}" if isinstance(call_id, int) else f"tool-{tool_name}",
        "type": "tool_output",
        "tool": tool_name or "unknown_tool",
        "status": _tool_output_status(raw_output, structured_output),
        "summary": summary,
    }
    if isinstance(call_id, int):
        citation["call_id"] = call_id
    if args_preview:
        citation["input"] = args_preview
    return citation


def _normalize_answer_citations(raw: Any, fallback: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    source_items = raw if isinstance(raw, list) else fallback

    for item in source_items:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "") or "").strip() or "unknown_tool"
        summary = _truncate_text(item.get("summary") or "", limit=180)
        if not summary:
            continue
        normalized: Dict[str, Any] = {
            "id": str(item.get("id") or f"{tool}-{len(items)+1}"),
            "type": str(item.get("type") or "tool_output"),
            "tool": tool,
            "summary": summary,
            "status": str(item.get("status") or "info"),
        }
        if isinstance(item.get("call_id"), int):
            normalized["call_id"] = int(item.get("call_id"))
        input_val = item.get("input")
        if isinstance(input_val, dict) and input_val:
            normalized["input"] = input_val
        items.append(normalized)
        if len(items) >= max(1, limit):
            break
    return items


def _build_grounding_meta(citations: List[Dict[str, Any]]) -> Dict[str, Any]:
    count = len(citations)
    return {
        "schema_version": 1,
        "supported_by_tools": count > 0,
        "citation_count": count,
        "coverage": "tool_trace" if count > 0 else "llm_only",
        "note": (
            "Answer is grounded with tool outputs."
            if count > 0
            else "No tool evidence was available for this answer."
        ),
    }

def _build_viz_from_tool_call(tool: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Build visualization hints from tool-call arguments."""
    try:
        tool = str(tool or "")
        args = args or {}

        nodes, edges, path_hint = _extract_viz_candidates(args)
        mode = "path" if ("traceroute" in tool or path_hint) else "focus"

        test_type = str(args.get("test_type", "") or "").lower()
        analysis_type = str(args.get("analysis_type", "") or "").lower()
        if test_type == "traceroute" or analysis_type.endswith("_impact"):
            mode = "path"

        if not nodes and not edges:
            return None

        raw_viz = {
            "mode": mode,
            "title": _title_for_viz(tool, args),
            "nodes": nodes,
            "edges": edges,
            "reason": _infer_viz_reason(tool, args, mode, path_hint),
            "source": "tool_call",
        }
        return _coerce_viz_contract(raw_viz, tool=tool, args=args, source="tool_call")
    except Exception:
        return None


def _build_viz_from_tool_output(tool: str, args: Dict[str, Any], payload: Any) -> Optional[Dict[str, Any]]:
    """Build visualization hints from tool outputs with broad best-effort parsing."""
    try:
        tool = str(tool or "")
        args = args or {}

        arg_nodes, arg_edges, arg_path_hint = _extract_viz_candidates(args)
        out_nodes, out_edges, out_path_hint = _extract_viz_candidates(payload)

        nodes = _dedupe_nodes(arg_nodes + out_nodes)
        edges = _dedupe_edges(arg_edges + out_edges)

        mode = "focus"
        if "traceroute" in tool or arg_path_hint or out_path_hint:
            mode = "path"

        test_type = str(args.get("test_type", "") or "").lower()
        analysis_type = str(args.get("analysis_type", "") or "").lower()
        if test_type == "traceroute" or analysis_type.endswith("_impact"):
            mode = "path"

        if mode == "path" and not edges and len(nodes) >= 2:
            edges = [{"source": nodes[i], "target": nodes[i + 1]} for i in range(len(nodes) - 1)]

        if not nodes and not edges:
            return None

        raw_viz = {
            "mode": mode,
            "title": _title_for_viz(tool, args),
            "nodes": nodes,
            "edges": edges,
            "reason": _infer_viz_reason(tool, args, mode, bool(arg_path_hint or out_path_hint)),
            "source": "tool_output",
        }
        return _coerce_viz_contract(raw_viz, tool=tool, args=args, source="tool_output")
    except Exception:
        return None


def _compose_chat_message(request: ChatRequest) -> str:
    """Compose a single prompt string with optional pinned context and attachment metadata."""
    base = str(request.message or "").strip()
    sections: List[str] = [base] if base else []

    if request.context_device:
        ctx = request.context_device
        ctx_lines = [f"- id: {ctx.id}"]
        if ctx.label:
            ctx_lines.append(f"- label: {ctx.label}")
        if ctx.platform:
            ctx_lines.append(f"- platform: {ctx.platform}")
        if ctx.device_type:
            ctx_lines.append(f"- device_type: {ctx.device_type}")
        sections.append("[Pinned Device Context]\\n" + "\\n".join(ctx_lines))

    if request.attachments:
        lines = []
        for att in request.attachments[:5]:
            size_label = f"{int(att.size / 1024)}KB" if att.size else "unknown size"
            lines.append(f"- {att.name} ({att.mime_type}, {size_label})")
        sections.append(
            "[Attached Images]\\n"
            + "\\n".join(lines)
            + "\\nUse these image references as user-provided context when answering."
        )

    return "\\n\\n".join([s for s in sections if s.strip()])


async def chat_stream_generator(request: ChatRequest, runtime):
    """SSE 스트리밍 제너레이터"""
    try:
        current_tool_name: Optional[str] = None
        current_tool_args: Dict[str, Any] = {}
        current_call_id: int = 0
        latest_viz: Optional[Dict[str, Any]] = None
        recent_citations: List[Dict[str, Any]] = []
        query_text = str(request.message or "")

        if get_auto_prepare_on_chat():
            prep = await ensure_batfish_ready(auto_init=get_auto_init_batfish())
            if prep.get("status") in ("unavailable", "not_ready"):
                data = {
                    "type": "answer",
                    "content": "Batfish is not ready. Please run lab_init_batfish (or legacy lab_manage(action=\"init_batfish\")) or enable AUTO_INIT_BATFISH.",
                    "citations": [],
                    "grounding": _build_grounding_meta([]),
                    "meta": prep,
                }
                yield f"event: answer\ndata: {json.dumps(data)}\n\n"
                yield f"event: complete\ndata: {json.dumps({'type': 'complete'})}\n\n"
                return

        composed_message = _compose_chat_message(request)
        runtime_payload = {
            "message": composed_message,
            "history": [m.model_dump() for m in request.history],
            "answer_type": request.answer_type,
        }
        async for data in runtime.astream(runtime_payload):
            data = dict(data or {})
            event_type = str(data.get("type", "message"))

            if event_type == "planning":
                data.setdefault("skills", [])
                data.setdefault("mode", "prompt_only")
                data.setdefault("tool_backend", get_tool_backend())
                data.setdefault("agent_backend", get_agent_backend())
                data.setdefault("bound_tool_count", int(getattr(app.state, "bound_tool_count", 0) or 0))

            if event_type == "tool_call":
                current_tool_name = str(data.get("tool", "") or "")
                current_tool_args = data.get("input", {}) or {}
                call_id = data.get("call_id")
                if isinstance(call_id, int):
                    current_call_id = call_id
                else:
                    current_call_id += 1
                    data["call_id"] = current_call_id
                viz = _build_viz_from_tool_call(current_tool_name, current_tool_args)
                if viz:
                    normalized_viz = _coerce_viz_contract(
                        {**viz, "query": query_text},
                        tool=current_tool_name,
                        args=current_tool_args,
                        query=query_text,
                        source="tool_call",
                        call_id=current_call_id,
                    )
                    if normalized_viz:
                        latest_viz = normalized_viz
                        data["viz"] = normalized_viz

            if event_type == "tool_output":
                raw_content = data.get("content", "")
                if not isinstance(raw_content, str):
                    raw_content = str(raw_content)
                    data["content"] = raw_content
                tool_name = str(data.get("tool", current_tool_name) or "")
                args = data.get("input", current_tool_args) or {}
                call_id = data.get("call_id")
                resolved_call_id = call_id if isinstance(call_id, int) else (current_call_id if current_call_id > 0 else None)
                structured = None
                try:
                    structured = json.loads(raw_content)
                except Exception:
                    structured = None
                viz = _build_viz_from_tool_output(
                    tool_name,
                    args,
                    structured if structured is not None else raw_content,
                )
                if viz:
                    normalized_viz = _coerce_viz_contract(
                        {**viz, "query": query_text},
                        tool=tool_name,
                        args=args,
                        query=query_text,
                        source="tool_output",
                        call_id=resolved_call_id if isinstance(resolved_call_id, int) else None,
                    )
                    if normalized_viz:
                        latest_viz = normalized_viz
                        data["viz"] = normalized_viz

                citation = _build_answer_citation(
                    call_id=resolved_call_id if isinstance(resolved_call_id, int) else None,
                    tool_name=tool_name,
                    tool_input=args if isinstance(args, dict) else {},
                    raw_output=raw_content,
                    structured_output=structured,
                )
                recent_citations = [
                    c for c in recent_citations
                    if not (
                        isinstance(c.get("call_id"), int)
                        and isinstance(citation.get("call_id"), int)
                        and int(c.get("call_id")) == int(citation.get("call_id"))
                    )
                ]
                recent_citations.append(citation)
                recent_citations = recent_citations[-8:]
                data["citation"] = citation

            if event_type == "answer":
                raw_viz = data.get("viz")
                normalized_answer_viz = _coerce_viz_contract(
                    raw_viz if isinstance(raw_viz, dict) else {},
                    tool=current_tool_name or "",
                    args=current_tool_args,
                    query=query_text,
                    source="answer",
                    call_id=current_call_id if current_call_id > 0 else None,
                ) if isinstance(raw_viz, dict) else None
                if normalized_answer_viz:
                    latest_viz = normalized_answer_viz
                    data["viz"] = normalized_answer_viz
                elif latest_viz:
                    data["viz"] = latest_viz

                citations = _normalize_answer_citations(data.get("citations"), recent_citations, limit=6)
                data["citations"] = citations
                data["grounding"] = _build_grounding_meta(citations)

            yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

        yield f"event: complete\ndata: {json.dumps({'type': 'complete'})}\n\n"

    except Exception as e:
        error_data = {"type": "error", "message": str(e)}
        yield f"event: error\ndata: {json.dumps(error_data)}\n\n"
        yield f"event: complete\ndata: {json.dumps({'type': 'complete'})}\n\n"


@app.post("/api/chat")
async def chat(request: ChatRequest):
    """SSE 스트리밍 채팅 엔드포인트"""
    async def _ensure_runtime_loaded():
        if getattr(app.state, "runtime", None) is not None:
            return app.state.runtime

        lock = getattr(app.state, "_runtime_lock", None)
        if lock is None:
            app.state._runtime_lock = asyncio.Lock()
            lock = app.state._runtime_lock

        async with lock:
            if getattr(app.state, "runtime", None) is not None:
                return app.state.runtime
            try:
                from agent.runtime import create_runtime

                runtime = create_runtime(
                    agent_backend=get_agent_backend(),
                    tool_backend=get_tool_backend(),
                    prompt_override=get_executor_prompt_override(),
                )
                app.state.runtime = runtime
                app.state.runtime_load_error = None
                app.state.bound_tool_count = int(getattr(runtime, "bound_tool_count", 0) or 0)
                # backward compatible aliases
                app.state.graph = runtime
                app.state.graph_load_error = None
                logger.info(
                    "[NetAlly] Agent runtime loaded: backend=%s tools=%s",
                    get_agent_backend(),
                    app.state.bound_tool_count,
                )
                return runtime
            except Exception as e:
                app.state.runtime = None
                app.state.runtime_load_error = str(e)
                app.state.graph = None
                app.state.graph_load_error = str(e)
                raise

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",  # nginx 버퍼링 비활성화
    }

    try:
        runtime = await _ensure_runtime_loaded()
    except Exception as e:
        raw = str(e)
        if "OPENAI_API_KEY" in raw or "api_key" in raw:
            message = (
                "LLM API 키가 설정되지 않아 채팅 기능을 사용할 수 없습니다. "
                "Settings에서 OpenAI API Key를 설정하거나 OPENAI_API_KEY 환경변수를 지정하세요."
            )
            code = "LLM_NOT_CONFIGURED"
        else:
            message = f"Agent runtime 로딩 실패: {raw}"
            code = "RUNTIME_LOAD_FAILED"

        async def error_stream():
            yield f"event: error\ndata: {json.dumps({'type': 'error', 'code': code, 'message': message})}\n\n"
            yield f"event: complete\ndata: {json.dumps({'type': 'complete'})}\n\n"

        return StreamingResponse(error_stream(), media_type="text/event-stream", headers=headers)

    return StreamingResponse(chat_stream_generator(request, runtime), media_type="text/event-stream", headers=headers)


# =============================================================================
# Topology API
# =============================================================================

@app.get("/api/topology")
async def get_topology(layer: str = "l1"):
    """
    네트워크 토폴로지 정보 반환 (NSO 또는 Batfish 기반)
    layer: "l1" (Physical/L1) 또는 "l3" (Logical/L3)
    """
    try:
        batfish = _get_batfish_client()
        
        if batfish.is_available:
            if not batfish._builder:
                batfish.load_snapshot(get_batfish_snapshot())
            
            if batfish._builder:
                return get_batfish_l3_topology(batfish, layer=layer)
        
        # Fallback to NSO (L1 fallback)
        from agent.clients.nso import NSOClient
        nso = NSOClient(
            base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf"),
            username=os.getenv("NSO_USERNAME", "admin"),
            password=os.getenv("NSO_PASSWORD", "admin")
        )
        
        devices = nso.get_devices()
        nodes = []
        for idx, dev_name in enumerate(devices):
            device_info = nso.get_device_info(dev_name) if dev_name else {}
            nodes.append(TopologyNode(
                id=dev_name or f"device-{idx}",
                type="router",  # 기본값
                data={
                    "mgmt_ip": device_info.get("address"),
                    "platform": device_info.get("platform", {}).get("name") if isinstance(device_info, dict) else None,
                    "device_type": device_info.get("device-type", {}) if isinstance(device_info, dict) else {},
                }
            ))
        
        return TopologyResponse(nodes=nodes, edges=[])
        
    except Exception as e:
        logger.error(f"Topology error: {e}")
        return TopologyResponse(nodes=[], edges=[])


@app.get("/api/topology/pnetlab")
async def get_pnetlab_topology():
    """
    PNETLab에서 실시간 토폴로지 정보 추출
    - 노드 위치 (left, top) 포함
    - Layer1 물리 연결 정보
    """
    try:
        # Prefer LabFS (UNL + /opt/unetlab/tmp) when possible to avoid web auth (cookies/XSRF/CAPTCHA).
        explicit_backend = os.getenv("PNETLAB_INVENTORY_BACKEND", "").strip().lower()
        force_labfs = bool(os.getenv("PNETLAB_LAB_PATH") or os.getenv("PNETLAB_LAB_NAME"))
        if force_labfs or explicit_backend in {"labfs_local", "labfs_ssh"} or not explicit_backend:
            from agent.pnetlab_labfs import build_pnetlab_map_from_labfs, resolve_inventory_backend

            effective = explicit_backend or resolve_inventory_backend()
            if force_labfs or effective in {"labfs_local", "labfs_ssh"}:
                topo = build_pnetlab_map_from_labfs()
                # If user explicitly forced LabFS, return the error as-is.
                if force_labfs or explicit_backend in {"labfs_local", "labfs_ssh"}:
                    return topo
                # Auto mode: if LabFS succeeded, use it; otherwise fall back to API.
                if isinstance(topo, dict) and not topo.get("error"):
                    return topo

        from agent.clients.pnetlab import PnetlabClient
        
        client = PnetlabClient(
            base_url=os.getenv("PNETLAB_URL") or os.getenv("PNETLAB_HOST", "http://100.66.240.82")
        )

        if not _pnetlab_api_auth_enabled():
            return {
                "error": (
                    "PNETLab API auth is disabled. Use LabFS mode (recommended): "
                    "set PNETLAB_INVENTORY_BACKEND=labfs_local (inside PNETLab) "
                    "or labfs_ssh + PNETLAB_SSH_HOST/PNETLAB_SSH_KEY_PATH."
                ),
                "nodes": [],
                "edges": [],
            }
        
        if not client._is_authenticated:
            return {
                "error": (
                    "PNETLab not authenticated. Recommended: use LabFS mode (cookie-less). "
                    "Set PNETLAB_INVENTORY_BACKEND=labfs_local (if running inside PNETLab) "
                    "or labfs_ssh + PNETLAB_SSH_HOST/PNETLAB_SSH_KEY_PATH, and set PNETLAB_LAB_NAME or PNETLAB_LAB_PATH."
                ),
                "nodes": [],
                "edges": [],
            }
        
        # Layer1 토폴로지 추출 (노드 위치 포함)
        l1_topo = client.get_layer1_topology()
        
        # React Flow 형식으로 변환
        nodes = []
        for n in l1_topo.get("nodes", []):
            nodes.append({
                "id": n["hostname"],
                "type": "router",
                "data": {
                    "label": n["hostname"],
                    "type": n.get("template", "router"),
                    "status": n.get("status", "unknown"),
                    "icon": n.get("icon") or "",
                },
                "position": {
                    "x": int(n.get("left", 0)),
                    "y": int(n.get("top", 0))
                }
            })
        
        edges = []
        for e in l1_topo.get("edges", []):
            n1 = e.get("node1", {})
            n2 = e.get("node2", {})
            src = n1.get("hostname", "")
            tgt = n2.get("hostname", "")
            src_iface = n1.get("interfaceName", "").replace("GigabitEthernet", "ge")
            tgt_iface = n2.get("interfaceName", "").replace("GigabitEthernet", "ge")
            
            edges.append({
                "source": src,
                "target": tgt,
                "label": f"{src_iface} ↔ {tgt_iface}"
            })
        
        logger.info(f"PNETLab topology: {len(nodes)} nodes, {len(edges)} edges")
        return {"nodes": nodes, "edges": edges}
        
    except Exception as e:
        logger.error(f"PNETLab topology error: {e}")
        return {"error": str(e), "nodes": [], "edges": []}


@app.get("/api/dashboard/summary")
async def get_dashboard_summary(mode: str = "lab"):
    """
    네트워크 건강 상태 및 주요 이슈 요약 정보 반환
    
    Args:
        mode: "lab" (실험실 모드) 또는 "production" (운영 모드)
    """
    def normalize_dashboard_summary(raw: Any, mode_value: str, offline_note: Optional[str] = None) -> Dict[str, Any]:
        default_protocol = {"total": 0, "up": 0, "down": 0, "status": "unknown"}
        data = raw if isinstance(raw, dict) else {}
        protocols = data.get("protocols")
        protocols = protocols if isinstance(protocols, dict) else {}
        bgp = protocols.get("bgp")
        ospf = protocols.get("ospf")
        bgp = bgp if isinstance(bgp, dict) else {}
        ospf = ospf if isinstance(ospf, dict) else {}
        compliance = data.get("compliance")
        compliance = compliance if isinstance(compliance, dict) else {}
        device_status = data.get("device_status")
        device_status = device_status if isinstance(device_status, dict) else {}
        issues = data.get("issues")
        issues = issues if isinstance(issues, list) else []

        if offline_note and not issues:
            issues = [{"severity": "warning", "title": "Batfish Offline", "message": offline_note}]

        return {
            "health_score": int(data.get("health_score", 0) or 0),
            "mode": str(data.get("mode", mode_value) or mode_value),
            "protocols": {
                "bgp": {
                    "total": int(bgp.get("total", default_protocol["total"]) or 0),
                    "up": int(bgp.get("up", default_protocol["up"]) or 0),
                    "down": int(bgp.get("down", default_protocol["down"]) or 0),
                    "status": str(bgp.get("status", default_protocol["status"]) or "unknown"),
                },
                "ospf": {
                    "total": int(ospf.get("total", default_protocol["total"]) or 0),
                    "up": int(ospf.get("up", default_protocol["up"]) or 0),
                    "down": int(ospf.get("down", default_protocol["down"]) or 0),
                    "status": str(ospf.get("status", default_protocol["status"]) or "unknown"),
                },
            },
            "issues": issues,
            "device_status": device_status,
            "compliance": {
                "routing": int(compliance.get("routing", 0) or 0),
                "security": int(compliance.get("security", 0) or 0),
            },
        }

    try:
        batfish = _get_batfish_client()
        
        if batfish.is_available:
            if not batfish._builder:
                batfish.load_snapshot(get_batfish_snapshot())
            
            if batfish._builder:
                return normalize_dashboard_summary(batfish.get_dashboard_data(mode=mode), mode)
        
        return normalize_dashboard_summary({}, mode, offline_note="Batfish analysis is not available.")
    except Exception as e:
        logger.error(f"Dashboard summary error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


@app.get("/api/dashboard/reachability")
async def get_reachability(src: Optional[str] = None):
    """
    장비 간 도달성 매트릭스 정보 반환
    """
    try:
        batfish = _get_batfish_client()
        
        if batfish.is_available and batfish._builder:
            return batfish.get_reachability_matrix(src_node=src)
        
        return []
    except Exception as e:
        logger.error(f"Reachability error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


@app.get("/api/dashboard/protocols/{protocol}")
async def get_protocol_details(protocol: str):
    """BGP 또는 OSPF 상세 세션 정보 반환"""
    try:
        batfish = _get_batfish_client()
        
        if batfish.is_available:
            if not batfish._builder:
                batfish.load_snapshot(get_batfish_snapshot())
            
            if protocol == "bgp":
                return batfish.get_bgp_details()
            elif protocol == "ospf":
                return batfish.get_ospf_details()
        return []
    except Exception as e:
        logger.error(f"Protocol details error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


def get_batfish_l3_topology(batfish: "BatfishClient", layer: str = "l1") -> Optional[TopologyResponse]:
    """
    Batfish에서 토폴로지 추출
    - layer: "l1" (Physical) - layer1Edges() 또는 물리 인터페이스 간 L3 연결
    - layer: "l3" (Logical) - BGP 피어링 등 포함
    """
    try:
        bf = batfish._builder.bf
        
        # 1. 노드 속성 가져오기
        node_props = bf.q.nodeProperties().answer().frame()
        nodes = []
        node_map = set()
        
        for _, row in node_props.iterrows():
            node_name = str(row.get("Node", ""))
            if not node_name or node_name in node_map:
                continue
            node_map.add(node_name)
            
            # 장비 유형 추론 고도화
            node_lower = node_name.lower()
            device_type = "router" 
            if "pe" in node_lower or "router" in node_lower:
                device_type = "router"
            elif "spine" in node_lower or "sw" in node_lower:
                device_type = "switch"
            elif "leaf" in node_lower:
                device_type = "switch"
            elif "p" in node_lower and len(node_lower) <= 3:
                device_type = "router"
            elif "host" in node_lower or "srv" in node_lower or "server" in node_lower:
                device_type = "server"
            elif "pc" in node_lower or "client" in node_lower:
                device_type = "server"
            
            nodes.append(TopologyNode(
                id=node_name,
                type="device",
                data={
                    "label": node_name,
                    "platform": str(row.get("Platform", "Network Device")),
                    "vendor": str(row.get("Vendor", "Cisco")),
                    "device_type": device_type
                }
            ))
        
        # 2. Edges 추출 (직접 연결만, 깔끔한 라벨)
        edges = []
        edge_set = set()  # 인터페이스 쌍으로 중복 제거
        
        def simplify_interface_name(iface_name: str) -> str:
            """인터페이스 이름을 짧게 변환 (GigabitEthernet0/1 -> ge0/1)"""
            iface_lower = iface_name.lower()
            if 'gigabitethernet' in iface_lower:
                return iface_name.replace('GigabitEthernet', 'ge').replace('gigabitethernet', 'ge')
            elif 'fastethernet' in iface_lower:
                return iface_name.replace('FastEthernet', 'fa').replace('fastethernet', 'fa')
            elif 'ethernet' in iface_lower:
                return iface_name.replace('Ethernet', 'eth').replace('ethernet', 'eth')
            elif 'serial' in iface_lower:
                return iface_name.replace('Serial', 's').replace('serial', 's')
            return iface_name
        
        # Layer 1 모드: 물리 인터페이스만, Layer 3 모드: 모든 연결
        if layer == "l1":
            # L1 Physical 모드: 오직 실제 물리 포트만 표시
            try:
                l3_edges = bf.q.layer3Edges().answer().frame()
                for _, row in l3_edges.iterrows():
                    src_iface = row.get("Interface")
                    dst_iface = row.get("Remote_Interface")
                    
                    src_node = getattr(src_iface, 'hostname', '') if src_iface else ''
                    src_port = getattr(src_iface, 'interface', '') if src_iface else ''
                    dst_node = getattr(dst_iface, 'hostname', '') if dst_iface else ''
                    dst_port = getattr(dst_iface, 'interface', '') if dst_iface else ''
                    
                    if not src_node or not dst_node or not src_port or not dst_port:
                        continue
                    
                    # 물리 인터페이스만 허용
                    physical_prefix = ['gigabitethernet', 'fastethernet', 'ethernet', 'serial', 'port-channel', 'tengigabitethernet']
                    virtual_prefix = ['loopback', 'vlan', 'tunnel', 'null', 'mgmt']
                    
                    src_lower = src_port.lower()
                    dst_lower = dst_port.lower()
                    
                    # 가상 인터페이스 제외
                    if any(v in src_lower for v in virtual_prefix) or any(v in dst_lower for v in virtual_prefix):
                        continue
                    
                    # 물리 인터페이스 체크
                    is_physical = any(p in src_lower for p in physical_prefix) and any(p in dst_lower for p in physical_prefix)
                    if not is_physical:
                        continue
                    
                    # 인터페이스 쌍으로 중복 체크 (양방향 동일하게 처리)
                    edge_key = tuple(sorted([f"{src_node}:{src_port}", f"{dst_node}:{dst_port}"]))
                    if edge_key not in edge_set:
                        edge_set.add(edge_key)
                        
                        # 라벨 간소화
                        src_simple = simplify_interface_name(src_port)
                        dst_simple = simplify_interface_name(dst_port)
                        
                        edges.append(TopologyEdge(
                            source=src_node,
                            target=dst_node,
                            label=f"{src_simple} ↔ {dst_simple}"
                        ))
            except Exception as e:
                logger.warning(f"L1 physical edges fetch failed: {e}")
        
        else:  # layer == "l3"
            # L3 Logical 모드: 모든 L3 연결 + BGP 피어링
            try:
                l3_edges = bf.q.layer3Edges().answer().frame()
                for _, row in l3_edges.iterrows():
                    src_iface = row.get("Interface")
                    dst_iface = row.get("Remote_Interface")
                    
                    src_node = getattr(src_iface, 'hostname', '') if src_iface else ''
                    src_port = getattr(src_iface, 'interface', '') if src_iface else ''
                    dst_node = getattr(dst_iface, 'hostname', '') if dst_iface else ''
                    dst_port = getattr(dst_iface, 'interface', '') if dst_iface else ''
                    
                    if src_node and dst_node and src_port and dst_port:
                        edge_key = tuple(sorted([f"{src_node}:{src_port}", f"{dst_node}:{dst_port}"]))
                        if edge_key not in edge_set:
                            edge_set.add(edge_key)
                            
                            src_simple = simplify_interface_name(src_port)
                            dst_simple = simplify_interface_name(dst_port)
                            
                            edges.append(TopologyEdge(
                                source=src_node,
                                target=dst_node,
                                label=f"{src_simple} ↔ {dst_simple}"
                            ))
            except Exception as e:
                logger.warning(f"L3 edges fetch failed: {e}")
            
            # BGP 피어링 추가 (L3 모드만)
            try:
                bgp_edges = bf.q.bgpEdges().answer().frame()
                for _, row in bgp_edges.iterrows():
                    src_node = str(row.get("Node", ""))
                    dst_node = str(row.get("Remote_Node", ""))
                    if src_node and dst_node:
                        edge_key = tuple(sorted([src_node, dst_node]))
                        bgp_key = f"bgp:{edge_key[0]}:{edge_key[1]}"
                        if bgp_key not in edge_set:
                            edge_set.add(bgp_key)
                            edges.append(TopologyEdge(source=src_node, target=dst_node, label="BGP"))
            except Exception as e:
                logger.warning(f"BGP edges fetch failed: {e}")
                    
        return TopologyResponse(nodes=nodes, edges=edges)
    except Exception as e:
        logger.error(f"Batfish topology extraction failed: {e}")
        return None


# =============================================================================
# Device Detail API
# =============================================================================

@app.get("/api/device/{device_id}")
async def get_device_detail(device_id: str):
    """
    장비 상세 정보 조회
    - NSO에서 설정 가져오기
    - Batfish에서 인터페이스/라우팅 정보 가져오기
    """
    try:
        from agent.clients.nso import NSOClient

        nso = NSOClient(
            base_url=os.getenv("NSO_BASE_URL", "http://localhost:8080/restconf"),
            username=os.getenv("NSO_USERNAME", "admin"),
            password=os.getenv("NSO_PASSWORD", "admin")
        )

        devices = nso.get_devices()
        resolved_device = device_id
        lower_map = {str(d).lower(): str(d) for d in devices if d}
        if device_id not in devices:
            resolved_device = lower_map.get(device_id.lower(), device_id)

        device_info = nso.get_device_info(resolved_device) if resolved_device else {}
        native_config = ""
        try:
            native_config = nso.get_native_config(resolved_device) if resolved_device else ""
        except Exception:
            native_config = ""

        nso_interfaces_raw = nso.get_interfaces(resolved_device) if resolved_device else []
        nso_interfaces: List[Dict[str, Any]] = []
        for iface in nso_interfaces_raw if isinstance(nso_interfaces_raw, list) else []:
            if not isinstance(iface, dict):
                continue
            iface_name = str(
                iface.get("name")
                or iface.get("id")
                or iface.get("interface-name")
                or iface.get("ifname")
                or ""
            )
            if not iface_name:
                continue

            status_raw = str(
                iface.get("status")
                or iface.get("admin-status")
                or iface.get("oper-status")
                or iface.get("enabled")
                or ""
            ).lower()
            status = "up" if status_raw in {"up", "true", "enabled", "connected"} else "down"

            ip = ""
            ip_data = iface.get("ip")
            if isinstance(ip_data, dict):
                addr = ip_data.get("address", {})
                if isinstance(addr, dict):
                    primary = addr.get("primary", {})
                    if isinstance(primary, dict):
                        p_addr = str(primary.get("address", "") or "")
                        p_mask = str(primary.get("mask", "") or "")
                        if p_addr:
                            ip = f"{p_addr}/{p_mask}" if p_mask else p_addr

            nso_interfaces.append(
                {
                    "name": iface_name,
                    "ip": ip,
                    "status": status,
                    "protocol": str(iface.get("protocol", "")),
                }
            )

        nso_bgp_neighbors_raw = nso.get_bgp_neighbors(resolved_device) if resolved_device else []
        nso_bgp_neighbors: List[Dict[str, Any]] = []
        for n in nso_bgp_neighbors_raw if isinstance(nso_bgp_neighbors_raw, list) else []:
            if not isinstance(n, dict):
                continue
            nso_bgp_neighbors.append(
                {
                    "peer": str(
                        n.get("id")
                        or n.get("neighbor-id")
                        or n.get("address")
                        or n.get("ip")
                        or ""
                    ),
                    "as": str(
                        n.get("remote-as")
                        or n.get("peer-as")
                        or n.get("as")
                        or "Unknown"
                    ),
                    "state": str(n.get("state") or "Configured"),
                }
            )

        batfish = _get_batfish_client()
        bf_interfaces: List[Dict[str, Any]] = []
        bf_bgp_neighbors: List[Dict[str, Any]] = []
        bf_routes: List[Dict[str, Any]] = []

        if batfish.is_available:
            if not batfish._builder:
                try:
                    batfish.load_snapshot(get_batfish_snapshot())
                except Exception:
                    pass

        if batfish.is_available and batfish._builder:
            try:
                bf = batfish._builder.bf

                iface_props = bf.q.interfaceProperties(nodes=resolved_device).answer().frame()
                for _, row in iface_props.iterrows():
                    bf_interfaces.append({
                        "name": str(row.get("Interface", "")),
                        "ip": str(row.get("Primary_Address", "")),
                        "status": "up" if row.get("Active", False) else "down",
                        "protocol": str(row.get("Routing_Protocol", "")),
                    })

                bgp_sessions = batfish.get_bgp_sessions(device_filter=resolved_device)
                for session in bgp_sessions:
                    bf_bgp_neighbors.append({
                        "peer": session.get("remote_node", ""),
                        "as": "Unknown",
                        "state": session.get("status", "Unknown"),
                    })
                bf_routes = batfish.get_route_table(resolved_device)
            except Exception as e:
                logger.warning(f"Batfish detail fetch failed for {resolved_device}: {e}")

        interfaces = bf_interfaces if bf_interfaces else nso_interfaces
        bgp_neighbors = bf_bgp_neighbors if bf_bgp_neighbors else nso_bgp_neighbors

        routes: List[Dict[str, Any]] = []
        for r in bf_routes if isinstance(bf_routes, list) else []:
            if not isinstance(r, dict):
                continue
            routes.append(
                {
                    "network": str(r.get("network", "")),
                    "nextHop": str(r.get("next_hop", "")),
                    "protocol": str(r.get("protocol", "")),
                    "metric": str(r.get("metric", "")),
                }
            )

        platform_val = None
        version_val = None
        if isinstance(device_info.get("platform"), dict):
            platform_val = device_info.get("platform", {}).get("name")
            version_val = device_info.get("platform", {}).get("version")

        if not platform_val:
            device_type_data = device_info.get("device-type")
            if isinstance(device_type_data, dict):
                cli_data = device_type_data.get("cli")
                if isinstance(cli_data, dict):
                    platform_val = cli_data.get("ned-id")

        return {
            "name": resolved_device,
            "hostname": resolved_device,
            "platform": platform_val,
            "version": version_val,
            "mgmt_ip": device_info.get("address"),
            "interfaces": interfaces,
            "bgp_neighbors": bgp_neighbors,
            "routes": routes,
            "routes_count": len(routes),
            "config": native_config or None,
            "configs": native_config or None,
            "source": {
                "device_id_requested": device_id,
                "device_id_resolved": resolved_device,
                "nso_found": bool(device_info),
                "batfish_available": bool(batfish.is_available and batfish._builder),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Device detail error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Evidence API (향후 확장)
# =============================================================================

@app.get("/api/evidence/{run_id}")
async def get_evidence(run_id: str):
    """특정 실행의 Evidence 조회"""
    # TODO: Evidence Store에서 조회
    return {"run_id": run_id, "status": "not_implemented"}


# =============================================================================
# Static Frontend (Mount Last)
# =============================================================================

# Serve the built frontend (SPA) from the Docker image when present.
# Must be mounted AFTER all /api routes; otherwise it shadows them.
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_path):
    app.mount("/", StaticFiles(directory=static_path, html=True), name="static")


# =============================================================================
# Run (개발용)
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
