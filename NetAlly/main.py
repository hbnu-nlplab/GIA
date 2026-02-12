"""
NetAlly FastAPI Backend
- SSE 스트리밍 채팅 API
- 토폴로지 API
- Evidence(검증 결과) API
"""

import os
import json
import asyncio
from typing import List, Optional, Any, Dict
from contextlib import asynccontextmanager
from pathlib import Path
import re

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


class ChatRequest(BaseModel):
    """채팅 요청"""
    message: str = Field(..., description="사용자 질문")
    history: List[ChatMessage] = Field(default_factory=list, description="대화 기록")
    answer_type: str = Field(default="text", description="답변 형식: text, numeric, set, map, boolean")


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

    return {"error": res.get("error", "MCP call failed"), "tool": tool_name, "raw": res}


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
    try:
        params = {}
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
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": detail,
                        "code": "mutations_blocked",
                        "tool": tool_name,
                        "hint": _mutation_block_hint(tool_name),
                    },
                )
        else:
            from agent.tools import lab_bootstrap

            result = await asyncio.to_thread(
                lab_bootstrap.invoke,
                {"action": "refresh_onboard", "params": params}
            )
        return result
    except Exception as e:
        logger.error(f"Lab refresh error: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})


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

def _build_viz_from_tool_call(tool: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Build a small visualization hint payload from a tool call.

    This is intentionally rule-based and conservative: we only emit node/edge
    IDs that we can confidently derive from tool arguments.
    """
    try:
        tool = str(tool or "")
        args = args or {}

        nodes: List[str] = []
        edges: List[Dict[str, str]] = []
        mode: str = "focus"
        title: Optional[str] = None

        def add_node(val: Any) -> None:
            if val is None:
                return
            s = str(val).strip()
            if not s:
                return
            nodes.append(s)

        if tool in {"batfish_traceroute", "batfish_reachability"}:
            add_node(args.get("src"))
            add_node(args.get("dst"))
            title = f"{tool}: {args.get('src')} -> {args.get('dst')}"
        elif tool in {"batfish_route_table", "nso_get_device_info", "nso_get_interfaces", "nso_get_routing", "nso_get_logs"}:
            add_node(args.get("device"))
            title = f"{tool}: {args.get('device')}"
        elif tool in {"network_query"}:
            # wrapper tool: highlight the requested device if present
            add_node(args.get("device"))
            title = f"{tool}: {args.get('category')}"
        elif tool in {"network_verify"}:
            params = args.get("params") or {}
            add_node(params.get("src"))
            add_node(params.get("dst"))
            title = f"{tool}: {args.get('test_type')}"
        elif tool in {"lab_get_status"}:
            add_node(args.get("device"))
            title = f"{tool}"

        # Dedup while preserving order
        seen = set()
        nodes_out = []
        for n in nodes:
            key = n.lower()
            if key in seen:
                continue
            seen.add(key)
            nodes_out.append(n)

        if not nodes_out and not edges:
            return None

        return {
            "mode": mode,
            "title": title,
            "nodes": nodes_out,
            "edges": edges,
        }
    except Exception:
        return None


def _build_viz_from_tool_output(tool: str, args: Dict[str, Any], payload: Any) -> Optional[Dict[str, Any]]:
    """
    Build visualization hint from a tool output. Best-effort JSON parsing.
    """
    try:
        tool = str(tool or "")
        args = args or {}

        # Batfish traceroute returns {found, path:[node...], disposition}
        if tool in {"batfish_traceroute"} and isinstance(payload, dict):
            path = payload.get("path")
            if isinstance(path, list) and all(isinstance(x, (str, int)) for x in path) and len(path) >= 2:
                nodes = [str(x) for x in path]
                edges = [{"source": nodes[i], "target": nodes[i + 1]} for i in range(len(nodes) - 1)]
                return {
                    "mode": "path",
                    "title": f"traceroute: {args.get('src')} -> {args.get('dst')}",
                    "nodes": nodes,
                    "edges": edges,
                }

        # Reachability doesn't always include a path, but we can at least focus src/dst.
        if tool in {"batfish_reachability"} and isinstance(payload, dict):
            src = args.get("src")
            dst = args.get("dst")
            if src or dst:
                nodes = [str(x) for x in (src, dst) if x]
                return {
                    "mode": "focus",
                    "title": f"reachability: {src} -> {dst}",
                    "nodes": nodes,
                    "edges": [],
                }

        return None
    except Exception:
        return None


async def chat_stream_generator(request: ChatRequest, runtime):
    """SSE 스트리밍 제너레이터"""
    try:
        current_tool_name: Optional[str] = None
        current_tool_args: Dict[str, Any] = {}
        current_call_id: int = 0

        if get_auto_prepare_on_chat():
            prep = await ensure_batfish_ready(auto_init=get_auto_init_batfish())
            if prep.get("status") in ("unavailable", "not_ready"):
                data = {
                    "type": "answer",
                    "content": "Batfish is not ready. Please run lab_init_batfish (or legacy lab_manage(action=\"init_batfish\")) or enable AUTO_INIT_BATFISH.",
                    "meta": prep,
                }
                yield f"event: answer\ndata: {json.dumps(data)}\n\n"
                yield f"event: complete\ndata: {json.dumps({'type': 'complete'})}\n\n"
                return

        runtime_payload = {
            "message": request.message,
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
                    data["viz"] = viz

            if event_type == "tool_output":
                raw_content = data.get("content", "")
                if not isinstance(raw_content, str):
                    raw_content = str(raw_content)
                    data["content"] = raw_content
                tool_name = str(data.get("tool", current_tool_name) or "")
                args = data.get("input", current_tool_args) or {}
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
                    data["viz"] = viz

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
        
        # 쿠키 설정 (환경변수에서)
        cookies_str = os.getenv("PNETLAB_COOKIES", "")
        if cookies_str:
            client._load_cookies_from_string(cookies_str)
            client._is_authenticated = True
        
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
        
        # NSO에서 장비 정보
        devices = nso.get_devices()
        if device_id not in devices:
            raise HTTPException(status_code=404, detail="Device not found")
        device_info = nso.get_device_info(device_id)
        
        # Batfish에서 인터페이스 및 라우팅 정보
        batfish = _get_batfish_client()
        interfaces = []
        bgp_neighbors = []
        
        if batfish.is_available and batfish._builder:
            try:
                bf = batfish._builder.bf
                
                # 인터페이스 속성
                iface_props = bf.q.interfaceProperties(nodes=device_id).answer().frame()
                for _, row in iface_props.iterrows():
                    interfaces.append({
                        "name": str(row.get("Interface", "")),
                        "ip": str(row.get("Primary_Address", "")),
                        "status": "up" if row.get("Active", False) else "down",
                        "protocol": str(row.get("Routing_Protocol", ""))
                    })
                
                # BGP 네이버
                bgp_sessions = batfish.get_bgp_sessions(device_filter=device_id)
                for session in bgp_sessions:
                    bgp_neighbors.append({
                        "peer": session.get("remote_node", ""),
                        "as": "Unknown",  # Batfish에서 AS 번호 조회 필요 시 추가
                        "state": session.get("status", "Unknown")
                    })
            except Exception as e:
                logger.warning(f"Batfish detail fetch failed for {device_id}: {e}")
        
        return {
            "hostname": device_id,
            "platform": device_info.get("platform", {}).get("name"),
            "version": device_info.get("platform", {}).get("version"),
            "mgmt_ip": device_info.get("address"),
            "interfaces": interfaces,
            "bgp_neighbors": bgp_neighbors,
            "routes": len(batfish.get_route_table(device_id)) if batfish.is_available else 0,
            "configs": None  # 설정 내용은 별도 API로 분리 가능
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
