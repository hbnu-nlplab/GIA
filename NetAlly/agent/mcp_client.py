"""
MCP client utilities for NetAlly.

This module provides a thin async client around MCP streamable HTTP transport.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List


class MCPClient:
    """Small MCP client wrapper with normalized response format."""

    def __init__(
        self,
        server_url: str | None = None,
        timeout_seconds: float = 20.0,
        sse_read_timeout_seconds: float = 60.0,
    ) -> None:
        self.server_url = server_url or os.getenv(
            "NETALLY_MCP_SERVER_URL",
            "http://127.0.0.1:8811/mcp",
        )
        self.timeout_seconds = timeout_seconds
        self.sse_read_timeout_seconds = sse_read_timeout_seconds

    @asynccontextmanager
    async def _session(self):
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
        except Exception as e:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "MCP dependency is missing. Install with: pip install 'mcp[cli]>=1.0.0'"
            ) from e

        async with streamable_http_client(self.server_url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session

    @staticmethod
    def _unwrap_single_result_envelope(payload: Any) -> Any:
        """Unwrap nested {'result': ...} envelopes emitted by some MCP tool runtimes."""
        while isinstance(payload, dict) and set(payload.keys()) == {"result"}:
            payload = payload["result"]
        return payload

    @staticmethod
    def _normalize_tool_result(tool_name: str, result: Any) -> Dict[str, Any]:
        content_text: List[str] = []
        for item in getattr(result, "content", []) or []:
            text = getattr(item, "text", None)
            if text is not None:
                content_text.append(text)
                continue

            data = getattr(item, "data", None)
            if data is not None:
                try:
                    content_text.append(json.dumps(data, ensure_ascii=False))
                except Exception:
                    content_text.append(str(data))
                continue

            content_text.append(str(item))

        structured = getattr(result, "structuredContent", None)
        if structured is None and len(content_text) == 1:
            try:
                structured = json.loads(content_text[0])
            except Exception:
                structured = None

        if structured is None:
            payload: Any = {"text": "\n".join(content_text)}
        else:
            payload = structured

        payload = MCPClient._unwrap_single_result_envelope(payload)
        protocol_error = bool(getattr(result, "isError", False))
        payload_error = None
        payload_code = None
        if isinstance(payload, dict):
            err = payload.get("error")
            if err is not None:
                payload_error = str(err)
            code = payload.get("code")
            if code is not None:
                payload_code = str(code)

        is_error = bool(protocol_error or payload_error)
        return {
            "ok": not is_error,
            "tool": tool_name,
            "result": payload,
            "content": content_text,
            "is_error": is_error,
            "error": payload_error,
            "code": payload_code,
        }

    async def list_tools(self) -> Dict[str, Any]:
        try:
            async with self._session() as session:
                res = await session.list_tools()
                tools = []
                for t in getattr(res, "tools", []) or []:
                    tools.append(
                        {
                            "name": getattr(t, "name", ""),
                            "description": getattr(t, "description", "") or "",
                        }
                    )
                return {"ok": True, "tools": tools}
        except Exception as e:
            return {"ok": False, "tools": [], "error": str(e)}

    async def call_tool(self, name: str, arguments: Dict[str, Any] | None = None) -> Dict[str, Any]:
        try:
            async with self._session() as session:
                res = await session.call_tool(name=name, arguments=arguments or {})
                return self._normalize_tool_result(name, res)
        except Exception as e:
            return {
                "ok": False,
                "tool": name,
                "result": {},
                "content": [],
                "is_error": True,
                "error": str(e),
                "code": "mcp_transport_error",
            }

    async def health_check(self) -> Dict[str, Any]:
        listed = await self.list_tools()
        if not listed.get("ok"):
            return {"ok": False, "error": listed.get("error", "list_tools failed")}

        tools = listed.get("tools", [])
        return {
            "ok": True,
            "server_url": self.server_url,
            "tool_count": len(tools),
            "tool_names": [t.get("name", "") for t in tools],
        }


_mcp_client: MCPClient | None = None


def get_mcp_client() -> MCPClient:
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
    return _mcp_client


def reset_mcp_client() -> None:
    global _mcp_client
    _mcp_client = None
