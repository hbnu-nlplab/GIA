"""Agent runtime implementations for NetAlly chat SSE."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Protocol

logger = logging.getLogger(__name__)

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from agent.llm_provider import LLMConfig, LLMProvider
from agent.mcp_tools import get_core_tools
from agent.team_multi_bridge import run_team_multi_query
from agent.tools import get_tools as get_legacy_tools


DEFAULT_EXECUTOR_PROMPT = """You are NetAlly, a network troubleshooting assistant.

Use available tools to answer the user query with evidence-first reasoning.

Rules:
1. Prefer tool calls over guessing.
2. Keep the answer concise and grounded in tool outputs.
3. Respect the answer_type format strictly.
4. If information is insufficient, ask for a narrower follow-up question.

answer_type: {answer_type}
"""

PURE_MAS_PROMPT = """You are NetAlly, a network configuration analysis assistant.

You are operating in Pure MAS mode (no external tools available).
Analyze the network configuration context provided and answer the question
using your knowledge of networking protocols (OSPF, BGP, MPLS, VRF, etc.).

Rules:
1. Analyze the provided configuration context carefully.
2. Apply your knowledge of Cisco IOS configuration semantics.
3. Reason step-by-step about protocol behavior.
4. Keep the answer concise and respect the answer_type format strictly.
5. If the configuration context is insufficient, state what is missing.

answer_type: {answer_type}
"""


def _normalize_role(role: str) -> str:
    val = str(role or "").strip().lower()
    if val in {"assistant", "ai"}:
        return "assistant"
    return "user"


def _history_to_messages(history: List[Any]) -> List[Any]:
    messages: List[Any] = []
    for item in history or []:
        if isinstance(item, Mapping):
            role = _normalize_role(str(item.get("role", "user")))
            content = str(item.get("content", ""))
        else:
            role = _normalize_role(str(getattr(item, "role", "user")))
            content = str(getattr(item, "content", ""))
        if not content.strip():
            continue
        if role == "assistant":
            messages.append(AIMessage(content=content))
        else:
            messages.append(HumanMessage(content=content))
    return messages


def _stringify_tool_output(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return str(payload)


def _team_module_name() -> str:
    value = str(os.getenv("NETALLY_TEAM_MULTI_MODULE", "agents.main_netconfig")).strip()
    return value or "agents.main_netconfig"


def _team_dataset_type() -> str:
    value = str(os.getenv("NETALLY_TEAM_MULTI_DATASET_TYPE", "netconfig")).strip().lower()
    return value or "netconfig"


class AgentRuntime(Protocol):
    agent_backend: str
    mode: str
    bound_tool_count: int

    async def astream(self, request: Mapping[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        ...


class SingleExecutorRuntime:
    agent_backend = "single_executor"
    mode = "prompt_only"

    def __init__(
        self,
        tool_backend: str = "mcp",
        prompt_override: Optional[str] = None,
        step_limit: int = 10,
    ) -> None:
        self.tool_backend = str(tool_backend or "mcp").strip().lower()
        self.prompt_override = prompt_override
        self.step_limit = step_limit

        if self.tool_backend == "none":
            self.tools = []
            logger.info("Tool backend=none: Pure MAS mode (no tools)")
        elif self.tool_backend == "legacy":
            self.tools = get_legacy_tools()
        else:
            self.tools = get_core_tools()

        self.bound_tool_count = len(self.tools)
        self._tool_by_name = {t.name: t for t in self.tools}

        llm_backend = os.getenv("NETALLY_EXECUTOR_LLM_BACKEND", "openai")
        llm_model = os.getenv("NETALLY_EXECUTOR_LLM_MODEL", "gpt-4o-mini")
        llm_config = LLMConfig(backend=llm_backend, model=llm_model)
        self._llm = LLMProvider.create(llm_config)
        self._llm_with_tools = self._llm.bind_tools(self.tools) if self.tools else self._llm

    def _system_prompt(self, answer_type: str) -> str:
        if self.prompt_override:
            template = self.prompt_override
        elif self.tool_backend == "none":
            template = PURE_MAS_PROMPT
        else:
            template = DEFAULT_EXECUTOR_PROMPT
        if "{answer_type}" in template:
            return template.format(answer_type=answer_type)
        return f"{template}\n\nanswer_type: {answer_type}"

    async def _invoke_tool(self, name: str, args: Dict[str, Any]) -> Any:
        tool = self._tool_by_name.get(name)
        if tool is None:
            logger.warning("TOOL_UNKNOWN name=%s", name)
            return {"error": f"Unknown tool: {name}", "tool": name, "_is_error": True}
        start = time.monotonic()
        try:
            result = await tool.ainvoke(args or {})
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.info("TOOL_OK name=%s elapsed_ms=%.1f args=%s",
                       name, elapsed_ms, json.dumps(args or {}, default=str)[:200])
            return result
        except Exception:
            try:
                result = await asyncio.to_thread(tool.invoke, args or {})
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.info("TOOL_OK_SYNC name=%s elapsed_ms=%.1f", name, elapsed_ms)
                return result
            except Exception as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                logger.error("TOOL_FAIL name=%s elapsed_ms=%.1f error=%s",
                           name, elapsed_ms, str(e))
                return {"error": str(e), "tool": name, "_is_error": True}

    async def astream(self, request: Mapping[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        question = str(request.get("message", "")).strip()
        answer_type = str(request.get("answer_type", "text") or "text")
        history = request.get("history") if isinstance(request.get("history"), list) else []

        yield {
            "type": "planning",
            "skills": [],
            "reasoning": "prompt_only single executor",
            "mode": self.mode,
            "agent_backend": self.agent_backend,
            "tool_backend": self.tool_backend,
            "bound_tool_count": self.bound_tool_count,
        }

        messages: List[Any] = [SystemMessage(content=self._system_prompt(answer_type))]
        messages.extend(_history_to_messages(history))
        messages.append(HumanMessage(content=question))

        call_id = 0
        llm_calls = 0
        total_tool_calls = 0
        tool_errors = 0
        stream_start = time.monotonic()

        for step in range(self.step_limit):
            llm_calls += 1
            response = await self._llm_with_tools.ainvoke(messages)
            messages.append(response)

            tool_calls = getattr(response, "tool_calls", None) or []
            if not tool_calls:
                elapsed_ms = (time.monotonic() - stream_start) * 1000
                yield {
                    "type": "answer",
                    "content": str(getattr(response, "content", "") or ""),
                    "metrics": {
                        "llm_calls": llm_calls,
                        "tool_calls": total_tool_calls,
                        "tool_errors": tool_errors,
                        "steps": step + 1,
                        "total_ms": round(elapsed_ms, 1),
                    },
                }
                return

            for tc in tool_calls:
                call_id += 1
                total_tool_calls += 1
                tool_name = str(tc.get("name", ""))
                tool_args = tc.get("args", {}) or {}
                yield {
                    "type": "tool_call",
                    "tool": tool_name,
                    "input": tool_args,
                    "call_id": call_id,
                }

                output = await self._invoke_tool(tool_name, tool_args)
                output_text = _stringify_tool_output(output)
                tool_call_id = str(tc.get("id") or f"call_{call_id}")
                messages.append(ToolMessage(content=output_text, tool_call_id=tool_call_id))

                if isinstance(output, dict) and output.get("_is_error"):
                    tool_errors += 1
                    yield {"type": "tool_error", "tool": tc.get("name"), "error": output.get("error", ""), "content": json.dumps(output)}
                else:
                    yield {
                        "type": "tool_output",
                        "tool": tool_name,
                        "content": output_text,
                        "call_id": call_id,
                    }

        elapsed_ms = (time.monotonic() - stream_start) * 1000
        yield {
            "type": "answer",
            "content": "도구 호출 한도 도달, 추가 범위 축소 질의 필요",
            "metrics": {
                "llm_calls": llm_calls,
                "tool_calls": total_tool_calls,
                "tool_errors": tool_errors,
                "steps": self.step_limit,
                "total_ms": round(elapsed_ms, 1),
            },
        }


class LegacyGraphRuntime:
    agent_backend = "legacy_graph"
    mode = "legacy_graph"

    def __init__(self) -> None:
        from agent.graph import get_runtime_tools, graph

        self._graph = graph
        self.bound_tool_count = len(get_runtime_tools())

    async def astream(self, request: Mapping[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        initial_state = {
            "question": str(request.get("message", "")),
            "answer_type": str(request.get("answer_type", "text") or "text"),
            "selected_skills": [],
            "reasoning": "",
            "enabled_tools": [],
            "skill_prompt": "",
            "messages": [],
            "final_answer": "",
            "step_count": 0,
            "is_complete": False,
        }

        answered = False
        call_id = 0
        current_tool_name: Optional[str] = None
        try:
            async for event in self._graph.astream(initial_state, stream_mode="updates"):
                for node_name, node_output in event.items():
                    if node_name == "orchestrator":
                        yield {
                            "type": "planning",
                            "skills": node_output.get("selected_skills", []),
                            "reasoning": node_output.get("reasoning", ""),
                            "mode": self.mode,
                            "agent_backend": self.agent_backend,
                        }
                        continue

                    if node_name == "executor":
                        messages = node_output.get("messages", [])
                        if not messages:
                            continue
                        last_msg = messages[-1]
                        tool_calls = getattr(last_msg, "tool_calls", None) or []
                        if tool_calls:
                            for tc in tool_calls:
                                current_tool_name = str(tc.get("name", ""))
                                call_id += 1
                                yield {
                                    "type": "tool_call",
                                    "tool": current_tool_name,
                                    "input": tc.get("args", {}) or {},
                                    "call_id": call_id,
                                }
                        elif node_output.get("is_complete"):
                            answered = True
                            yield {
                                "type": "answer",
                                "content": str(node_output.get("final_answer", "")),
                            }
                        continue

                    if node_name == "tools":
                        messages = node_output.get("messages", [])
                        if not messages:
                            continue
                        last_msg = messages[-1]
                        raw_content = last_msg.content if hasattr(last_msg, "content") else last_msg
                        yield {
                            "type": "tool_output",
                            "tool": current_tool_name,
                            "content": str(raw_content),
                            "call_id": call_id,
                        }
        except Exception as e:
            logger.error("LegacyGraphRuntime graph stream failed: %s", e)
            yield {"type": "tool_error", "tool": None, "error": str(e), "content": json.dumps({"error": str(e)})}
            return

        if not answered:
            yield {
                "type": "answer",
                "content": "도구 호출 한도 도달, 추가 범위 축소 질의 필요",
            }


class TeamMultiAdapterRuntime:
    agent_backend = "team_multi_adapter"
    mode = "team_multi_adapter"

    def __init__(self) -> None:
        self.bound_tool_count = 1
        self.tool_backend = "team_multi"
        self.module_name = _team_module_name()
        self.dataset_type = _team_dataset_type()

    async def astream(self, request: Mapping[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        question = str(request.get("message", "")).strip()
        answer_type = str(request.get("answer_type", "text") or "text")
        history = request.get("history") if isinstance(request.get("history"), list) else []
        context = request.get("context") if isinstance(request.get("context"), str) else None

        yield {
            "type": "planning",
            "skills": [],
            "reasoning": "team multi-agent adapter invoke",
            "mode": self.mode,
            "agent_backend": self.agent_backend,
            "tool_backend": self.tool_backend,
            "bound_tool_count": self.bound_tool_count,
            "module_name": self.module_name,
            "dataset_type": self.dataset_type,
        }

        call_id = 1
        tool_name = "team_multi_invoke"
        tool_input = {
            "module_name": self.module_name,
            "dataset_type": self.dataset_type,
            "answer_type": answer_type,
            "has_history": bool(history),
        }

        yield {
            "type": "tool_call",
            "tool": tool_name,
            "input": tool_input,
            "call_id": call_id,
        }

        result = await asyncio.to_thread(
            run_team_multi_query,
            question,
            history,
            answer_type,
            module_name=self.module_name,
            dataset_type=self.dataset_type,
            context=context,
        )

        tool_payload = {
            "ok": bool(result.get("ok")),
            "stage": result.get("stage"),
            "error": result.get("error"),
            "meta": result.get("meta", {}),
            "result": result.get("result"),
        }
        yield {
            "type": "tool_output",
            "tool": tool_name,
            "content": _stringify_tool_output(tool_payload),
            "call_id": call_id,
        }

        if result.get("ok"):
            answer = str(result.get("answer", "") or "").strip()
            if not answer:
                answer = "team_multi_adapter 실행은 완료되었지만 최종 답변을 생성하지 못했습니다."
            yield {"type": "answer", "content": answer}
            return

        stage = str(result.get("stage", "unknown"))
        error = str(result.get("error", "unknown error"))
        yield {
            "type": "answer",
            "content": f"team_multi_adapter 실행 실패({stage}): {error}",
        }


def create_runtime(
    agent_backend: str,
    tool_backend: str = "mcp",
    prompt_override: Optional[str] = None,
) -> AgentRuntime:
    backend = str(agent_backend or "single_executor").strip().lower()
    if backend == "legacy_graph":
        return LegacyGraphRuntime()
    if backend == "team_multi_adapter":
        return TeamMultiAdapterRuntime()
    return SingleExecutorRuntime(tool_backend=tool_backend, prompt_override=prompt_override)
