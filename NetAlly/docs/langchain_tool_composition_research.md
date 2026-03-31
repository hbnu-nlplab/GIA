# LangChain Tool Composition Research

Date: 2026-03-27

## 1. Is calling `tool.invoke()` inside another `@tool` function an anti-pattern?

**Yes, it is a known problematic pattern**, though not explicitly documented as an "anti-pattern" in official docs.

### Key findings from source code (`langchain_core/tools/base.py`):

**The `_arun` fallback mechanism**: When a tool does NOT provide an `_arun` (async) implementation, `BaseTool._arun()` falls back to running `_run` via `run_in_executor`:

```python
async def _arun(self, *args, **kwargs):
    if kwargs.get("run_manager") and signature(self._run).parameters.get("run_manager"):
        kwargs["run_manager"] = kwargs["run_manager"].get_sync()
    return await run_in_executor(None, self._run, *args, **kwargs)
```

This means: if you call `tool.ainvoke()` on a tool that only has a sync `_run`, it will be run in a thread pool executor. This is **safe** but adds overhead.

**The critical problem**: If you call `tool.invoke()` (sync) from inside an `async def` `@tool` function, you are blocking the event loop. If you call `tool.ainvoke()` inside a sync `@tool`, you hit the classic "cannot call async from sync" problem, requiring workarounds like `asyncio.run()` or thread pool executors.

### Recommended patterns:

1. **Call the underlying function directly** instead of `.invoke()`:
   ```python
   # WRONG - goes through full Runnable pipeline, callbacks, etc.
   @tool
   async def composite_tool(query: str):
       result = await other_tool.ainvoke({"query": query})  # overhead + potential issues
       return process(result)

   # BETTER - call the implementation directly
   @tool
   async def composite_tool(query: str):
       result = await other_tool_impl(query)  # direct function call
       return process(result)
   ```

2. **Use LangGraph nodes** for tool composition instead of nesting tools:
   - Each tool is a separate node in the graph
   - The graph orchestrator handles sequencing
   - This preserves callback chains and tracing

3. **If you must nest**, use `ainvoke` in async contexts and ensure the inner tool has a proper `_arun` implementation.

## 2. Known GitHub Issues

### Issue #35782 - Malformed tool calls silently dropped (Open, Mar 2026)
- **URL**: https://github.com/langchain-ai/langchain/issues/35782
- **Problem**: In `_convert_delta_to_message_chunk`, a malformed tool call (missing `function` key) causes ALL tool calls in the batch to be silently dropped.
- **Impact**: Tool results can be completely lost without any error.
- **Quote**: "One malformed tool call (missing 'function' key) causes ALL tool calls in the batch to be silently dropped"

### Issue #35514 - Streaming tool call executed with empty args (Open, Mar 2026)
- **URL**: https://github.com/langchain-ai/langchain/issues/35514
- **Problem**: SSE fragmentation causes tool calls to be executed with empty `{}` args before all argument chunks arrive.
- **Impact**: Tools receive empty/partial arguments during streaming.
- **Relevant to**: Any system using streaming + tool calling (especially with OpenRouter/non-OpenAI providers).

### Issue #35796 - StructuredTool.from_function spurious schema field (Open, Mar 2026)
- **URL**: https://github.com/langchain-ai/langchain/issues/35796
- **Problem**: `StructuredTool.from_function` injects spurious `v__args` field into JSON schema when function parameter is named `args`.

## 3. Sync/Async Tool Calling Patterns

### From `base.py` source code:

**`invoke()` path (sync)**:
```python
def invoke(self, input, config=None, **kwargs):
    tool_input, kwargs = _prep_run_args(input, config, **kwargs)
    return self.run(tool_input, **kwargs)
```

**`ainvoke()` path (async)**:
```python
async def ainvoke(self, input, config=None, **kwargs):
    tool_input, kwargs = _prep_run_args(input, config, **kwargs)
    return await self.arun(tool_input, **kwargs)
```

**Critical**: `ainvoke` calls `arun` which calls `_arun`. If `_arun` is not overridden, it runs `_run` in a thread executor. The `@tool` decorator with an `async def` function DOES set up `_arun` correctly (it uses `coroutine` as the async implementation). But `@tool` with a regular `def` function only sets `_run`, so `ainvoke` will use the thread pool fallback.

### The nested event loop problem:

```python
@tool
def sync_tool(query: str) -> str:
    # DANGER: This will fail if already in an async context
    result = asyncio.run(async_tool.ainvoke({"query": query}))
    return result
```

The NetAlly codebase already has a workaround for this (`_run_async` in `direct_tools.py`):
```python
def _run_async(coro):
    try:
        asyncio.get_running_loop()
        # Already in an event loop - use thread to avoid nested loop
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)
```

## 4. LangChain/LangGraph Official Recommendations

### From LangChain docs (Tools concept page):
- Tools are designed to be called BY agents, not by each other
- Tool composition is not a documented first-class pattern
- The `@tool` decorator creates a `StructuredTool` that wraps the function

### From LangGraph patterns:
- **Recommended**: Use graph nodes for tool orchestration
- Each tool is invoked by a `ToolNode` in the graph
- Tool results flow back through the graph state
- This avoids nested invoke issues entirely

### Best practice summary:
1. **Do NOT nest `tool.invoke()` inside `@tool` functions** - call underlying functions directly
2. **For async tools**: always provide proper async implementation (use `async def` with `@tool`)
3. **For tool composition**: use LangGraph graph nodes, not nested tool calls
4. **If mixing sync/async**: use the thread pool executor pattern (as in NetAlly's `_run_async`)
5. **Watch for streaming bugs**: Issues #35782 and #35514 can cause silent data loss

## 5. Sources

| Source | URL |
|--------|-----|
| LangChain tools/base.py source | https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/tools/base.py |
| GitHub #35782 - Silent tool call dropping | https://github.com/langchain-ai/langchain/issues/35782 |
| GitHub #35514 - Empty args from SSE fragmentation | https://github.com/langchain-ai/langchain/issues/35514 |
| GitHub #35796 - StructuredTool schema bug | https://github.com/langchain-ai/langchain/issues/35796 |
| LangChain Tools docs | https://python.langchain.com/docs/concepts/tools/ |
| LangChain BaseTool API | https://python.langchain.com/api_reference/core/tools/langchain_core.tools.base.BaseTool.html |
