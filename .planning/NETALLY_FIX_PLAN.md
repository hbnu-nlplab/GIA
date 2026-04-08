# NetAlly 코드 수정 계획

**작성일:** 2026-03-18
**근거:** 8개 병렬 에이전트 코드 리뷰 결과 (CRITICAL 10개, HIGH 16개, MEDIUM 11개)
**목표:** NetAlly가 도구 호출 실패 시 명확한 에러를 반환하고, 안정적으로 동작하도록 수정

---

## Phase 0: 즉시 조치 (보안) — 5분

> 코드 수정 아님. git/설정 변경만.

- [ ] **SEC-01**: `.env.tailscale` git tracking 제거
  ```bash
  git rm --cached NetAlly/.env.tailscale
  echo "NetAlly/.env.tailscale" >> NetAlly/.gitignore
  ```
- [x] **SEC-02**: `NETALLY_MCP_ALLOW_MUTATIONS=false` 설정 (완료)
- [x] **SEC-03**: `PNETLAB_DEVICE_INFO_AUTOGEN=false` 설정 (완료)

---

## Phase 1: Tool 에러 전파 수정 — 핵심 문제

> **근본 원인:** tool 에러가 `{"error":...}` dict로 반환되어 LLM이 "데이터"로 오해.
> 이 Phase만 수정해도 "동작 안 함" 문제의 80% 해결.

### Task 1.1: `runtime.py` — tool 에러를 SSE error 이벤트로 분리
**파일:** `NetAlly/agent/runtime.py:119-130`
**현재:**
```python
except Exception as e:
    return {"error": str(e), "tool": name}  # 에러가 tool_output으로 전달
```
**수정:**
```python
except Exception as e:
    logger.error("Tool %s failed: %s", name, e)
    return {"error": str(e), "tool": name, "_is_error": True}
```

**파일:** `NetAlly/agent/runtime.py:164-175` (astream 루프 내 tool_output 부분)
**추가:** tool_output에 `_is_error` 플래그 확인 → `type: "tool_error"` 이벤트로 분리
```python
if isinstance(output, dict) and output.get("_is_error"):
    yield {"type": "tool_error", "tool": tc.get("name"), "error": output.get("error", "")}
else:
    yield {"type": "tool_output", ...}
```

### Task 1.2: `batfish.py` — bare except 제거
**파일:** `NetAlly/agent/clients/batfish.py:511`
**현재:** `except: pass` → `return "0.0.0.0"`
**수정:** `except Exception as e: logger.warning("get_node_ip(%s) failed: %s", node, e)`

### Task 1.3: `graph.py` — orchestrator bare except 수정
**파일:** `NetAlly/agent/graph.py:105-107`
**현재:** `except:` → defaults to `["core"]` 무조건
**수정:** `except (json.JSONDecodeError, KeyError, ValueError) as e:` + `logger.warning`

### Task 1.4: `main.py` — SSE error 이벤트에 에러 코드 추가
**파일:** `NetAlly/main.py:2039-2042`
**현재:** `{"type": "error", "message": str(e)}`
**수정:**
```python
error_code = "LLM_ERROR" if "api" in str(e).lower() else "RUNTIME_ERROR"
error_data = {"type": "error", "code": error_code, "message": str(e)[:200]}
```

---

## Phase 2: 앱 시작 안정성 — 크래시 방지

### Task 2.1: `graph.py` — module-level LLM 생성 → lazy init
**파일:** `NetAlly/agent/graph.py:294-299`
**현재:** `graph = create_orchestrated_graph(...)` — import 시 즉시 실행
**수정:** factory 함수로 감싸고, 호출 시점에 생성 (cached property 패턴)
```python
_graph = None
def get_graph():
    global _graph
    if _graph is None:
        _graph = create_orchestrated_graph(...)
    return _graph
```

### Task 2.2: `runtime.py` — sync invoke → ainvoke 전환
**파일:** `NetAlly/agent/runtime.py:153`
**현재:** `await asyncio.to_thread(self._llm_with_tools.invoke, messages)`
**수정:** `await self._llm_with_tools.ainvoke(messages)`

### Task 2.3: `runtime.py` — LegacyGraph에 try-except 추가
**파일:** `NetAlly/agent/runtime.py:217`
**현재:** `async for event in self._graph.astream(state)` — 예외 시 SSE 끊김
**수정:** try-except로 감싸고 error 이벤트 yield

---

## Phase 3: 프론트엔드 에러 표시 — UX

### Task 3.1: `ChatPanel.tsx` — tool_error 이벤트 처리
**파일:** `NetAlly/frontend/src/components/ChatPanel.tsx:531-612`
**추가:** `tool_error` 이벤트 타입 핸들러 — 빨간색 에러 박스로 표시
```javascript
if (resolvedType === 'tool_error') {
    pushSystemMessage(`Tool failed: ${data.tool} — ${data.error}`, 'error')
}
```

### Task 3.2: 채팅 시작 전 health check 자동 호출
**파일:** `NetAlly/frontend/src/components/ChatPanel.tsx`
**추가:** 첫 메시지 전송 전 `/api/runtime/health` 호출 → 서비스 상태 표시
- Batfish ✓/✗, NSO ✓/✗, PNETLab ✓/✗

---

## Phase 4: CORS/보안 — 외부 노출 전 필수

### Task 4.1: `main.py` — CORS origin 제한
**파일:** `NetAlly/main.py:410-416`
**현재:** `allow_origins=["*"]`
**수정:** `allow_origins=["http://localhost:3000", "http://localhost:8111"]`

### Task 4.2: `main.py` — runtime settings에서 비밀번호 마스킹
**파일:** `NetAlly/main.py:96-102`
**수정:** GET `/api/settings` 응답에서 `*_PASSWORD`, `*_KEY` 필드 마스킹

### Task 4.3: `mcp_server.py` — MCP tool input validation 추가
**파일:** `NetAlly/agent/mcp_server.py:80-130`
**수정:** `device`, `src`, `dst` 파라미터에 패턴 검증 추가
```python
if not re.match(r'^[\w.\-]+$', device):
    return {"error": f"Invalid device name: {device}"}
```

---

## Phase 5: Deprecation 정리 — 코드 품질

### Task 5.1: `onboarding.py` — deprecation 경고 추가
- `scan_and_sync()` 상단에 `logger.warning("DEPRECATED: use deploy scripts instead")`
- `asyncio.run()` in async 문제 → 호출되면 명시적 에러 반환

### Task 5.2: dead code 정리
- `pnetlab.py:945` — `login()` 반환값 체크 수정
- `onboarding.py:891` — `gs.pnetlab_vm_ip` mutation → `dataclasses.replace` 사용
- `graph.py:96-97` — function body 내 import → top-level로 이동

---

## 실행 순서 및 예상 시간

| Phase | 예상 시간 | 의존성 | 효과 |
|-------|----------|--------|------|
| **0** | 5분 | 없음 | 보안 즉시 개선 |
| **1** | 30분 | 없음 | **"동작 안 함" 80% 해결** |
| **2** | 20분 | Phase 1 | 앱 시작 안정성 |
| **3** | 15분 | Phase 1 | 사용자 에러 확인 가능 |
| **4** | 15분 | 없음 | 보안 강화 |
| **5** | 10분 | 없음 | 코드 품질 |

**총 예상: ~1.5시간**
**Phase 0+1만 하면 즉시 개선 체감 가능**

---

## 검증 방법

각 Phase 완료 후:
```bash
cd NetAlly && uv run pytest -q tests                    # 백엔드 테스트
cd NetAlly && uv run pytest tests/test_chat_sse_contract.py  # SSE 계약 테스트
```

Phase 1 완료 후 수동 검증:
1. Batfish 미실행 상태에서 채팅 → `tool_error` 이벤트 수신 확인
2. NSO 미연결 상태에서 채팅 → 명확한 에러 메시지 확인
3. 정상 상태에서 채팅 → 기존과 동일하게 동작 확인

---
*8개 병렬 에이전트 리뷰 결과 기반 — 2026-03-18*
