#!/usr/bin/env python3
"""NetAlly 채팅 API 직접 테스트 — SSE 파싱."""
import requests
import json
import sys

BASE = "http://localhost:8111"

def chat(message: str, verbose: bool = False) -> dict:
    """Send message and parse SSE response."""
    r = requests.post(
        f"{BASE}/api/chat",
        json={"message": message},
        stream=True,
        timeout=300,
    )

    tools_used = []
    answer = ""

    for line in r.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data: "):
            continue
        data_str = line[6:]  # strip "data: "
        if data_str == "[DONE]":
            break
        try:
            event = json.loads(data_str)
        except json.JSONDecodeError:
            continue

        etype = event.get("type", "")

        if etype == "tool_call":
            tool_name = event.get("name", "")
            tools_used.append(tool_name)
            if verbose:
                print(f"  [tool] {tool_name}")

        elif etype == "tool_output":
            if verbose:
                output = event.get("output", "")
                if isinstance(output, str):
                    print(f"  [result] {output[:200]}")
                else:
                    print(f"  [result] {json.dumps(output, default=str)[:200]}")

        elif etype == "answer":
            chunk = event.get("content", "")
            answer += chunk

        elif etype == "complete":
            pass

    return {
        "answer": answer.strip(),
        "tools": tools_used,
    }


def main():
    questions = [
        ("L1", "What is the system hostname on PE1? Answer in plain string."),
        ("L2", "Which devices have SSH enabled? Answer as JSON array."),
        ("L4", "What is the traceroute path from PE2 to 10.0.3.1? Answer as plain string."),
        ("L5", "Which devices are single points of failure (SPOF)? Answer as JSON array."),
    ]

    # CLI에서 특정 질문만
    if len(sys.argv) > 1:
        msg = " ".join(sys.argv[1:])
        print(f"\nQ: {msg}")
        result = chat(msg, verbose=True)
        print(f"\nA: {result['answer'][:500]}")
        print(f"Tools: {result['tools']}")
        return

    # 전체 테스트
    print(f"{'='*60}")
    print(f"  NetAlly Chat API Test")
    print(f"{'='*60}")

    for level, q in questions:
        print(f"\n[{level}] Q: {q}")
        result = chat(q, verbose=True)
        print(f"  A: {result['answer'][:300]}")
        print(f"  Tools: {result['tools']}")
        ok = len(result['tools']) > 0 and len(result['answer']) > 0
        print(f"  {'PASS' if ok else 'FAIL'}")


if __name__ == "__main__":
    main()
