"""
OpenRouter API 대량 데이터셋 평가 배치 처리기
=============================================

vLLM 오프라인 배치처럼 효율적으로 OpenRouter API를 호출하는 패턴.

핵심 전략:
  - asyncio + aiohttp 로 동시 요청 (N개 Semaphore 제어)
  - Exponential backoff retry (429/502/503 대응)
  - 진행률 체크포인트 (중단 후 재개 가능)
  - 결과 JSONL 스트리밍 저장

Rate Limit 정책 (공식 문서 기준, 2025):
  - Free 모델(:free 접미): 최대 20 RPM, 50~1000 req/day
  - 유료 모델: 명시적 RPM 없음 — Cloudflare DDoS 보호가 상한선
  - 계정을 여러 개 만들어도 rate limit는 전역(global) 적용
  - 모델별로 rate limit가 다르므로 모델을 분산하면 처리량 증가 가능
  - 권장 동시 요청 수: 유료 모델 10~20, free 모델 3~5

OpenAI Batch API vs OpenRouter 비교:
  - OpenAI Batch API: 비동기 큐 방식, 24h 내 처리, 50% 할인
  - OpenRouter: 실시간 동기 API만 제공, 배치 엔드포인트 없음
  - OpenRouter는 asyncio 병렬 호출로 배치 효과를 직접 구현해야 함
"""

import asyncio
import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import aiohttp

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

@dataclass
class BatchConfig:
    model: str = "openai/gpt-4o-mini"          # 평가에 쓸 모델
    max_concurrent: int = 10                    # 동시 요청 수 (유료: 10~20 권장)
    max_retries: int = 5                        # 최대 재시도
    retry_base_delay: float = 1.0               # 첫 retry 대기(초)
    retry_max_delay: float = 60.0               # 최대 retry 대기(초)
    request_timeout: int = 120                  # 요청 타임아웃(초)
    temperature: float = 0.0                    # 평가용: 결정론적
    max_tokens: int = 512


# ---------------------------------------------------------------------------
# 데이터 구조
# ---------------------------------------------------------------------------

@dataclass
class EvalItem:
    """단일 평가 항목"""
    id: str
    question: str
    context: str = ""          # 네트워크 config 등 컨텍스트
    expected: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class EvalResult:
    """평가 결과"""
    id: str
    predicted: str
    expected: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    error: str = ""
    success: bool = True


# ---------------------------------------------------------------------------
# 핵심: 단일 요청 (retry 포함)
# ---------------------------------------------------------------------------

async def call_openrouter(
    session: aiohttp.ClientSession,
    item: EvalItem,
    config: BatchConfig,
) -> EvalResult:
    """
    단일 평가 항목에 대해 OpenRouter API 호출.
    429/502/503 에러 시 exponential backoff retry.
    """
    messages = _build_messages(item)
    payload = {
        "model": config.model,
        "messages": messages,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/GIA-NetConfigQA",  # OpenRouter 권장
        "X-Title": "NetConfigQA2.0 Evaluation",
    }

    retryable_codes = {429, 502, 503}
    delay = config.retry_base_delay

    for attempt in range(config.max_retries + 1):
        t0 = time.monotonic()
        try:
            async with session.post(
                BASE_URL,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=config.request_timeout),
            ) as resp:
                latency_ms = (time.monotonic() - t0) * 1000

                if resp.status == 200:
                    data = await resp.json()
                    return _parse_success(item, data, config.model, latency_ms)

                if resp.status in retryable_codes and attempt < config.max_retries:
                    # 429: rate limit  /  502,503: provider down
                    # Retry-After 헤더 우선 사용
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else min(delay, config.retry_max_delay)
                    print(f"[{item.id}] HTTP {resp.status} → retry {attempt+1}/{config.max_retries} after {wait:.1f}s")
                    await asyncio.sleep(wait)
                    delay *= 2  # exponential backoff
                    continue

                # 비재시도 에러 (400, 401, 402, 403, 408 등)
                error_body = await resp.text()
                return EvalResult(
                    id=item.id,
                    predicted="",
                    expected=item.expected,
                    model=config.model,
                    latency_ms=latency_ms,
                    error=f"HTTP {resp.status}: {error_body[:200]}",
                    success=False,
                )

        except asyncio.TimeoutError:
            if attempt < config.max_retries:
                wait = min(delay, config.retry_max_delay)
                print(f"[{item.id}] Timeout → retry {attempt+1}/{config.max_retries} after {wait:.1f}s")
                await asyncio.sleep(wait)
                delay *= 2
                continue
            return EvalResult(
                id=item.id, predicted="", expected=item.expected,
                model=config.model, error="Timeout after all retries", success=False,
            )
        except aiohttp.ClientError as e:
            return EvalResult(
                id=item.id, predicted="", expected=item.expected,
                model=config.model, error=f"ClientError: {e}", success=False,
            )

    return EvalResult(
        id=item.id, predicted="", expected=item.expected,
        model=config.model, error="Max retries exceeded", success=False,
    )


def _build_messages(item: EvalItem) -> list[dict]:
    """평가 프롬프트 구성"""
    system = (
        "You are a network configuration expert. "
        "Answer the question based solely on the provided configuration. "
        "Be concise and precise."
    )
    user_parts = []
    if item.context:
        user_parts.append(f"### Network Configuration\n```\n{item.context}\n```\n")
    user_parts.append(f"### Question\n{item.question}")
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(user_parts)},
    ]


def _parse_success(
    item: EvalItem, data: dict, model: str, latency_ms: float
) -> EvalResult:
    choice = data.get("choices", [{}])[0]
    predicted = choice.get("message", {}).get("content", "").strip()
    usage = data.get("usage", {})
    return EvalResult(
        id=item.id,
        predicted=predicted,
        expected=item.expected,
        model=model,
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
        latency_ms=latency_ms,
        success=True,
    )


# ---------------------------------------------------------------------------
# 배치 실행 엔진
# ---------------------------------------------------------------------------

async def run_batch(
    items: list[EvalItem],
    config: BatchConfig,
    output_path: Path,
    checkpoint_path: Path | None = None,
) -> list[EvalResult]:
    """
    Semaphore 기반 병렬 처리 + JSONL 체크포인트.

    중단 후 재개: checkpoint_path 의 완료된 ID를 skip.
    """
    # 체크포인트: 이미 완료된 항목 로드
    done_ids: set[str] = set()
    results: list[EvalResult] = []
    if checkpoint_path and checkpoint_path.exists():
        with checkpoint_path.open() as f:
            for line in f:
                r = EvalResult(**json.loads(line))
                done_ids.add(r.id)
                results.append(r)
        print(f"Checkpoint loaded: {len(done_ids)} items already done, skipping.")

    pending = [item for item in items if item.id not in done_ids]
    print(f"Pending: {len(pending)} / {len(items)} items | concurrency={config.max_concurrent}")

    semaphore = asyncio.Semaphore(config.max_concurrent)
    out_file = output_path.open("a", buffering=1)  # line-buffered

    async def bounded_call(item: EvalItem) -> EvalResult:
        async with semaphore:
            result = await call_openrouter(session, item, config)
            # 즉시 디스크에 기록 (중단 안전)
            out_file.write(json.dumps(asdict(result)) + "\n")
            status = "OK" if result.success else f"ERR:{result.error[:40]}"
            print(f"  [{result.id}] {status} | {result.latency_ms:.0f}ms")
            return result

    connector = aiohttp.TCPConnector(limit=config.max_concurrent + 5)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [bounded_call(item) for item in pending]
        new_results = await asyncio.gather(*tasks, return_exceptions=False)

    out_file.close()
    results.extend(new_results)
    return results


# ---------------------------------------------------------------------------
# 유틸리티
# ---------------------------------------------------------------------------

def load_netconfigqa_dataset(csv_path: Path) -> list[EvalItem]:
    """
    NetConfigQA2.0 CSV → EvalItem 리스트 변환.
    CSV 컬럼: id, question, answer, level, answer_type
    """
    import csv
    items = []
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            items.append(EvalItem(
                id=row["id"],
                question=row["question"],
                expected=row.get("answer", ""),
                metadata={
                    "level": row.get("level", ""),
                    "answer_type": row.get("answer_type", ""),
                },
            ))
    return items


def print_summary(results: list[EvalResult]) -> None:
    success = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    total_tokens = sum(r.prompt_tokens + r.completion_tokens for r in success)
    avg_latency = sum(r.latency_ms for r in success) / max(len(success), 1)

    print("\n" + "=" * 50)
    print(f"Total:   {len(results)}")
    print(f"Success: {len(success)}")
    print(f"Failed:  {len(failed)}")
    print(f"Tokens:  {total_tokens:,}")
    print(f"Avg latency: {avg_latency:.0f}ms")
    if failed:
        print("\nFailed items:")
        for r in failed[:5]:
            print(f"  {r.id}: {r.error}")
    print("=" * 50)


# ---------------------------------------------------------------------------
# 엔트리포인트
# ---------------------------------------------------------------------------

async def main():
    """사용 예시 — NetConfigQA2.0 평가"""
    config = BatchConfig(
        model="openai/gpt-4o-mini",
        max_concurrent=10,       # 유료 모델: 10~20 권장
        max_retries=5,
        temperature=0.0,
        max_tokens=256,
    )

    # 데이터 로드 (예시: 직접 생성)
    sample_items = [
        EvalItem(
            id=f"q{i:04d}",
            question=f"What is the hostname of the device?",
            context="hostname PE1\ninterface Loopback0\n ip address 10.0.0.1 255.255.255.255",
            expected="PE1",
        )
        for i in range(50)  # 50개 샘플
    ]

    output_path = Path("eval_results.jsonl")
    checkpoint_path = Path("eval_checkpoint.jsonl")  # 동일 파일을 체크포인트로 재사용

    results = await run_batch(
        items=sample_items,
        config=config,
        output_path=output_path,
        checkpoint_path=checkpoint_path,
    )
    print_summary(results)


if __name__ == "__main__":
    asyncio.run(main())
