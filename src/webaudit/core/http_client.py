"""Async httpx Client-Factory mit Rate-Limiting, Retry und Connection Pool."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from webaudit.core.config import ScanConfig

RETRYABLE_STATUS_CODES = {429, 502, 503}
MAX_RETRIES = 2
BACKOFF_BASE = 0.5


class RateLimiter:
    """Token-Bucket Rate-Limiter."""

    def __init__(self, requests_per_second: int) -> None:
        self._rps = requests_per_second
        self._semaphore = asyncio.Semaphore(requests_per_second)
        self._interval = 1.0 / requests_per_second if requests_per_second > 0 else 0

    async def acquire(self) -> None:
        await self._semaphore.acquire()
        asyncio.get_event_loop().call_later(self._interval, self._semaphore.release)


class AuditHttpClient:
    """HTTP-Client mit eingebautem Rate-Limiting, Retry und Connection Pool."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._rate_limiter = RateLimiter(config.rate_limit)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout),
            follow_redirects=True,
            verify=config.verify_ssl,
            headers={"User-Agent": config.user_agent},
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
            ),
        )

    async def _request_with_retry(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            await self._rate_limiter.acquire()
            try:
                resp = await self._client.request(method, url, **kwargs)
                if resp.status_code in RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
                    delay = BACKOFF_BASE * (2**attempt)
                    await asyncio.sleep(delay)
                    continue
                return resp
            except httpx.TimeoutException as e:
                last_exc = e
                if attempt < MAX_RETRIES:
                    delay = BACKOFF_BASE * (2**attempt)
                    await asyncio.sleep(delay)
                    continue
                raise
            except httpx.ConnectError:
                raise
        raise last_exc  # type: ignore[misc]

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request_with_retry("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request_with_retry("HEAD", url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AuditHttpClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


def create_http_client(config: ScanConfig) -> AuditHttpClient:
    """Factory-Funktion fuer den HTTP-Client."""
    return AuditHttpClient(config)
