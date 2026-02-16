"""Async httpx Client-Factory mit Rate-Limiting."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from webaudit.core.config import ScanConfig


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
    """HTTP-Client mit eingebautem Rate-Limiting fuer alle Scanner."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._rate_limiter = RateLimiter(config.rate_limit)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout),
            follow_redirects=True,
            verify=config.verify_ssl,
            headers={"User-Agent": config.user_agent},
        )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.get(url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.head(url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AuditHttpClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


def create_http_client(config: ScanConfig) -> AuditHttpClient:
    """Factory-Funktion fuer den HTTP-Client."""
    return AuditHttpClient(config)
