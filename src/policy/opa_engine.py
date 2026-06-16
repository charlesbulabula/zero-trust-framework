import hashlib
import json
import logging
import time
from typing import Any, Dict, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)


class OPAError(Exception):
    pass


class PolicyDenied(Exception):
    def __init__(self, reason: str, full_response: dict):
        super().__init__(reason)
        self.reason = reason
        self.full_response = full_response


class TTLCache:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._store: Dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any):
        self._store[key] = (value, time.monotonic() + self.ttl)

    def invalidate(self, key: str):
        self._store.pop(key, None)

    def clear(self):
        self._store.clear()

    def __len__(self):
        now = time.monotonic()
        return sum(1 for _, (_, exp) in self._store.items() if exp > now)


class OPAEngine:
    def __init__(
        self,
        opa_url: str,
        cache_ttl: int = 60,
        timeout: float = 5.0,
        verify_ssl: bool = True,
    ):
        self.opa_url = opa_url.rstrip("/")
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self._cache = TTLCache(ttl=cache_ttl)
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            headers={"Content-Type": "application/json"},
        )
        logger.info("OPAEngine initialized: url=%s cache_ttl=%ds", opa_url, cache_ttl)

    def _make_cache_key(self, package: str, input_data: dict) -> str:
        serialized = package + json.dumps(input_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def evaluate(self, package: str, input_data: dict) -> bool:
        cache_key = self._make_cache_key(package, input_data)
        cached = self._cache.get(cache_key)
        if cached is not None:
            logger.debug("OPA cache hit: package=%s key=%s result=%s", package, cache_key[:16], cached)
            if cached is False:
                raise PolicyDenied(
                    reason=f"Policy denied (cached): package={package}",
                    full_response={"cached": True, "allow": False},
                )
            return True

        url = f"{self.opa_url}/v1/data/{package.replace('.', '/')}"
        payload = {"input": input_data}

        try:
            resp = self._client.post(url, json=payload)
            resp.raise_for_status()
        except httpx.TimeoutException as exc:
            raise OPAError(f"OPA request timed out: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise OPAError(
                f"OPA returned HTTP {exc.response.status_code}: {exc.response.text[:500]}"
            ) from exc
        except httpx.RequestError as exc:
            raise OPAError(f"OPA connection error: {exc}") from exc

        try:
            body = resp.json()
        except json.JSONDecodeError as exc:
            raise OPAError(f"OPA returned invalid JSON: {exc}") from exc

        if "result" not in body:
            raise OPAError(f"OPA response missing 'result' field: {body}")

        result = body["result"]
        if not isinstance(result, dict):
            raise OPAError(f"OPA result is not a dict: {result!r}")

        allowed = result.get("allow", False)

        if not isinstance(allowed, bool):
            raise OPAError(f"OPA 'allow' field is not a bool: {allowed!r}")

        self._cache.set(cache_key, allowed)

        logger.info(
            "OPA decision: package=%s allow=%s input_keys=%s",
            package,
            allowed,
            list(input_data.keys()),
        )

        if not allowed:
            deny_reason = result.get("deny_reason") or f"Policy denied: package={package}"
            raise PolicyDenied(reason=deny_reason, full_response=body)

        return True

    def check_health(self) -> bool:
        try:
            resp = self._client.get(f"{self.opa_url}/health")
            return resp.status_code == 200
        except Exception as exc:
            logger.warning("OPA health check failed: %s", exc)
            return False

    def invalidate_cache(self, package: Optional[str] = None, input_data: Optional[dict] = None):
        if package and input_data:
            key = self._make_cache_key(package, input_data)
            self._cache.invalidate(key)
        else:
            self._cache.clear()
            logger.info("OPA cache cleared")

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

# _r 20260616155413-832e09f0
