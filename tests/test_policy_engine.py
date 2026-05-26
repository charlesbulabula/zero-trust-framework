import json
import time
from unittest.mock import MagicMock, patch

import pytest

from src.policy.opa_engine import OPAEngine, OPAError, PolicyDenied, TTLCache


ALLOW_RESPONSE = {"result": {"allow": True}}
DENY_RESPONSE = {"result": {"allow": False, "deny_reason": "insufficient_privilege_for_write"}}
DENY_NO_REASON = {"result": {"allow": False}}


@pytest.fixture
def mock_httpx_client():
    with patch("src.policy.opa_engine.httpx.Client") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def engine(mock_httpx_client):
    return OPAEngine(opa_url="http://opa.local:8181", cache_ttl=60)


def _make_response(body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        from httpx import HTTPStatusError, Request, Response
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp


class TestOPAEngineAllow:
    def test_allow_decision_returns_true(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(ALLOW_RESPONSE)
        result = engine.evaluate("authz", {"method": "GET", "source_spiffe_id": "spiffe://cluster.local/ns/default/sa/svc"})
        assert result is True

    def test_allow_decision_calls_correct_url(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(ALLOW_RESPONSE)
        engine.evaluate("authz", {"method": "GET"})
        call_args = mock_httpx_client.post.call_args
        assert "authz" in call_args[0][0]

    def test_deny_raises_policy_denied(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(DENY_RESPONSE)
        with pytest.raises(PolicyDenied) as exc_info:
            engine.evaluate("authz", {"method": "POST"})
        assert "insufficient_privilege_for_write" in exc_info.value.reason

    def test_policy_denied_carries_full_response(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(DENY_RESPONSE)
        with pytest.raises(PolicyDenied) as exc_info:
            engine.evaluate("authz", {"method": "DELETE"})
        assert exc_info.value.full_response == DENY_RESPONSE

    def test_deny_without_reason_uses_default_message(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(DENY_NO_REASON)
        with pytest.raises(PolicyDenied) as exc_info:
            engine.evaluate("authz", {"method": "PUT"})
        assert "denied" in exc_info.value.reason.lower()


class TestOPAEngineCache:
    def test_allow_decision_cached_on_second_call(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(ALLOW_RESPONSE)
        input_data = {"method": "GET", "path": "/api/v1/alerts"}

        engine.evaluate("authz", input_data)
        engine.evaluate("authz", input_data)

        assert mock_httpx_client.post.call_count == 1

    def test_different_inputs_not_cached_together(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(ALLOW_RESPONSE)

        engine.evaluate("authz", {"method": "GET", "path": "/a"})
        engine.evaluate("authz", {"method": "GET", "path": "/b"})

        assert mock_httpx_client.post.call_count == 2

    def test_cache_expires_after_ttl(self, mock_httpx_client):
        engine = OPAEngine(opa_url="http://opa.local:8181", cache_ttl=10)
        mock_httpx_client.post.return_value = _make_response(ALLOW_RESPONSE)
        input_data = {"method": "GET"}

        with patch("src.policy.opa_engine.time.monotonic") as mock_time:
            mock_time.return_value = 1000.0
            engine._cache._store.clear()
            engine.evaluate("authz", input_data)
            assert mock_httpx_client.post.call_count == 1

            mock_time.return_value = 1015.0
            engine.evaluate("authz", input_data)
            assert mock_httpx_client.post.call_count == 2

    def test_deny_cached_raises_policy_denied_on_second_call(self, engine, mock_httpx_client):
        mock_httpx_client.post.return_value = _make_response(DENY_RESPONSE)
        input_data = {"method": "POST", "path": "/admin"}

        with pytest.raises(PolicyDenied):
            engine.evaluate("authz", input_data)

        with pytest.raises(PolicyDenied):
            engine.evaluate("authz", input_data)

        assert mock_httpx_client.post.call_count == 1


class TestOPAEngineErrors:
    def test_missing_result_key_raises_opa_error(self, engine, mock_httpx_client):
        bad_resp = MagicMock()
        bad_resp.json.return_value = {"something_else": True}
        bad_resp.raise_for_status = MagicMock()
        mock_httpx_client.post.return_value = bad_resp

        with pytest.raises(OPAError, match="missing 'result'"):
            engine.evaluate("authz", {"method": "GET"})

    def test_non_bool_allow_raises_opa_error(self, engine, mock_httpx_client):
        bad_resp = MagicMock()
        bad_resp.json.return_value = {"result": {"allow": "yes"}}
        bad_resp.raise_for_status = MagicMock()
        mock_httpx_client.post.return_value = bad_resp

        with pytest.raises(OPAError, match="not a bool"):
            engine.evaluate("authz", {"method": "GET"})

    def test_timeout_raises_opa_error(self, engine, mock_httpx_client):
        import httpx
        mock_httpx_client.post.side_effect = httpx.TimeoutException("timed out")

        with pytest.raises(OPAError, match="timed out"):
            engine.evaluate("authz", {"method": "GET"})


class TestTTLCache:
    def test_set_and_get(self):
        cache = TTLCache(ttl=60)
        cache.set("key1", True)
        assert cache.get("key1") is True

    def test_expired_returns_none(self):
        cache = TTLCache(ttl=1)
        with patch("src.policy.opa_engine.time.monotonic") as mock_time:
            mock_time.return_value = 1000.0
            cache.set("key1", True)
            mock_time.return_value = 1002.0
            assert cache.get("key1") is None

    def test_missing_key_returns_none(self):
        cache = TTLCache(ttl=60)
        assert cache.get("nonexistent") is None

    def test_invalidate_removes_key(self):
        cache = TTLCache(ttl=60)
        cache.set("key1", True)
        cache.invalidate("key1")
        assert cache.get("key1") is None

# _r 20260526141514-91838ca5
