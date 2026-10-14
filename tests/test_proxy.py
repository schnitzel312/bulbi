"""Tests for the allowlist proxy."""

import json
import urllib.request
from pathlib import Path

import pytest

from bulbi.proxy import AllowlistProxy, get_denied_requests


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / ".bulbi" / "proxy.log"


@pytest.fixture
def proxy(log_path: Path) -> AllowlistProxy:
    p = AllowlistProxy(
        allowed_domains=["httpbin.org", "example.com"],
        secrets={},
        log_path=log_path,
    )
    yield p
    p.stop()


def test_proxy_starts_and_stops(proxy: AllowlistProxy):
    port = proxy.start()
    assert port > 0
    proxy.stop()


def test_proxy_denies_unlisted_domain(proxy: AllowlistProxy, log_path: Path):
    port = proxy.start()

    # Try to reach a domain not in the allowlist via HTTP
    req = urllib.request.Request("http://evil.example.com/")
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
    opener = urllib.request.build_opener(handler)

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        opener.open(req, timeout=5)
    assert exc_info.value.code == 403

    # Check the log
    denied = get_denied_requests(log_path)
    assert len(denied) >= 1
    assert denied[0]["domain"] == "evil.example.com"
    assert denied[0]["action"] == "deny"


def test_proxy_log_format(proxy: AllowlistProxy, log_path: Path):
    port = proxy.start()

    # Make a request that will be denied
    req = urllib.request.Request("http://blocked.test/foo")
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
    opener = urllib.request.build_opener(handler)

    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass

    assert log_path.exists()
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) >= 1

    entry = json.loads(lines[0])
    assert "timestamp" in entry
    assert "domain" in entry
    assert "action" in entry
    assert "method" in entry
