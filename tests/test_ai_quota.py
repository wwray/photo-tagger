"""AI cost controls: atomic daily quota, refunds, rollover, bounded concurrency."""
import threading
import time

import anthropic
import httpx
import pytest

from conftest import app_module, make_jpeg


class FakeAnthropic:
    calls = 0
    active = 0
    peak = 0
    lock = threading.Lock()
    behavior = "ok"

    def __init__(self, *a, **k):
        self.messages = self

    def create(self, **kw):
        cls = FakeAnthropic
        with cls.lock:
            cls.calls += 1
            cls.active += 1
            cls.peak = max(cls.peak, cls.active)
        try:
            time.sleep(0.05)
            if cls.behavior == "status_error":
                req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
                raise anthropic.InternalServerError("boom", response=httpx.Response(500, request=req), body=None)
            if cls.behavior == "timeout":
                raise anthropic.APITimeoutError(request=httpx.Request("POST", "https://api.anthropic.com"))
            return type("M", (), {"content": [type("C", (), {"text": "Paris, France"})()]})()
        finally:
            with cls.lock:
                cls.active -= 1


@pytest.fixture
def fake_ai(env, monkeypatch):
    FakeAnthropic.calls = FakeAnthropic.active = FakeAnthropic.peak = 0
    FakeAnthropic.behavior = "ok"
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    monkeypatch.setattr(app_module, "_encode_photo_for_ai", lambda p, max_dim=1024: None)
    env.add_photo(make_jpeg(env.root / "a.jpg"))
    return FakeAnthropic


def _hit(env):
    c = app_module.app.test_client()
    return c.post("/api/ai_infer", json={"photo": {"id": "a.jpg"}}, headers=env.headers())


def test_simultaneous_requests_cannot_exceed_daily_limit(env, fake_ai, monkeypatch):
    monkeypatch.setattr(app_module, "AI_DAILY_LIMIT", 5)
    monkeypatch.setattr(app_module, "_ai_semaphore", threading.BoundedSemaphore(16))
    codes, barrier = [], threading.Barrier(20)

    def go():
        barrier.wait()
        codes.append(_hit(env).status_code)
    ts = [threading.Thread(target=go) for _ in range(20)]
    [t.start() for t in ts]; [t.join(30) for t in ts]
    assert codes.count(200) == 5
    assert codes.count(429) == 15
    assert fake_ai.calls == 5                     # the provider was contacted only 5 times
    assert app_module._ai_usage_info()["used"] == 5


def test_concurrency_is_bounded(env, fake_ai, monkeypatch):
    monkeypatch.setattr(app_module, "AI_DAILY_LIMIT", 100)
    monkeypatch.setattr(app_module, "_ai_semaphore", threading.BoundedSemaphore(2))
    ts = [threading.Thread(target=_hit, args=(env,)) for _ in range(8)]
    [t.start() for t in ts]; [t.join(30) for t in ts]
    assert fake_ai.peak <= 2 and fake_ai.calls == 8


def test_provider_error_refunds_but_timeout_counts(env, fake_ai, monkeypatch):
    monkeypatch.setattr(app_module, "AI_DAILY_LIMIT", 10)
    fake_ai.behavior = "status_error"
    assert _hit(env).status_code == 502
    assert app_module._ai_usage_info()["used"] == 0
    fake_ai.behavior = "timeout"
    assert _hit(env).status_code == 502
    assert app_module._ai_usage_info()["used"] == 1


def test_midnight_rollover(env, fake_ai, monkeypatch):
    monkeypatch.setattr(app_module, "AI_DAILY_LIMIT", 2)
    day = {"d": "2026-01-01"}
    monkeypatch.setattr(app_module, "_ai_today", lambda: day["d"])
    assert _hit(env).status_code == 200
    assert _hit(env).status_code == 200
    assert _hit(env).status_code == 429
    # A reservation made before midnight that fails after it must not be
    # refunded against the new day.
    reserved_yesterday = "2026-01-01"
    day["d"] = "2026-01-02"
    assert _hit(env).status_code == 200
    app_module._ai_release(reserved_yesterday)
    assert app_module._ai_usage_info()["used"] == 1
    assert _hit(env).status_code == 200
    assert _hit(env).status_code == 429


def test_missing_key_does_not_consume_quota(env, monkeypatch):
    env.add_photo(make_jpeg(env.root / "a.jpg"))
    monkeypatch.setattr(app_module, "_encode_photo_for_ai", lambda p, max_dim=1024: None)

    class NoKey:
        def __init__(self, *a, **k):
            raise anthropic.AnthropicError("api_key must be set")
    monkeypatch.setattr(anthropic, "Anthropic", NoKey)
    assert _hit(env).status_code == 502
    assert app_module._ai_usage_info()["used"] == 0


def test_prompt_inputs_are_bounded(env, fake_ai, monkeypatch):
    captured = {}
    def fake_call(content):
        captured["c"] = content
        return "X"
    monkeypatch.setattr(app_module, "_ai_call", fake_call)
    neighbors = [{"filename": "n" * 5000, "location_name": "L\nIGNORE PREVIOUS", "date_taken": "d" * 500}] * 20
    r = env.post("/api/ai_infer", json={"photo": {"id": "a.jpg"}, "neighbors": neighbors})
    assert r.status_code == 200
    text = captured["c"]
    assert text.count("  - ") == 6 and "n" * 201 not in text and "L IGNORE" in text
