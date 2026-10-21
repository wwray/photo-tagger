"""Geocoder/AI credentials never reach logs, the log viewer or API responses."""
import io
import sys

import requests

from conftest import app_module

KEY = "liq_SuperSecretKey_987654321"


def _http_error(url, status=401):
    resp = requests.Response()
    resp.status_code = status
    resp.reason = "Unauthorized"
    resp.url = url
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        return e
    raise AssertionError("expected an HTTPError")


def _capture(monkeypatch):
    """Route stdout through a fresh tee (as the app does at import) and
    clear the in-app log buffer."""
    sink = io.StringIO()
    monkeypatch.setattr(sys, "stdout", app_module._TeeStream(sink, "out"))
    with app_module._log_buffer_lock:
        app_module._log_buffer.clear()
    return sink


def test_provider_error_with_key_in_url_is_redacted(env, monkeypatch):
    sink = _capture(monkeypatch)
    env.app.set_setting("geocoder_provider", "locationiq")
    env.app.set_setting("geocoder_api_key", KEY)

    def fake_get(url, params=None, **kw):
        q = "&".join(f"{k}={v}" for k, v in (params or {}).items())
        raise _http_error(f"{url}?{q}")
    monkeypatch.setattr(app_module.requests, "get", fake_get)
    monkeypatch.setattr(app_module, "_geocode_throttle", lambda p: None)

    r = env.post("/api/geocode", json={"lat": 1.5, "lon": 2.5})
    assert r.status_code == 200 and r.json["location_name"] is None
    r2 = env.client.get("/api/geocode_search", query_string={"q": "Paris"})
    assert r2.status_code == 502
    for resp in (r, r2):
        assert KEY not in resp.get_data(as_text=True)

    logged = sink.getvalue()
    assert "locationiq" in logged and "HTTP 401" in logged          # still diagnosable
    assert KEY not in logged
    viewer = env.client.get("/api/logs").get_data(as_text=True)
    assert "HTTP 401" in viewer and KEY not in viewer


def test_redaction_covers_tracebacks_and_known_secret_values(env, monkeypatch):
    sink = _capture(monkeypatch)
    app_module._register_secret(KEY)
    try:
        raise RuntimeError(f"failed calling https://api.mapbox.com/geocoding/v5/{KEY}.json")
    except RuntimeError:
        import traceback
        traceback.print_exc(file=sys.stdout)
    print(f"x-api-key: sk-ant-api03-abcdefghijklmnop and access_token={KEY}&z=1")
    out = sink.getvalue()
    assert KEY not in out and "sk-ant-api03" not in out
    assert "[REDACTED]" in out


def test_settings_never_return_the_key(env):
    r = env.post("/api/settings", json={"geocoder_provider": "opencage", "geocoder_api_key": KEY})
    assert r.status_code == 200 and r.json["has_geocoder_key"] is True
    for resp in (r, env.client.get("/api/settings"), env.client.get("/api/config")):
        assert KEY not in resp.get_data(as_text=True)
    # Logged as "updated", never echoed.
    assert all(KEY not in l["line"] for l in env.client.get("/api/logs").json["lines"])


def test_ai_provider_error_is_sanitized(env, monkeypatch):
    from conftest import make_jpeg
    a = make_jpeg(env.root / "a.jpg"); env.add_photo(a)

    def boom(content):
        raise RuntimeError("upstream said: invalid x-api-key: sk-ant-api03-SHOULDNOTLEAK123")
    monkeypatch.setattr(app_module, "_ai_call", boom)
    monkeypatch.setattr(app_module, "_encode_photo_for_ai", lambda p, max_dim=1024: None)
    r = env.post("/api/ai_infer", json={"photo": {"id": "a.jpg"}})
    assert r.status_code == 502
    assert "SHOULDNOTLEAK" not in r.get_data(as_text=True)
