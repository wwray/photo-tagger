"""A refused geocoder key stops lookups instead of failing once per photo."""
import piexif
import requests

from conftest import app_module, make_jpeg

KEY = "AIzaTestKeyNotReal123456"
DENIED = {"status": "REQUEST_DENIED",
          "error_message": "This IP, site or mobile application is not authorized to use this API key."}


class FakeProvider:
    """Stands in for requests.get; answers every call the same way."""
    def __init__(self, mode):
        self.mode, self.calls = mode, 0

    def __call__(self, url, params=None, **kw):
        self.calls += 1
        resp = requests.Response()
        resp.url = url
        if self.mode == "google_denied":
            resp.status_code, resp._content = 200, __import__("json").dumps(DENIED).encode()
            return resp
        if self.mode in ("http_403", "http_500"):
            resp.status_code = int(self.mode[-3:])
            return resp
        if self.mode == "timeout":
            raise requests.Timeout("read timed out")
        resp.status_code = 200
        resp._content = b'{"status":"OK","results":[{"address_components":[{"long_name":"Paris","types":["locality"]}]}]}'
        return resp


def _use(env, monkeypatch, provider, mode):
    env.app.set_setting("geocoder_provider", provider)
    env.app.set_setting("geocoder_api_key", KEY)
    fake = FakeProvider(mode)
    monkeypatch.setattr(app_module.requests, "get", fake)
    monkeypatch.setattr(app_module, "_geocode_throttle", lambda p: None)
    return fake


def _gps_jpeg(path, i):
    gps = {piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: ((45, 1), (i, 1), (0, 1)),
           piexif.GPSIFD.GPSLongitudeRef: b"W", piexif.GPSIFD.GPSLongitude: ((73, 1), (i, 1), (0, 1))}
    return make_jpeg(path, color=(i * 20, 10, 10), exif={"0th": {}, "Exif": {}, "GPS": gps, "1st": {}})


def test_scan_stops_geocoding_after_first_refusal(env, monkeypatch):
    for i in range(6):
        _gps_jpeg(env.root / f"g{i}.jpg", i)
    fake = _use(env, monkeypatch, "google", "google_denied")
    env.app._scan_state.update(running=True)
    env.app._run_scan(str(env.root))
    st = env.app._scan_state
    assert st["phase"] == "done", st
    assert fake.calls == 1                                    # not once per photo
    assert "refused the API key" in st["geocode_warning"]
    assert "REQUEST_DENIED" in st["geocode_warning"]
    assert KEY not in st["geocode_warning"]
    progress = env.client.get("/api/scan_progress").json
    assert progress["geocode_warning"] == st["geocode_warning"]


def test_geocode_endpoint_reports_refusal_and_stops_calling(env, monkeypatch):
    fake = _use(env, monkeypatch, "google", "google_denied")
    for _ in range(3):
        r = env.post("/api/geocode", json={"lat": 1, "lon": 2})
        assert r.json["geocoder_refused"] is True and "REQUEST_DENIED" in r.json["error"]
    assert fake.calls == 1
    r = env.client.get("/api/geocode_search", query_string={"q": "Paris"})
    assert r.status_code == 502 and r.json["geocoder_refused"] is True
    assert fake.calls == 1


def test_http_403_from_keyed_provider_also_stops(env, monkeypatch):
    fake = _use(env, monkeypatch, "locationiq", "http_403")
    env.post("/api/geocode", json={"lat": 1, "lon": 2})
    r = env.post("/api/geocode", json={"lat": 1, "lon": 2})
    assert r.json["geocoder_refused"] is True and "HTTP 403" in r.json["error"]
    assert fake.calls == 1


def test_transient_failures_do_not_stop_lookups(env, monkeypatch):
    for mode in ("http_500", "timeout"):
        fake = _use(env, monkeypatch, "locationiq", mode)
        for _ in range(3):
            r = env.post("/api/geocode", json={"lat": 1, "lon": 2})
            assert r.json["location_name"] is None and "geocoder_refused" not in r.json
        assert fake.calls == 3


def test_saving_settings_starting_a_scan_or_new_key_retries(env, monkeypatch):
    fake = _use(env, monkeypatch, "google", "google_denied")
    env.post("/api/geocode", json={"lat": 1, "lon": 2})
    assert env.app.geocoder_blocked_reason()
    env.post("/api/settings", json={"geocoder_provider": "google"})       # e.g. after fixing restrictions
    assert env.app.geocoder_blocked_reason() is None
    env.post("/api/geocode", json={"lat": 1, "lon": 2})
    assert fake.calls == 2 and env.app.geocoder_blocked_reason()
    env.post("/api/scan", json={"folder": str(env.root)})                # a new scan retries too
    assert env.app.geocoder_blocked_reason() is None
    env.app._scan_state.update(running=False)
    env.post("/api/geocode", json={"lat": 1, "lon": 2})
    env.app.set_setting("geocoder_api_key", KEY + "X")                   # different key isn't blocked
    assert env.app.geocoder_blocked_reason() is None


def test_block_expires(env, monkeypatch):
    _use(env, monkeypatch, "google", "google_denied")
    env.post("/api/geocode", json={"lat": 1, "lon": 2})
    assert env.app.geocoder_blocked_reason()
    real = app_module.time.time
    monkeypatch.setattr(app_module.time, "time", lambda: real() + app_module.GEOCODER_RETRY_SECONDS + 1)
    assert env.app.geocoder_blocked_reason() is None


def test_working_key_unaffected(env, monkeypatch):
    fake = _use(env, monkeypatch, "google", "ok")
    for _ in range(2):
        assert env.post("/api/geocode", json={"lat": 1, "lon": 2}).json["location_name"] == "Paris"
    assert fake.calls == 2 and env.app.geocoder_blocked_reason() is None
