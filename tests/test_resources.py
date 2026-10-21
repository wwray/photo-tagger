"""Upload limits/cleanup, concurrent import reservation, thumbnail cache bounds."""
import io
import os
import threading
import time

from conftest import app_module, make_jpeg


def _upload(env, name="Records.json", data=b'{"locations": []}'):
    return env.client.post("/api/history/import", data={"file": (io.BytesIO(data), name)},
                           headers=env.headers(), content_type="multipart/form-data")


def _wait_import_idle(env):
    deadline = time.time() + 10
    while env.app._hist_import_state["running"] and time.time() < deadline:
        time.sleep(0.05)


def _tmp_files(env):
    d = env.app.UPLOAD_TMP_DIR
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def test_successful_upload_is_imported_and_cleaned_up(env):
    payload = b'{"locations": [{"latitudeE7": 450000000, "longitudeE7": -730000000, "timestamp": "2024-01-01T00:00:00Z"}]}'
    r = _upload(env, data=payload + b" " * 600_000)  # big enough that Werkzeug spools to disk
    assert r.status_code == 200, r.json
    _wait_import_idle(env)
    assert env.app._hist_import_state["phase"] == "done"
    assert _tmp_files(env) == []


def test_rejected_upload_leaves_nothing_behind(env):
    r = _upload(env, name="evil.exe", data=b"MZ" + b"\0" * 700_000)
    assert r.status_code == 400
    assert _tmp_files(env) == []
    assert env.app._hist_import_state["running"] is False


def test_oversized_upload_rejected_and_slot_released(env, monkeypatch):
    monkeypatch.setitem(app_module.app.config, "MAX_CONTENT_LENGTH", 100_000)
    r = _upload(env, data=b"x" * 300_000)
    assert r.status_code == 413
    assert _tmp_files(env) == []
    assert env.app._hist_import_state["running"] is False


def test_failed_import_job_cleans_up_upload(env):
    r = _upload(env, data=b'{"locations": [ this is not json')
    assert r.status_code == 200
    _wait_import_idle(env)
    assert env.app._hist_import_state["phase"] == "error"
    assert _tmp_files(env) == []


def test_concurrent_imports_reserve_atomically(env, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    real_prepare = app_module._prepare_history_source

    def slow_prepare():
        entered.set()
        release.wait(5)
        return real_prepare()
    monkeypatch.setattr(app_module, "_prepare_history_source", slow_prepare)
    results = {}
    t = threading.Thread(target=lambda: results.setdefault("first", _upload(env)))
    t.start()
    assert entered.wait(5)
    second = _upload(env)  # first is still receiving its body
    assert second.status_code == 409
    release.set(); t.join(5)
    assert results["first"].status_code == 200
    _wait_import_idle(env)


def test_upload_temp_names_are_unique(env, monkeypatch):
    seen = []
    monkeypatch.setattr(app_module, "_run_history_import",
                        lambda import_id, filepath, ext, cleanup_path=None: seen.append(filepath))
    for _ in range(2):
        assert _upload(env).status_code == 200
        with app_module._hist_import_lock:
            app_module._hist_import_state["running"] = False
    assert len(seen) == 2 and seen[0] != seen[1]
    for f in seen:
        os.unlink(f)


def test_stale_spools_removed_at_startup(env):
    env.app.UPLOAD_TMP_DIR.mkdir(parents=True, exist_ok=True)
    (env.app.UPLOAD_TMP_DIR / "spool_abc.part").write_bytes(b"x")
    (env.app.UPLOAD_TMP_DIR / "upload_123.json").write_bytes(b"x")
    env.app._clear_stale_upload_spools()
    assert _tmp_files(env) == []


def test_thumbnail_cache_is_bounded(env, monkeypatch):
    monkeypatch.setattr(app_module, "THUMB_CACHE_MAX_MB", 1)
    cache = env.app.THUMB_CACHE_DIR; cache.mkdir(parents=True)
    now = time.time()
    for i in range(6):  # 6 x 300KB = 1.8MB > 1MB
        p = cache / f"{i:02d}.jpg"; p.write_bytes(b"\0" * 300_000)
        os.utime(p, (now - 100 + i, now - 100 + i))
    (cache / "old.tmp").write_bytes(b"x"); os.utime(cache / "old.tmp", (now - 7200, now - 7200))
    app_module.evict_thumb_cache()
    remaining = sorted(p.name for p in cache.iterdir())
    total = sum(p.stat().st_size for p in cache.iterdir())
    assert total <= 0.8 * 1024 * 1024
    assert remaining == ["04.jpg", "05.jpg"]  # newest kept, oldest + orphaned temp gone


def test_thumbnail_generation_concurrency_is_bounded(env, monkeypatch):
    for i in range(6):
        env.add_photo(make_jpeg(env.root / f"t{i}.jpg", color=(i * 40, 0, 0)))
    monkeypatch.setattr(app_module, "_thumb_semaphore", threading.BoundedSemaphore(2))
    active, peak, lock = [0], [0], threading.Lock()
    real_open = app_module.Image.open

    def slow_open(*a, **k):
        with lock:
            active[0] += 1; peak[0] = max(peak[0], active[0])
        time.sleep(0.1)
        with lock:
            active[0] -= 1
        return real_open(*a, **k)
    monkeypatch.setattr(app_module.Image, "open", slow_open)
    codes = []
    def get(i):
        c = app_module.app.test_client()
        codes.append(c.get("/api/thumbnail", query_string={"id": f"t{i}.jpg", "size": 160}).status_code)
    ts = [threading.Thread(target=get, args=(i,)) for i in range(6)]
    [t.start() for t in ts]; [t.join(10) for t in ts]
    assert codes == [200] * 6
    assert peak[0] <= 2
