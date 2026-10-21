"""Anti-forgery for browser mutations (no authentication) and destructive resets."""
import pytest

from conftest import app_module, make_jpeg


def _seed(env):
    p = make_jpeg(env.root / "a.jpg")
    env.add_photo(p)


def _count_photos():
    conn = app_module._connect_db()
    try:
        return conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
    finally:
        conn.close()


def test_page_embeds_token_and_reads_need_no_token(env):
    html = env.client.get("/").get_data(as_text=True)
    assert f'content="{env.token}"' in html
    assert env.client.get("/api/sessions").status_code == 200


@pytest.mark.parametrize("headers", [
    {},                                                     # plain cross-site form/fetch: no token
    {"Origin": "http://localhost"},                         # same origin but no token
    {app_module.CSRF_HEADER: "wrong", "Origin": "http://localhost"},
    {"Origin": "http://evil.example"},                      # foreign origin, no token
])
def test_mutations_without_valid_token_are_rejected(env, headers):
    _seed(env)
    r = env.client.post("/api/pending/discard", json={}, headers=headers)
    assert r.status_code == 403
    r = env.client.post("/api/dry_run", json={"dry_run": False}, headers=headers)
    assert r.status_code == 403
    assert env.app.get_dry_run() is True


def test_foreign_origin_rejected_even_with_token(env):
    h = {app_module.CSRF_HEADER: env.token, "Origin": "http://evil.example"}
    assert env.client.post("/api/dry_run", json={"dry_run": False}, headers=h).status_code == 403
    h = {app_module.CSRF_HEADER: env.token, "Referer": "http://evil.example/page"}
    assert env.client.post("/api/dry_run", json={"dry_run": False}, headers=h).status_code == 403
    h = {app_module.CSRF_HEADER: env.token, "Origin": "null"}
    assert env.client.post("/api/dry_run", json={"dry_run": False}, headers=h).status_code == 403
    assert env.app.get_dry_run() is True


def test_form_post_cannot_reset(env):
    _seed(env)
    r = env.client.post("/api/reset_database", data={"confirm": "RESET LIBRARY DATA"},
                        headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert _count_photos() == 1


def test_reset_requires_server_issued_confirmation(env):
    _seed(env)
    # Token present but no confirmation → refused.
    r = env.post("/api/reset_database", json={})
    assert r.status_code == 400 and r.json["code"] == "confirm"
    # Made-up confirmation token → refused.
    r = env.post("/api/reset_database", json={"confirm": app_module.RESET_CONFIRM_PHRASE,
                                              "confirm_token": "made-up"})
    assert r.status_code == 400
    prep = env.post("/api/reset_database/prepare").json
    assert prep["counts"]["photos"] == 1
    # Right token, wrong phrase → refused, and the token is now spent.
    r = env.post("/api/reset_database", json={"confirm": "yes", "confirm_token": prep["confirm_token"]})
    assert r.status_code == 400
    r = env.post("/api/reset_database", json={"confirm": prep["confirm_phrase"],
                                              "confirm_token": prep["confirm_token"]})
    assert r.status_code == 400
    assert _count_photos() == 1
    # Fresh prepare + exact confirmation → reset happens, once.
    prep = env.post("/api/reset_database/prepare").json
    body = {"confirm": prep["confirm_phrase"], "confirm_token": prep["confirm_token"]}
    assert env.post("/api/reset_database", json=body).status_code == 200
    assert _count_photos() == 0
    assert env.post("/api/reset_database", json=body).status_code == 400


def test_expired_reset_token_refused(env, monkeypatch):
    _seed(env)
    prep = env.post("/api/reset_database/prepare").json
    real_time = app_module.time.time
    monkeypatch.setattr(app_module.time, "time", lambda: real_time() + 3600)
    r = env.post("/api/reset_database", json={"confirm": prep["confirm_phrase"],
                                              "confirm_token": prep["confirm_token"]})
    assert r.status_code == 400
    assert _count_photos() == 1


def test_get_requests_do_not_change_pending_rows(env):
    _seed(env)
    conn = app_module._connect_db()
    for v in ("one", "two"):
        conn.execute("INSERT INTO pending_changes (photo_id, field, new_value) VALUES ('a.jpg','location_name',?)", (v,))
    conn.commit(); conn.close()
    env.client.get("/api/pending", query_string={"folder": str(env.root)})
    conn = app_module._connect_db()
    assert conn.execute("SELECT COUNT(*) FROM pending_changes").fetchone()[0] == 2
    conn.close()


def test_allowed_hosts_and_trusted_origins(env, monkeypatch):
    monkeypatch.setattr(app_module, "ALLOWED_HOSTS", {"tower:5000"})
    assert env.client.get("/api/sessions").status_code == 403                 # Host: localhost
    assert env.client.get("/api/sessions", headers={"Host": "tower:5000"}).status_code == 200
    monkeypatch.setattr(app_module, "ALLOWED_HOSTS", set())
    monkeypatch.setattr(app_module, "TRUSTED_ORIGINS", {"https://photos.home.lan"})
    h = {app_module.CSRF_HEADER: env.token, "Origin": "https://photos.home.lan"}
    assert env.client.post("/api/dry_run", json={"dry_run": True}, headers=h).status_code == 200


def test_security_headers(env):
    r = env.client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "Access-Control-Allow-Origin" not in r.headers


def test_json_body_limit(env, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_JSON_MB", 1)
    big = {"photos": [{"id": "x" * 1000}] * 1200}  # > 1 MB
    r = env.post("/api/save_batch", json=big)
    assert r.status_code == 413
    monkeypatch.setattr(app_module, "AI_MAX_REQUEST_KB", 1)
    r = env.post("/api/ai_infer", json={"photo": {"id": "a"}, "neighbors": [{"filename": "y" * 2000}]})
    assert r.status_code == 413
