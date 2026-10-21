"""Filesystem boundaries: allowed roots, traversal, symlinks, id/path binding."""
import os
import time
import tempfile
from pathlib import Path

import pytest

from conftest import app_module, make_jpeg, can_symlink


def test_save_requires_existing_library_id(env):
    victim = env.outside / "victim.jpg"; make_jpeg(victim)
    before = victim.read_bytes()
    env.app.set_setting("dry_run", "false")
    # Old API shape: a bare path and no id.
    r = env.post("/api/save", json={"path": str(victim), "location_name": "pwned", "dry_run": False})
    assert r.status_code == 404
    r = env.post("/api/save_batch", json={"photos": [{"path": str(victim), "location_name": "pwned"}],
                                          "dry_run": False})
    assert r.status_code == 200 and not r.json["results"][0]["ok"]
    assert victim.read_bytes() == before


def test_mismatched_id_and_path_rejected(env):
    a = make_jpeg(env.root / "a.jpg"); b = make_jpeg(env.root / "b.jpg")
    env.add_photo(a); env.add_photo(b)
    env.app.set_setting("dry_run", "false")
    before = b.read_bytes()
    r = env.post("/api/save", json={"id": "a.jpg", "path": str(b), "location_name": "x"})
    assert r.status_code == 403
    r = env.post("/api/save_batch", json={"photos": [{"id": "a.jpg", "path": str(b), "location_name": "x"}]})
    assert not r.json["results"][0]["ok"]
    assert b.read_bytes() == before


def test_library_row_pointing_outside_roots_is_refused(env):
    """Even a DB row can't steer a write outside the allowed roots (e.g. a
    row from before ALLOWED_ROOTS, or a root removed from the config)."""
    victim = make_jpeg(env.outside / "v.jpg")
    before = victim.read_bytes()
    env.add_photo(victim, root=env.outside)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/save", json={"id": "v.jpg", "location_name": "x"})
    assert r.status_code == 403
    assert victim.read_bytes() == before
    assert env.client.get("/api/thumbnail?id=v.jpg&size=220").status_code == 404


def test_unsupported_file_type_refused(env):
    txt = env.root / "notes.txt"; txt.write_text("hello")
    env.add_photo(txt)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/save", json={"id": "notes.txt", "location_name": "x"})
    assert r.status_code == 403
    assert txt.read_text() == "hello"


@pytest.mark.parametrize("make_path", [
    lambda e: str(e.root / ".." / "outside"),
    lambda e: str(e.outside),
    lambda e: "relative/path",
    lambda e: str(e.root) + "\x00",
])
def test_scan_and_browse_reject_outside_paths(env, make_path):
    path = make_path(env)
    r = env.post("/api/scan", json={"folder": path})
    assert r.status_code in (400, 403)
    r = env.client.get("/api/browse", query_string={"path": path})
    assert r.status_code in (400, 403)


def test_multiple_allowed_roots_work(env):
    a = make_jpeg(env.root / "a.jpg"); b = make_jpeg(env.root2 / "deep" / "b.jpg")
    env.add_photo(a)
    env.add_photo(b, root=env.root2)
    for pid in ("a.jpg", os.path.join("deep", "b.jpg")):
        r = env.client.get("/api/thumbnail", query_string={"id": pid, "size": 220})
        assert r.status_code == 200 and r.mimetype == "image/jpeg"
    r = env.client.get("/api/browse", query_string={"path": str(env.root2)})
    assert r.status_code == 200 and r.json["dirs"] == ["deep"] and r.json["parent"] is None
    assert str(env.root) in r.json["roots"]
    r = env.post("/api/sessions", json={"name": "two", "scan_root": str(env.root2)})
    assert r.status_code == 200
    r = env.post("/api/sessions", json={"name": "bad", "scan_root": str(env.outside)})
    assert r.status_code == 403


def test_thumbnail_rejects_paths_and_bad_sizes(env):
    victim = make_jpeg(env.outside / "v.jpg")
    assert env.client.get("/api/thumbnail", query_string={"path": str(victim)}).status_code == 404
    a = make_jpeg(env.root / "a.jpg"); env.add_photo(a)
    for size in ("99999", "-1", "abc", "221"):
        assert env.client.get("/api/thumbnail", query_string={"id": "a.jpg", "size": size}).status_code == 400


def test_history_import_server_path_must_be_allowed(env):
    takeout = env.outside / "Records.json"; takeout.write_text('{"locations": []}')
    r = env.post("/api/history/import", json={"path": str(takeout)})
    assert r.status_code == 403
    assert env.app._hist_import_state["running"] is False
    inside = env.root / "Records.json"; inside.write_text('{"locations": []}')
    r = env.post("/api/history/import", json={"path": str(inside)})
    assert r.status_code == 200 and r.json["started"]
    deadline = time.time() + 10
    while env.app._hist_import_state["running"] and time.time() < deadline:
        time.sleep(0.05)
    assert env.app._hist_import_state["phase"] == "done"
    assert inside.exists()  # a server-side source file is never deleted


def test_ai_image_is_loaded_from_library_not_client_path(env, monkeypatch):
    a = make_jpeg(env.root / "a.jpg"); env.add_photo(a)
    secret = make_jpeg(env.outside / "secret.jpg")
    seen = []
    monkeypatch.setattr(app_module, "_encode_photo_for_ai", lambda p, max_dim=1024: seen.append(p) or None)
    monkeypatch.setattr(app_module, "_ai_call", lambda content: "Somewhere")
    r = env.post("/api/ai_infer", json={"photo": {"id": "a.jpg", "path": str(secret)}})
    assert r.status_code == 200, r.json
    assert seen == [os.path.realpath(str(a))]
    r = env.post("/api/ai_infer", json={"photo": {"path": str(secret)}})
    assert r.status_code == 404


needs_symlinks = pytest.mark.skipif(not can_symlink(Path(tempfile.mkdtemp())),
                                    reason="symlinks not permitted on this system")


@needs_symlinks
def test_symlink_escapes_are_refused(env):
    secret_dir = env.outside / "secret"; secret_dir.mkdir()
    victim = make_jpeg(secret_dir / "v.jpg")
    before = victim.read_bytes()
    (env.root / "link_dir").symlink_to(secret_dir, target_is_directory=True)
    (env.root / "link.jpg").symlink_to(victim)
    # Browsing/scanning into the linked dir is refused; it isn't even listed.
    assert env.client.get("/api/browse", query_string={"path": str(env.root / "link_dir")}).status_code == 403
    assert "link_dir" not in env.client.get("/api/browse", query_string={"path": str(env.root)}).json["dirs"]
    assert env.post("/api/scan", json={"folder": str(env.root / "link_dir")}).status_code == 403
    # The scanner skips both escaping links.
    assert app_module._list_photo_files(env.root) == []
    # A library row for the file symlink can't be written through.
    env.add_photo(env.root / "link.jpg")
    env.app.set_setting("dry_run", "false")
    assert env.post("/api/save", json={"id": "link.jpg", "location_name": "x"}).status_code == 403
    assert victim.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="Windows junction variant of the directory-escape test")
def test_directory_junction_escape_is_refused(env):
    import _winapi
    secret_dir = env.outside / "secret"; secret_dir.mkdir()
    victim = make_jpeg(secret_dir / "v.jpg")
    _winapi.CreateJunction(str(secret_dir), str(env.root / "junction"))
    assert env.client.get("/api/browse", query_string={"path": str(env.root / "junction")}).status_code == 403
    assert "junction" not in env.client.get("/api/browse", query_string={"path": str(env.root)}).json["dirs"]
    assert env.post("/api/scan", json={"folder": str(env.root / "junction")}).status_code == 403
    assert app_module._list_photo_files(env.root) == []
    env.add_photo(env.root / "junction" / "v.jpg")
    env.app.set_setting("dry_run", "false")
    before = victim.read_bytes()
    assert env.post("/api/save", json={"id": os.path.join("junction", "v.jpg"),
                                       "location_name": "x"}).status_code == 403
    assert victim.read_bytes() == before


@needs_symlinks
def test_symlinked_sidecar_is_not_followed(env):
    raw = env.root / "R.cr2"; raw.write_bytes(b"raw")
    target = env.outside / "target.xmp"; target.write_text("<keep/>")
    (env.root / "R.xmp").symlink_to(target)
    with pytest.raises(app_module.PathNotAllowed):
        app_module._write_xmp_sidecar(str(raw), "x", None, None, None)
    assert target.read_text() == "<keep/>"
