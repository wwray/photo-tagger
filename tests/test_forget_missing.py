"""Scans forget photos whose files are gone, but never on a bad listing."""
import os
import shutil

import pytest

from conftest import app_module, make_jpeg


def _scan(env, rescan):
    env.app._scan_state.update(running=True)
    env.app._run_scan(str(env.root), rescan=rescan)
    assert env.app._scan_state["phase"] == "done", env.app._scan_state


def _pending(env, photo_id):
    conn = app_module._connect_db()
    try:
        return conn.execute("SELECT COUNT(*) FROM pending_changes WHERE photo_id=?",
                            (photo_id,)).fetchone()[0]
    finally:
        conn.close()


@pytest.mark.parametrize("rescan", [False, True])
def test_removed_folder_is_forgotten(env, rescan):
    make_jpeg(env.root / "keep" / "a.jpg")
    make_jpeg(env.root / "gone" / "b.jpg", color=(10, 200, 10))
    _scan(env, rescan=False)
    gone_id = os.path.join("gone", "b.jpg")
    assert env.row(gone_id)
    conn = app_module._connect_db()
    conn.execute("INSERT INTO pending_changes (photo_id,field,new_value) VALUES (?,?,?)",
                 (gone_id, "location_name", "Paris"))
    conn.commit()
    conn.close()

    shutil.rmtree(env.root / "gone")
    _scan(env, rescan=rescan)
    assert env.row(gone_id) is None
    assert _pending(env, gone_id) == 0
    assert env.row(os.path.join("keep", "a.jpg"))
    folders = {p["folder"] for p in env.client.get(
        "/api/scan_result", query_string={"folder": str(env.root)}).json["photos"]}
    assert folders == {"keep"}


def test_nothing_forgotten_when_no_photos_found(env):
    # An unmounted share looks like an empty folder — keep the library.
    make_jpeg(env.root / "a.jpg")
    _scan(env, rescan=False)
    os.remove(env.root / "a.jpg")
    _scan(env, rescan=True)
    assert env.row("a.jpg")


def test_nothing_forgotten_when_a_folder_was_unreadable(env, monkeypatch):
    make_jpeg(env.root / "a.jpg")
    make_jpeg(env.root / "sub" / "b.jpg", color=(10, 200, 10))
    _scan(env, rescan=False)
    shutil.rmtree(env.root / "sub")
    real_walk = os.walk

    def walk_with_error(top, onerror=None, **kw):
        if onerror:
            onerror(PermissionError(13, "Permission denied", str(env.root / "locked")))
        yield from real_walk(top, onerror=onerror, **kw)

    monkeypatch.setattr(app_module.os, "walk", walk_with_error)
    _scan(env, rescan=True)
    assert env.row(os.path.join("sub", "b.jpg"))


def test_files_are_never_deleted(env):
    make_jpeg(env.root / "a.jpg")
    make_jpeg(env.root / "_duplicates" / "c.jpg")           # excluded from listings
    _scan(env, rescan=False)
    env.add_photo(env.root / "_duplicates" / "c.jpg")       # a row the listing filters out
    _scan(env, rescan=True)
    assert (env.root / "_duplicates" / "c.jpg").exists()
    assert env.row(os.path.join("_duplicates", "c.jpg"))    # still on disk, so kept
