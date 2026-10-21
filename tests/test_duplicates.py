"""Exact-duplicate detection: full-content SHA-256, never a 64KiB prefix."""
import os
import time

import pytest

from conftest import app_module


def _run_dups(env):
    env.app._dup_state.update(running=True)
    env.app._run_dup_scan(str(env.root))
    st = env.app._dup_state
    assert st["phase"] == "done", st
    return st["result"]


def _ids(groups):
    return [sorted(p["id"] for p in g) for g in groups]


def test_files_sharing_first_64k_are_not_identical(env):
    prefix = os.urandom(65536)
    a = env.root / "a.jpg"; a.write_bytes(prefix + b"tail-A" * 1000)
    b = env.root / "b.jpg"; b.write_bytes(prefix + b"tail-B" * 1000)  # same size, same first 64KiB
    assert a.stat().st_size == b.stat().st_size
    env.add_photo(a); env.add_photo(b)
    result = _run_dups(env)
    assert result["exact_groups"] == []


def test_truly_identical_files_are_grouped_with_verified_hash(env):
    data = os.urandom(200_000)
    for name in ("x.jpg", "sub/x_copy.jpg"):
        p = env.root / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(data)
        env.add_photo(p)
    other = env.root / "y.jpg"; other.write_bytes(os.urandom(200_000))  # same size, different
    env.add_photo(other)
    result = _run_dups(env)
    assert _ids(result["exact_groups"]) == [[os.path.join("sub", "x_copy.jpg"), "x.jpg"]]
    row = env.row("x.jpg")
    assert row["file_hash_algo"] == "sha256" and len(row["file_hash"]) == 64
    assert row["file_size"] == 200_000


def test_legacy_partial_hashes_are_never_trusted_and_get_recomputed(env):
    prefix = os.urandom(65536)
    a = env.root / "a.jpg"; a.write_bytes(prefix + b"A" * 5000)
    b = env.root / "b.jpg"; b.write_bytes(prefix + b"B" * 5000)
    # Simulate rows from before the migration: same legacy MD5-of-64KiB.
    env.add_photo(a, file_hash="d41d8cd98f00b204e9800998ecf8427e")
    env.add_photo(b, file_hash="d41d8cd98f00b204e9800998ecf8427e")
    conn = app_module._connect_db()
    conn.execute("UPDATE photos SET file_hash_algo=NULL")
    conn.commit(); conn.close()
    app_module.init_db()  # migration labels them
    assert env.row("a.jpg")["file_hash_algo"] == "md5-64k-legacy"
    result = _run_dups(env)
    assert result["exact_groups"] == []
    assert env.row("a.jpg")["file_hash_algo"] == "sha256"
    assert env.row("a.jpg")["file_hash"] != env.row("b.jpg")["file_hash"]


def test_stale_hash_is_recomputed_after_file_changes(env):
    data = os.urandom(100_000)
    a = env.root / "a.jpg"; a.write_bytes(data)
    b = env.root / "b.jpg"; b.write_bytes(data)
    env.add_photo(a); env.add_photo(b)
    assert len(_run_dups(env)["exact_groups"]) == 1
    # Edit b in place (same size): the stored hash must not be reused.
    b.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))
    os.utime(b, (time.time() + 5, time.time() + 5))
    env.app._dup_state.update(result=None)
    assert _run_dups(env)["exact_groups"] == []


def test_file_changing_during_hash_is_reported_unstable(env, monkeypatch):
    p = env.root / "growing.jpg"; p.write_bytes(b"x" * 10_000)
    real_fstat = os.fstat
    calls = {"n": 0}

    def flaky_fstat(fd):
        st = real_fstat(fd)
        calls["n"] += 1
        if calls["n"] % 2 == 0:  # "after" stat always differs from "before"
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                                   st.st_gid, st.st_size + 1, st.st_atime, st.st_mtime, st.st_ctime))
        return st
    monkeypatch.setattr(app_module.os, "fstat", flaky_fstat)
    monkeypatch.setattr(app_module.time, "sleep", lambda s: None)
    with pytest.raises(app_module.FileUnstableError):
        app_module.compute_file_sha256(str(p))


def test_perceptual_matches_are_kept_separate_from_exact(env):
    from conftest import make_jpeg
    make_jpeg(env.root / "p1.jpg", color=(10, 120, 200))
    make_jpeg(env.root / "p2.jpg", color=(10, 120, 200), extra_bytes=b"\0" * 10)  # same picture, different bytes
    for n in ("p1.jpg", "p2.jpg"):
        ph, dh = app_module.compute_perceptual_hashes(str(env.root / n))
        env.add_photo(env.root / n, phash=ph, dhash=dh)
    result = _run_dups(env)
    assert result["exact_groups"] == []
    assert _ids(result["phash_groups"]) == [["p1.jpg", "p2.jpg"]]


def test_duplicate_resolution_moves_never_deletes(env):
    data = os.urandom(50_000)
    a = env.root / "a.jpg"; a.write_bytes(data)
    b = env.root / "b.jpg"; b.write_bytes(data)
    env.add_photo(a); env.add_photo(b)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/duplicates/resolve", json={"move_ids": ["b.jpg"], "dry_run": False})
    assert r.status_code == 200 and r.json["results"][0]["ok"], r.json
    assert not b.exists()
    moved = env.root / "_duplicates" / "b.jpg"
    assert moved.read_bytes() == data
