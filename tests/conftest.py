"""
Test harness. Everything runs against temporary directories, synthetic
photos/sidecars and mocked external services — never a real library, real
credentials or a paid API.

app.py does work at import time (init_db, privilege handling, startup
cleanup), so the environment is pointed at a throwaway location *before*
it's imported; each test then gets its own fresh database and photo roots.
"""
import io
import os
import sys
import shutil
import tempfile
from pathlib import Path

import piexif
import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
_BOOT = tempfile.mkdtemp(prefix="phototagger-test-boot-")
os.environ["DB_PATH"] = os.path.join(_BOOT, "boot.db")
os.environ["PHOTO_ROOT"] = os.path.join(_BOOT, "photos")
for var in ("PUID", "PGID", "ANTHROPIC_API_KEY", "ALLOWED_ROOTS", "ALLOWED_HOSTS",
            "TRUSTED_ORIGINS", "HISTORY_IMPORT_ROOTS"):
    os.environ.pop(var, None)
sys.path.insert(0, str(ROOT))

import app as app_module  # noqa: E402

ORIGIN = "http://localhost"


def make_jpeg(path, color=(200, 30, 30), size=(64, 48), exif=None, extra_bytes=b""):
    """A small real JPEG with EXIF (camera make/model + description)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if exif is None:
        exif = {"0th": {piexif.ImageIFD.Make: b"TestCam", piexif.ImageIFD.Model: b"TC-1",
                        piexif.ImageIFD.Software: b"KeepMe 1.0"},
                "Exif": {piexif.ExifIFD.LensModel: b"KeepLens 50mm"}, "GPS": {}, "1st": {}}
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "JPEG", exif=piexif.dump(exif), quality=90)
    path.write_bytes(buf.getvalue() + extra_bytes)
    return path


class Env:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.root = tmp_path / "photos"
        self.root2 = tmp_path / "photos2"
        self.outside = tmp_path / "outside"
        self.data = tmp_path / "data"
        for d in (self.root, self.root2, self.outside, self.data):
            d.mkdir()
        self.app = app_module
        self.client = app_module.app.test_client()

    @property
    def token(self):
        return app_module._csrf_token()

    def headers(self, **extra):
        h = {app_module.CSRF_HEADER: self.token, "Origin": ORIGIN}
        h.update(extra)
        return h

    def post(self, url, json=None, **kw):
        headers = kw.pop("headers", None) or self.headers()
        return self.client.post(url, json=json, headers=headers, **kw)

    def add_photo(self, path, root=None, **fields):
        """Register a file in the library as a scan would."""
        root = Path(root or self.root)
        path = Path(path)
        st = path.stat()
        photo = {"id": str(path.relative_to(root)), "path": str(path), "filename": path.name,
                 "folder": str(path.parent.relative_to(root)), "size_kb": round(st.st_size / 1024),
                 "file_size": st.st_size, "file_mtime": st.st_mtime, "scan_root": str(root)}
        photo.update(fields)
        conn = app_module._connect_db()
        app_module.db_upsert_photo(conn, photo)
        conn.commit()
        conn.close()
        return photo["id"]

    def row(self, photo_id):
        conn = app_module._connect_db()
        try:
            r = conn.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
            return dict(r) if r else None
        finally:
            conn.close()


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = Env(tmp_path)
    monkeypatch.setattr(app_module, "DB_PATH", str(e.data / "test.db"))
    monkeypatch.setattr(app_module, "THUMB_CACHE_DIR", e.data / "thumb_cache")
    monkeypatch.setattr(app_module, "UPLOAD_TMP_DIR", e.data / "tmp_imports")
    monkeypatch.setattr(app_module, "ALLOWED_ROOTS", [str(e.root), str(e.root2)])
    monkeypatch.setattr(app_module, "HISTORY_IMPORT_ROOTS", [])
    monkeypatch.setattr(app_module, "ALLOWED_HOSTS", set())
    monkeypatch.setattr(app_module, "TRUSTED_ORIGINS", set())
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    for state, lock in ((app_module._scan_state, app_module._scan_lock),
                        (app_module._dup_state, app_module._dup_lock),
                        (app_module._hist_import_state, app_module._hist_import_lock),
                        (app_module._hist_match_state, app_module._hist_match_lock)):
        with lock:
            state.update(running=False, phase="", error=None)
    with app_module._thumb_cache_lock:
        app_module._thumb_cache_bytes = None
    app_module.clear_geocoder_block()
    yield e
    app_module.clear_geocoder_block()
    shutil.rmtree(e.data / "thumb_cache", ignore_errors=True)


def can_symlink(tmp_path):
    try:
        target = tmp_path / "_t"
        target.write_text("x")
        (tmp_path / "_l").symlink_to(target)
        return True
    except (OSError, NotImplementedError):
        return False
