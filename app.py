import io
import os
import re
import sys
import hmac
import errno
import stat
import time
import json
import uuid
import base64
import bisect
import shutil
import secrets
import calendar
import hashlib
import sqlite3
import tempfile
import threading
import contextlib
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from array import array
from collections import deque
from pathlib import Path
from datetime import datetime
from urllib.parse import quote as _url_quote, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

import ijson
import exifread
import piexif
import imagehash
import requests
from flask import Flask, Request, jsonify, request, send_file, render_template, g
from PIL import Image, ImageOps


def _env_int(name, default, minimum=None, maximum=None):
    """Integer env var with a clear startup error instead of a bare
    ValueError traceback when someone types PUID=nobody or similar."""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        value = default
    else:
        try:
            value = int(str(raw).strip())
        except ValueError:
            raise SystemExit(f"[startup] FATAL: {name}={raw!r} is not an integer")
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


class _PhotoTaggerRequest(Request):
    """
    Werkzeug spools file uploads bigger than ~500KB into the system temp dir
    (/tmp, i.e. the container's writable layer — on Unraid, docker.img) and
    upload.save() then copies them a second time. A multi-GB Takeout export
    could fill docker.img that way. Spool straight into the data volume
    instead, under a unique name, and remember every spool file so
    _cleanup_upload_spools() can delete whatever a failed or rejected
    upload left behind.
    """
    def _get_file_stream(self, total_content_length, content_type, filename=None,
                         content_length=None):
        UPLOAD_TMP_DIR.mkdir(parents=True, exist_ok=True)
        f = tempfile.NamedTemporaryFile("wb+", dir=UPLOAD_TMP_DIR, prefix="spool_",
                                        suffix=".part", delete=False)
        try:
            g.setdefault("_upload_spools", []).append(f)
        except RuntimeError:
            pass  # no app context (never the case for a real request)
        return f


app = Flask(__name__)
app.request_class = _PhotoTaggerRequest

# ─── In-app log viewer ──────────────────────────────────────────────────────
# Everything printed to stdout/stderr (our own `_log()` calls, init_db's
# prints, the [startup] privilege-drop lines, traceback.print_exc(), even
# Flask/werkzeug's own request logging) previously only went to `docker
# logs`. That's fine if you have shell access, but on Unraid etc. it means
# a scan or startup error is invisible from the UI. Wrapping the streams
# tees every line into a small ring buffer that /api/logs can serve, with
# zero changes needed at each of the ~40 existing print() call sites.
_LOG_BUFFER_MAX = 2000
_log_buffer      = deque(maxlen=_LOG_BUFFER_MAX)
_log_buffer_lock = threading.Lock()
_log_seq         = 0

# ─── Credential redaction ───────────────────────────────────────────────────
# Geocoder keys travel as URL query parameters, and requests' HTTPError text
# is "401 Client Error: ... for url: https://...?key=<the key>&lat=...". That
# string used to go to the log verbatim (and from there to the in-app log
# viewer). Redaction happens centrally — in the stdout/stderr tee below and
# in _safe_error() for API responses — rather than at each call site, so a
# new provider or a traceback can't bypass it.
_SECRET_PARAM_RE = re.compile(
    r"(?i)([?&;]\s*(?:key|api[_-]?key|access[_-]?token|token|apikey|secret|password|signature|sig)=)[^&\s#'\"]+")
_SECRET_HEADER_RE = re.compile(r"(?i)((?:x-api-key|authorization|x-goog-api-key)['\"]?\s*[:=]\s*['\"]?)[^'\"\s,}]+")
_ANTHROPIC_KEY_RE = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")
_known_secrets = set()
_known_secrets_lock = threading.Lock()

def _register_secret(value):
    """Remember a secret's literal value so it's scrubbed even where it
    doesn't appear in key=value form (e.g. in a URL path)."""
    if value and len(value) >= 6:
        with _known_secrets_lock:
            _known_secrets.add(value)

def redact(text):
    if not text:
        return text
    text = str(text)
    text = _SECRET_PARAM_RE.sub(r"\1[REDACTED]", text)
    text = _SECRET_HEADER_RE.sub(r"\1[REDACTED]", text)
    text = _ANTHROPIC_KEY_RE.sub("[REDACTED]", text)
    with _known_secrets_lock:
        secrets_now = list(_known_secrets)
    for s in secrets_now:
        if s in text:
            text = text.replace(s, "[REDACTED]")
    return text

_register_secret(os.environ.get("ANTHROPIC_API_KEY", ""))

class _TeeStream:
    """Writes through to the real stream and also appends whole lines to
    the in-memory log buffer, so the UI can tail server output."""
    def __init__(self, real_stream, level):
        self._real = real_stream
        self._level = level
        self._partial = ""
        self._partial_lock = threading.Lock()

    def write(self, data):
        data = redact(data)
        self._real.write(data)
        global _log_seq
        # stdout/stderr are shared singletons written concurrently by the
        # scan/dup-scan/history threads and every request thread — without
        # a lock around this read-modify-write, two interleaved writes can
        # corrupt _partial's line boundaries and garble the log viewer.
        with self._partial_lock:
            self._partial += data
            lines = []
            while "\n" in self._partial:
                line, self._partial = self._partial.split("\n", 1)
                if line.strip():
                    lines.append(line)
        if lines:
            with _log_buffer_lock:
                for line in lines:
                    _log_seq += 1
                    _log_buffer.append({"id": _log_seq,
                                         "ts": datetime.now().isoformat(timespec="seconds"),
                                         "level": self._level,
                                         "line": line})

    def flush(self):
        self._real.flush()

    def isatty(self):
        return False

sys.stdout = _TeeStream(sys.stdout, "out")
sys.stderr = _TeeStream(sys.stderr, "err")

# ─── Config ───────────────────────────────────────────────────────────────────

PHOTO_EXTENSIONS   = {".jpg", ".jpeg", ".cr2", ".nef", ".arw", ".orf", ".rw2", ".dng"}
_EPOCH = datetime(1970, 1, 1)  # fixed reference point for turning a naive date_taken into a sortable float
# EXIF/hash reading during a scan is one file at a time in I/O (open the
# file) and CPU (phash/dhash) work — neither saturates a single core, so a
# thread pool overlaps many files' I/O and hashing instead of doing it
# strictly one-at-a-time. Capped rather than unbounded: too many threads
# hammering a spinning-disk NAS at once can make each individual read
# *slower* (seek thrashing) even though total throughput might rise on an
# SSD — SCAN_WORKERS lets that be tuned per deployment instead of assumed.
SCAN_WORKERS       = _env_int("SCAN_WORKERS", min(8, (os.cpu_count() or 4) * 2), 1, 32)
THUMB_CACHE_DIR    = Path(os.environ.get("DB_PATH", "/app/data/phototagger.db")).parent / "thumb_cache"
DEFAULT_PHOTO_ROOT = os.environ.get("PHOTO_ROOT", "/photos")
AI_DAILY_LIMIT     = _env_int("AI_DAILY_LIMIT", 50, 0)
AI_MODEL           = os.environ.get("AI_MODEL", "claude-haiku-4-5")
DB_PATH            = os.environ.get("DB_PATH", "/app/data/phototagger.db")
UPLOAD_TMP_DIR     = Path(DB_PATH).parent / "tmp_imports"

# ─── Filesystem boundaries ────────────────────────────────────────────────
# Every path the app reads or writes on behalf of a request — scan roots,
# the folder browser, thumbnails, metadata writes, renames, duplicate moves,
# server-side history imports, AI image loading — must resolve (symlinks
# included) to somewhere under one of these roots. Several roots are fine
# (several mounted shares); separate them with the OS path separator (":"
# in the Linux container, like $PATH). Default: /photos when PHOTO_ROOT is
# inside it (the normal container layout, even when PHOTO_ROOT is scoped to
# a subfolder like /photos/2024), otherwise PHOTO_ROOT itself.
def _default_allowed_roots():
    root = os.path.abspath(DEFAULT_PHOTO_ROOT)
    container = os.path.abspath("/photos")
    try:
        if os.path.commonpath([root, container]) == container:
            return [container]
    except ValueError:
        pass  # different drives on Windows
    return [root]

ALLOWED_ROOTS = [p for p in (s.strip() for s in os.environ.get("ALLOWED_ROOTS", "").split(os.pathsep)) if p] \
                or _default_allowed_roots()
# Server-side location-history imports may additionally read from these
# (e.g. a Takeout folder mounted outside the photo library). Uploads from
# the browser don't need this — they land in the data volume.
HISTORY_IMPORT_ROOTS = [p for p in (s.strip() for s in os.environ.get("HISTORY_IMPORT_ROOTS", "").split(os.pathsep)) if p]

# ─── Resource limits ──────────────────────────────────────────────────────
# Uploads are location-history files; a multi-year Takeout Records.json can
# be well over 1GB, so the default is generous. Everything else the UI sends
# is JSON — the biggest legitimate body is "Save all" on a large library.
MAX_UPLOAD_MB        = _env_int("MAX_UPLOAD_MB", 4096, 1)
MAX_JSON_MB          = _env_int("MAX_JSON_MB", 32, 1)
THUMB_CACHE_MAX_MB   = _env_int("THUMB_CACHE_MAX_MB", 2048, 0)   # 0 = unlimited
THUMB_WORKERS        = _env_int("THUMB_WORKERS", 4, 1, 32)
# Sizes the UI actually requests (grid densities, dup cards, previews,
# detail view). Anything else is rejected so the cache can't be filled
# with one file per arbitrary ?size= value.
THUMB_SIZES          = {160, 220, 280, 420, 800, 1400}
AI_MAX_CONCURRENT    = _env_int("AI_MAX_CONCURRENT", 2, 1, 16)
AI_MAX_REQUEST_KB    = _env_int("AI_MAX_REQUEST_KB", 256, 1)
AI_MAX_IMAGE_MB      = _env_int("AI_MAX_IMAGE_MB", 200, 1)
AI_TIMEOUT_SECONDS   = _env_int("AI_TIMEOUT_SECONDS", 60, 5)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# ─── Request-forgery protection (not authentication) ──────────────────────
# Optional comma-separated Host allow-list (e.g. "192.168.1.10:5000,tower:5000").
# Empty = any Host, which is the long-standing behavior. Setting it is the
# defense against DNS-rebinding; see README "Security model".
ALLOWED_HOSTS   = {h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}
# Extra browser origins allowed to make changes, for a reverse proxy that
# rewrites Host (e.g. "https://photos.home.lan").
TRUSTED_ORIGINS = {o.strip().lower().rstrip("/") for o in os.environ.get("TRUSTED_ORIGINS", "").split(",") if o.strip()}
CSRF_HEADER     = "X-PhotoTagger-CSRF"
# Baked into the image at build time (docker-publish.yml passes --build-arg
# GIT_SHA=<commit>, the Dockerfile turns that into this env var) so the
# running app can show which build is actually live in its own UI — see
# the version badge in the header. "dev" for a local `docker build`/`python
# app.py` with no GIT_SHA set, so this never breaks outside CI.
APP_VERSION        = os.environ.get("GIT_SHA", "dev")[:7]

_geocode_lock = threading.Lock()
_last_geocode = 0.0
_ai_lock      = threading.Lock()

# PUID/PGID for Unraid.
# The container starts as root (see Dockerfile) specifically so this can
# work: we create/own the data dir as root, then drop to the requested
# uid/gid before Flask ever touches a file. /photos is a host bind mount —
# its ownership is the host's responsibility, so it's deliberately not
# chowned here (that could take a long time and rewrite a whole library).
#
# A configured identity is a promise: if PUID/PGID are set and the drop
# doesn't fully succeed, the process exits rather than quietly carrying on
# as root with write access to the whole library. Unset PUID/PGID keeps the
# old behavior (run as whoever started us) but says so loudly; PUID=0 and
# PGID=0 is an explicit, logged request to stay root.
def _drop_privileges(puid_raw, pgid_raw, data_dir, _os=os):
    def fatal(msg):
        print(f"[startup] FATAL: {msg}", flush=True)
        raise SystemExit(1)

    if not hasattr(_os, "geteuid"):
        if puid_raw or pgid_raw:
            print("[startup] PUID/PGID ignored: this platform has no POSIX user ids", flush=True)
        return None

    if not puid_raw and not pgid_raw:
        if _os.geteuid() == 0:
            print("[startup] WARNING: running as root — PUID/PGID are not set. Set them "
                  "(e.g. 99/100 on Unraid) so files are written as that user.", flush=True)
        return None
    if not puid_raw or not pgid_raw:
        fatal("set both PUID and PGID, or neither")
    try:
        puid, pgid = int(puid_raw), int(pgid_raw)
    except ValueError:
        fatal(f"PUID/PGID must be integers (got {puid_raw!r}/{pgid_raw!r})")
    if puid < 0 or pgid < 0:
        fatal("PUID/PGID must not be negative")

    if puid == 0 or pgid == 0:
        if puid != 0 or pgid != 0:
            fatal("PUID and PGID must both be 0 to run as root deliberately")
        print("[startup] PUID=0/PGID=0 — running as root by explicit configuration", flush=True)
        return (0, 0)

    if _os.geteuid() != 0:
        # Already unprivileged (e.g. `docker run --user`): fine only if we're
        # already exactly who was asked for.
        if _os.getuid() == puid and _os.geteuid() == puid and _os.getgid() == pgid and _os.getegid() == pgid:
            print(f"[startup] Already running as uid={puid} gid={pgid}", flush=True)
            return (puid, pgid)
        fatal(f"PUID/PGID request uid={puid} gid={pgid}, but the process is uid={_os.geteuid()} "
              f"gid={_os.getegid()} and is not root, so it cannot switch")

    try:
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        before = data_dir.stat()
        print(f"[startup] {data_dir} currently owned by uid={before.st_uid} "
              f"gid={before.st_gid} — target is uid={puid} gid={pgid}", flush=True)
        # Re-own the data directory AND anything already in it (a db file
        # left over from a previous PUID/PGID otherwise gives "attempt to
        # write a readonly database"). Only the data dir — never the photo
        # library — and without following symlinks, so a link planted in
        # the data dir can't redirect a chown elsewhere.
        _os.chown(str(data_dir), puid, pgid)
        count = 0
        for dirpath, dirnames, filenames in _os.walk(str(data_dir), followlinks=False):
            for name in dirnames + filenames:
                _os.chown(_os.path.join(dirpath, name), puid, pgid, follow_symlinks=False)
                count += 1
        print(f"[startup] {data_dir} and {count} existing entr(y/ies) now owned by "
              f"uid={puid} gid={pgid}", flush=True)

        # Order matters: supplementary groups and gid can only be changed
        # while still root.
        _os.setgroups([])
        _os.setgid(pgid)
        _os.setuid(puid)
    except (OSError, AttributeError) as e:
        fatal(f"could not drop privileges to {puid}:{pgid}: {e}")

    # Verify instead of assuming.
    ids = (_os.getuid(), _os.geteuid(), _os.getgid(), _os.getegid())
    if ids != (puid, puid, pgid, pgid):
        fatal(f"privilege drop did not take effect (uid/euid/gid/egid = {ids})")
    extra_groups = set(_os.getgroups()) - {pgid}
    if extra_groups:
        fatal(f"supplementary groups still present after drop: {sorted(extra_groups)}")
    try:
        _os.setuid(0)
    except (OSError, PermissionError):
        pass
    else:
        fatal("was able to regain root after dropping privileges")
    print(f"[startup] Dropped privileges to uid={puid} gid={pgid} (supplementary groups cleared)",
          flush=True)
    return (puid, pgid)

_drop_privileges(os.environ.get("PUID", "").strip(), os.environ.get("PGID", "").strip(),
                 Path(DB_PATH).parent)

# ─── Database ─────────────────────────────────────────────────────────────────

# Some cameras write a firmware default into ImageDescription instead of
# leaving it empty — "OLYMPUS DIGITAL CAMERA" is the classic, widely
# documented case, and other manufacturers have their own "<BRAND> DIGITAL
# CAMERA"-shaped defaults. None of these are a caption or location a
# person entered; treating them as one made photos look "already tagged"
# (status='named') when nothing meaningful was actually saved on them —
# which then blocked Propagate-to-folder and other "don't overwrite
# confirmed data" logic from touching them at all. Defined up here (rather
# than near read_exif, where it's used) so it exists before _connect_db —
# which registers it as a SQL function for db_upsert_photo's self-healing
# CASE clause — is ever called, including by init_db() at import time.
_JUNK_DESCRIPTION_RE = re.compile(r"^[a-z0-9 ]+ digital camera$", re.IGNORECASE)

def _is_junk_description(text):
    if not text:
        return True
    t = text.strip()
    if not t:
        return True
    return bool(_JUNK_DESCRIPTION_RE.match(t))

def _connect_db():
    """
    Every connection — request-scoped or a background thread's own — goes
    through here so WAL mode, busy_timeout, and the custom SQL function
    db_upsert_photo relies on are all set up consistently, instead of each
    call site remembering to repeat them (and one inevitably forgetting).

    The busy_timeout matters more than it looks: a background scan holds
    SQLite's single writer lock for its entire commit batch (Python's
    sqlite3 module opens an implicit transaction on the first write and
    doesn't release the lock until .commit()), which can be several
    seconds of EXIF/hash-reading time for 50 photos. Without an explicit
    busy_timeout, SQLite's default is 0 — any other connection that tries
    to write during that window fails immediately with "database is
    locked" instead of just waiting a moment, which is exactly what turned
    "use a saved session while a scan is running" into a 500.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.create_function("is_junk_desc", 1, _is_junk_description)
    return conn

def _get_db():
    if "db" not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = _connect_db()
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def _close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def _db():
    """Get db connection — works both inside and outside request context."""
    if app.app_context():
        try:
            return _get_db()
        except RuntimeError:
            pass
    return _connect_db()

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = _connect_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS photos (
            id              TEXT PRIMARY KEY,   -- relative path from scan root
            path            TEXT NOT NULL,
            filename        TEXT NOT NULL,
            folder          TEXT NOT NULL,
            size_kb         INTEGER,
            file_mtime      REAL,               -- last modified time from filesystem
            date_taken      TEXT,
            lat             REAL,
            lon             REAL,
            location_name   TEXT,
            has_gps         INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'unknown',
            phash           TEXT,               -- perceptual hash (DCT-based)
            dhash           TEXT,               -- difference hash (structure/gradient-based)
            file_hash       TEXT,               -- see file_hash_algo: only 'sha256' is a full-content hash
            inferred_lat    REAL,
            inferred_lon    REAL,
            inferred_from   TEXT,
            inferred_delta_min INTEGER,
            scan_root       TEXT,
            last_scanned    TEXT,
            original_filename TEXT             -- for rename undo
        );

        CREATE TABLE IF NOT EXISTS pending_changes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            photo_id        TEXT NOT NULL,
            field           TEXT NOT NULL,      -- 'location_name','lat','lon','date_taken'
            old_value       TEXT,
            new_value       TEXT,
            created_at      TEXT DEFAULT (datetime('now')),
            committed       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS settings (
            key         TEXT PRIMARY KEY,
            value       TEXT,
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            scan_root   TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now')),
            last_used   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS rename_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            photo_id        TEXT NOT NULL,
            old_path        TEXT NOT NULL,
            new_path        TEXT NOT NULL,
            renamed_at      TEXT DEFAULT (datetime('now')),
            undone          INTEGER DEFAULT 0
        );

        -- Imported location-history sources (Google Takeout Records.json, GPX
        -- tracks). One row per import so a bad one can be removed cleanly
        -- without touching any other source's points.
        CREATE TABLE IF NOT EXISTS location_imports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name     TEXT NOT NULL,
            source_type     TEXT NOT NULL,      -- 'google_takeout' | 'gpx'
            point_count     INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'importing',  -- importing|done|error
            error           TEXT,
            imported_at     TEXT DEFAULT (datetime('now'))
        );

        -- Raw GPS trail points from imported sources. Can run into the
        -- millions of rows for a multi-year Takeout export — kept as bare
        -- floats with an index on timestamp for fast nearest-in-time lookup.
        CREATE TABLE IF NOT EXISTS location_points (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id       INTEGER NOT NULL REFERENCES location_imports(id) ON DELETE CASCADE,
            timestamp_epoch REAL NOT NULL,
            lat             REAL NOT NULL,
            lon             REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_photos_folder    ON photos(folder);
        CREATE INDEX IF NOT EXISTS idx_photos_status    ON photos(status);
        CREATE INDEX IF NOT EXISTS idx_photos_scan_root ON photos(scan_root);
        CREATE INDEX IF NOT EXISTS idx_photos_phash     ON photos(phash);
        CREATE INDEX IF NOT EXISTS idx_pending_photo    ON pending_changes(photo_id);
        CREATE INDEX IF NOT EXISTS idx_location_points_ts     ON location_points(timestamp_epoch);
        CREATE INDEX IF NOT EXISTS idx_location_points_import ON location_points(import_id);
    """)
    # Migration: add columns introduced after the first release
    existing = {r[1] for r in conn.execute("PRAGMA table_info(photos)")}
    for col, ddl in [("dhash", "TEXT"), ("date_source", "TEXT"),
                      ("history_lat", "REAL"), ("history_lon", "REAL"),
                      ("history_delta_min", "INTEGER"), ("history_import_id", "INTEGER"),
                      ("camera", "TEXT"), ("lens", "TEXT"), ("aperture", "TEXT"),
                      ("shutter", "TEXT"), ("iso", "TEXT"), ("focal_length", "TEXT"),
                      # Exact-duplicate provenance: which algorithm produced
                      # file_hash, and the size/mtime of the file it was
                      # computed from, so a later edit makes it stale
                      # instead of silently wrong.
                      ("file_hash_algo", "TEXT"), ("file_size", "INTEGER"),
                      ("hash_mtime", "REAL")]:
        if col not in existing:
            conn.execute(f"ALTER TABLE photos ADD COLUMN {col} {ddl}")
            print(f"[db] Migrated: added photos.{col}", flush=True)
    # Before file_hash_algo existed, file_hash was an MD5 of only the first
    # 64KB — two different photos sharing a header hashed identically, yet
    # were reported as byte-for-byte duplicates. Label those rows (data is
    # kept, not deleted) so exact-duplicate detection ignores them and
    # recomputes a full SHA-256 where it matters.
    relabeled = conn.execute("""UPDATE photos SET file_hash_algo='md5-64k-legacy'
                                WHERE file_hash IS NOT NULL AND file_hash_algo IS NULL""").rowcount
    if relabeled:
        print(f"[db] Migrated: marked {relabeled} legacy partial hash(es) as unverified", flush=True)
    # Self-heal formerly done on every GET /api/pending: keep only the most
    # recent uncommitted row per (photo_id, field). Committed rows are history.
    conn.execute("""
        DELETE FROM pending_changes
        WHERE committed=0 AND id NOT IN (
            SELECT MAX(id) FROM pending_changes WHERE committed=0
            GROUP BY photo_id, field
        )
    """)
    conn.commit()
    conn.close()
    # The settings table holds the geocoder API key in plain text; keep the
    # database readable by the app user only. SQLite gives -wal/-shm files
    # the same mode as the database file.
    if os.name == "posix":
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.chmod(DB_PATH + suffix, 0o600)
    print(f"[db] Initialised at {DB_PATH}", flush=True)

init_db()

# ─── DB helpers ───────────────────────────────────────────────────────────────

def db_upsert_photo(conn, photo: dict):
    conn.execute("""
        INSERT INTO photos (
            id, path, filename, folder, size_kb, file_mtime,
            date_taken, lat, lon, location_name, has_gps, status,
            phash, dhash, file_hash, file_hash_algo, file_size, hash_mtime,
            inferred_lat, inferred_lon,
            inferred_from, inferred_delta_min, scan_root, last_scanned, date_source,
            camera, lens, aperture, shutter, iso, focal_length
        ) VALUES (
            :id,:path,:filename,:folder,:size_kb,:file_mtime,
            :date_taken,:lat,:lon,:location_name,:has_gps,:status,
            :phash,:dhash,:file_hash,:file_hash_algo,:file_size,:hash_mtime,
            :inferred_lat,:inferred_lon,
            :inferred_from,:inferred_delta_min,:scan_root,:last_scanned,:date_source,
            :camera,:lens,:aperture,:shutter,:iso,:focal_length
        )
        ON CONFLICT(id) DO UPDATE SET
            path=excluded.path, filename=excluded.filename,
            folder=excluded.folder, size_kb=excluded.size_kb,
            file_mtime=excluded.file_mtime, date_taken=excluded.date_taken,
            lat=excluded.lat, lon=excluded.lon,
            -- A fresh read finding nothing normally keeps the old name (a
            -- transient EXIF read failure shouldn't wipe a real one) — but
            -- if the old name is a camera firmware default like "OLYMPUS
            -- DIGITAL CAMERA" rather than something anyone actually typed,
            -- a rescan should be allowed to clear it, not preserve it forever.
            location_name=CASE WHEN excluded.location_name IS NOT NULL THEN excluded.location_name
                               WHEN is_junk_desc(photos.location_name) THEN NULL
                               ELSE photos.location_name END,
            has_gps=excluded.has_gps,
            -- 'history' is a suggestion (from imported location history), not
            -- read straight from the file, so it's just as fragile to a
            -- rescan re-deriving 'unknown' as 'named'/'gps' would be — treat
            -- it the same way rather than silently discarding the match.
            -- Exception: a 'named' status backed only by junk description
            -- text was never a real name to protect — let it downgrade.
            status=CASE WHEN photos.status IN ('named','gps','history') AND excluded.status='unknown'
                             AND NOT (photos.status='named' AND is_junk_desc(photos.location_name))
                        THEN photos.status ELSE excluded.status END,
            phash=excluded.phash, dhash=excluded.dhash,
            -- A (re)scan only reaches here for a new or changed file, so any
            -- previous content hash no longer describes it. The exact-duplicate
            -- job recomputes a full SHA-256 on demand.
            file_hash=excluded.file_hash, file_hash_algo=excluded.file_hash_algo,
            file_size=excluded.file_size, hash_mtime=excluded.hash_mtime,
            date_source=excluded.date_source,
            inferred_lat=excluded.inferred_lat, inferred_lon=excluded.inferred_lon,
            inferred_from=excluded.inferred_from,
            inferred_delta_min=excluded.inferred_delta_min,
            scan_root=excluded.scan_root, last_scanned=excluded.last_scanned,
            camera=excluded.camera, lens=excluded.lens, aperture=excluded.aperture,
            shutter=excluded.shutter, iso=excluded.iso, focal_length=excluded.focal_length
    """, {**{
        "id":None,"path":None,"filename":None,"folder":None,"size_kb":None,
        "file_mtime":None,"date_taken":None,"lat":None,"lon":None,
        "location_name":None,"has_gps":0,"status":"unknown",
        "phash":None,"dhash":None,"file_hash":None,"file_hash_algo":None,
        "file_size":None,"hash_mtime":None,"date_source":None,
        "inferred_lat":None,"inferred_lon":None,
        "inferred_from":None,"inferred_delta_min":None,
        "scan_root":None,"last_scanned":None,
        "camera":None,"lens":None,"aperture":None,"shutter":None,
        "iso":None,"focal_length":None
    }, **photo})

def db_save_pending(conn, photo_id, field, old_value, new_value):
    # A dry-run stage for the same photo+field used to just accumulate: every
    # re-save while still adjusting a value before committing (reopen the
    # photo, nudge the pin, save again — or the same photo picked as a
    # Propagate/Push-date target more than once) inserted another row
    # instead of replacing the last one, so a couple of heavily-edited
    # photos could show dozens of "field changes" that were really the same
    # handful of fields staged repeatedly. old_value is always freshly read
    # from the untouched photos table by every caller (dry-run never writes
    # there), so it's safe to drop the superseded uncommitted row first —
    # only the latest queued value for a given field should ever be
    # pending at once. Committed rows are left alone; they're history, not
    # a duplicate to clean up.
    conn.execute("""
        DELETE FROM pending_changes WHERE photo_id=? AND field=? AND committed=0
    """, (photo_id, field))
    conn.execute("""
        INSERT INTO pending_changes (photo_id, field, old_value, new_value)
        VALUES (?,?,?,?)
    """, (photo_id, field, str(old_value) if old_value is not None else None,
          str(new_value) if new_value is not None else None))

def rows_to_dicts(rows):
    return [dict(r) for r in rows]

# ─── Settings / dry-run state (server-authoritative) ──────────────────────────
# The client used to send dry_run in the request body. That is unsafe: any time
# the JS state was wrong or stale, a real write happened. The server now owns
# this flag, it defaults to ON, and it is forced back ON on every page load.

def get_setting(key, default=None):
    conn = _connect_db()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    finally:
        conn.close()

def set_setting(key, value):
    conn = _connect_db()
    try:
        conn.execute("""INSERT INTO settings (key,value,updated_at)
                        VALUES (?,?,datetime('now'))
                        ON CONFLICT(key) DO UPDATE SET
                          value=excluded.value, updated_at=excluded.updated_at""",
                     (key, str(value)))
        conn.commit()
    finally:
        conn.close()

def get_dry_run():
    """Server-side dry run flag. Fails SAFE: unset/unreadable means ON."""
    v = get_setting("dry_run", "true")
    return str(v).lower() in ("1", "true", "yes")

def effective_dry_run(client_flag):
    """
    Resolve the dry run state for a write request.
    Server value wins, but a client asking for dry run can only make it
    MORE conservative, never less. There is no path to a real write unless
    the server flag is explicitly off.
    """
    return get_dry_run() or bool(client_flag)

def get_ai_model():
    """The model used for AI Suggest calls. Overridable from the UI
    (Settings), persisted in the settings table; falls back to the
    AI_MODEL env var / built-in default when nothing's been saved yet."""
    return get_setting("ai_model", AI_MODEL)

# ─── AI helpers ───────────────────────────────────────────────────────────────
# Usage is persisted in the settings table (same pattern as dry_run/ai_model)
# rather than kept only in a module-level dict — an in-memory-only counter
# means AI_DAILY_LIMIT isn't actually a daily cap in practice, since any
# restart (update, crash, host reboot) silently resets it to 0.

def _ai_load_usage():
    """(date, count) for today, from persisted storage. A stored date that
    isn't today reads as 0 without writing anything — the row only actually
    rolls over on the next _ai_reserve()."""
    today = _ai_today()
    stored_date = get_setting("ai_usage_date")
    if stored_date != today:
        return today, 0
    return today, int(get_setting("ai_usage_count", "0") or 0)

def _ai_today():
    return datetime.now().date().isoformat()

def _ai_reserve():
    """
    Atomically claim one unit of today's allowance BEFORE contacting the
    provider. This used to be check-now, increment-after-success as two
    separate steps, so N simultaneous requests could all pass the check
    and blow straight through AI_DAILY_LIMIT. The check and the increment
    are now one BEGIN IMMEDIATE transaction (serialized against every other
    writer, in any thread or process) under the process lock.
    Returns the reservation's date, or None if the limit is reached.
    """
    today = _ai_today()
    with _ai_lock:
        conn = _connect_db()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = dict(conn.execute(
                    "SELECT key, value FROM settings WHERE key IN ('ai_usage_date','ai_usage_count')").fetchall())
                count = int(rows.get("ai_usage_count") or 0) if rows.get("ai_usage_date") == today else 0
                if count >= AI_DAILY_LIMIT:
                    conn.execute("ROLLBACK")
                    return None
                for key, value in (("ai_usage_date", today), ("ai_usage_count", str(count + 1))):
                    conn.execute("""INSERT INTO settings (key,value,updated_at) VALUES (?,?,datetime('now'))
                                    ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                                    updated_at=excluded.updated_at""", (key, value))
                conn.execute("COMMIT")
                return today
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

def _ai_release(reserved_date):
    """Give back a reservation whose call never reached (or was rejected
    by) the provider. A reservation made before midnight is NOT refunded
    against the new day's counter — that counter never included it."""
    with _ai_lock:
        conn = _connect_db()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""UPDATE settings SET value=CAST(MAX(0, CAST(value AS INTEGER) - 1) AS TEXT)
                            WHERE key='ai_usage_count'
                              AND (SELECT value FROM settings WHERE key='ai_usage_date')=?""",
                         (reserved_date,))
            conn.execute("COMMIT")
        finally:
            conn.close()

_ai_semaphore = threading.BoundedSemaphore(AI_MAX_CONCURRENT)

def _ai_usage_info():
    with _ai_lock:
        _, count = _ai_load_usage()
        return {"used":count,"limit":AI_DAILY_LIMIT,"remaining":max(0,AI_DAILY_LIMIT-count)}

# ─── Filesystem safety ────────────────────────────────────────────────────────
# Requests name photos by library id; the server looks up the path it
# recorded at scan time and re-validates it here before touching the file.
# Paths a client does send (scan folder, browse, server-side history import)
# go through the same check: absolute, no NUL, and — after resolving every
# symlink — inside one of ALLOWED_ROOTS.

class PathNotAllowed(ValueError):
    """A path fell outside the allowed roots or isn't a supported file."""

class PhotoNotFound(Exception):
    """No library row for the requested photo id."""

def _norm_real(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))

def _allowed_root_reals(extra_roots=()):
    return [_norm_real(r) for r in list(ALLOWED_ROOTS) + list(extra_roots)]

def _is_within(real, root_real):
    try:
        return os.path.commonpath([real, root_real]) == root_real
    except ValueError:
        return False  # different drives (Windows)

def path_is_allowed(path, extra_roots=()):
    try:
        real = _norm_real(path)
    except (OSError, ValueError, TypeError):
        return False
    return any(_is_within(real, r) for r in _allowed_root_reals(extra_roots))

def resolve_allowed_path(path, kind="any", extra_roots=()):
    """Validate a path and return its fully-resolved real path. kind is
    'file', 'dir' or 'any' (must exist either way)."""
    if not isinstance(path, str) or not path.strip():
        raise PathNotAllowed("No path given")
    if "\x00" in path:
        raise PathNotAllowed("Invalid path")
    if not os.path.isabs(path):
        raise PathNotAllowed(f"Path must be absolute: {path}")
    real = os.path.realpath(os.path.abspath(path))
    if not path_is_allowed(real, extra_roots):
        raise PathNotAllowed(f"{path} is outside the allowed photo folders "
                             f"({os.pathsep.join(ALLOWED_ROOTS)})")
    if kind == "file" and not os.path.isfile(real):
        raise FileNotFoundError(f"File not found: {path}")
    if kind == "dir" and not os.path.isdir(real):
        raise FileNotFoundError(f"Not a directory: {path}")
    if kind == "any" and not os.path.exists(real):
        raise FileNotFoundError(f"Not found: {path}")
    return real

def photo_real_path(row):
    """The validated real path of a library row's original file."""
    real = resolve_allowed_path(row["path"], kind="file")
    for name in (row["path"], real):
        if Path(name).suffix.lower() not in PHOTO_EXTENSIONS:
            raise PathNotAllowed(f"Unsupported file type: {Path(name).name}")
    return real

def get_photo(db, photo_id, client_path=None):
    """
    Resolve a photo from a server-owned library id. A client-supplied path,
    if any, is only ever used as a consistency check — a mismatch is
    rejected rather than silently preferring either one.
    Returns (row, real_path).
    """
    if not isinstance(photo_id, str) or not photo_id:
        raise PhotoNotFound("A library photo id is required")
    row = db.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
    if not row:
        raise PhotoNotFound(f"Unknown photo id: {photo_id}")
    if client_path is not None and client_path != row["path"]:
        raise PathNotAllowed("Photo id and path do not match")
    return row, photo_real_path(row)

def sidecar_path_for(photo_path):
    """The XMP sidecar next to a photo, refusing a symlinked sidecar (a
    link could point a write at any file the app user can modify)."""
    sidecar = Path(photo_path).with_suffix(".xmp")
    if sidecar.is_symlink():
        raise PathNotAllowed(f"Refusing to use symlinked sidecar {sidecar.name}")
    if not path_is_allowed(str(sidecar.parent)):
        raise PathNotAllowed(f"{sidecar} is outside the allowed photo folders")
    return sidecar

def _default_file_mode():
    old = os.umask(0)
    os.umask(old)
    return 0o666 & ~old

_DEFAULT_FILE_MODE = _default_file_mode()

def atomic_write_bytes(target, data):
    """
    Write a file so readers only ever see the old or the new contents: a
    temp file in the same directory, fsync'd, then os.replace(). A crash or
    full disk mid-write leaves the original untouched instead of a
    truncated photo or sidecar. The original's permission bits are kept.
    """
    target = Path(target)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if target.exists():
            with contextlib.suppress(OSError):
                shutil.copymode(str(target), tmp)
        else:
            with contextlib.suppress(OSError):
                os.chmod(tmp, _DEFAULT_FILE_MODE)
        os.replace(tmp, str(target))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise

def move_no_clobber(src, dst):
    """
    Move a file, never overwriting an existing destination. A hard link is
    the atomic way to claim a name (it fails if the name exists); where the
    filesystem can't hard-link, fall back to check-then-rename (Windows'
    rename never overwrites; on POSIX that leaves a tiny race window) and,
    across devices, an exclusive-create copy.
    """
    src, dst = str(src), str(dst)
    try:
        os.link(src, dst)
    except FileExistsError:
        raise FileExistsError(errno.EEXIST, "Destination already exists", dst)
    except OSError:
        if os.path.lexists(dst):
            raise FileExistsError(errno.EEXIST, "Destination already exists", dst)
        try:
            os.rename(src, dst)
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
            with open(src, "rb") as fsrc, open(dst, "xb") as fdst:
                shutil.copyfileobj(fsrc, fdst, _HASH_CHUNK)
            shutil.copystat(src, dst)
            os.unlink(src)
        return
    try:
        os.unlink(src)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(dst)
        raise

# ─── Input validation ─────────────────────────────────────────────────────────

class BadInput(ValueError):
    pass

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

def clean_text(value, field, max_len=500):
    if value is None:
        return None
    if not isinstance(value, str):
        raise BadInput(f"{field} must be text")
    if len(value) > max_len:
        raise BadInput(f"{field} is too long (max {max_len} characters)")
    return _CONTROL_CHARS_RE.sub("", value)

def clean_coord(value, field, limit):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise BadInput(f"{field} must be a number")
    try:
        v = float(value)
    except (TypeError, ValueError):
        raise BadInput(f"{field} must be a number")
    if not (-limit <= v <= limit):
        raise BadInput(f"{field} must be between -{limit} and {limit}")
    return v

def clean_date(value):
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise BadInput("date_taken must be an ISO date/time")
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise BadInput("date_taken must be an ISO date/time")
    return value

def clean_rotation(value):
    if value in (None, "", 0, "0"):
        return 0
    try:
        deg = int(value)
    except (TypeError, ValueError):
        raise BadInput("rotate_degrees must be 90, 180 or 270")
    if deg % 360 not in (0, 90, 180, 270):
        raise BadInput("rotate_degrees must be 90, 180 or 270")
    return deg % 360

def safe_error(e, limit=500):
    """An exception message fit for an API response or a stored error:
    credentials redacted, length bounded."""
    return redact(str(e))[:limit]

# ─── EXIF helpers ─────────────────────────────────────────────────────────────

def _dms_to_decimal(dms, ref):
    try:
        d = float(dms[0].num)/float(dms[0].den)
        m = float(dms[1].num)/float(dms[1].den)
        s = float(dms[2].num)/float(dms[2].den)
        dec = d + m/60 + s/3600
        return -dec if ref in ("S","W") else dec
    except Exception:
        return None

def _exif_ratio_float(tag):
    """First value of an exifread numeric tag (FNumber, FocalLength, ...) as
    a float, or None. exifread stores EXIF rationals as Ratio(num,den)
    objects in `.values` — this is the shared unwrap for everything below
    that isn't GPS, which has its own DMS-specific helper above."""
    if tag is None:
        return None
    try:
        v = tag.values[0]
        return float(v.num) / float(v.den) if v.den else None
    except Exception:
        return None

def read_exif(filepath):
    result = {"date_taken":None,"lat":None,"lon":None,
              "location_name":None,"has_gps":False,"error":None,
              "date_source":None,"camera":None,"lens":None,
              "aperture":None,"shutter":None,"iso":None,"focal_length":None}
    try:
        with open(filepath,"rb") as f:
            tags = exifread.process_file(f, details=False)
        for tag in ("EXIF DateTimeOriginal","EXIF DateTimeDigitized","Image DateTime"):
            if tag in tags:
                try:
                    result["date_taken"] = datetime.strptime(
                        str(tags[tag]),"%Y:%m:%d %H:%M:%S").isoformat()
                    result["date_source"] = "exif"
                except ValueError: pass
                break
        lat_tag = tags.get("GPS GPSLatitude");  lat_ref = tags.get("GPS GPSLatitudeRef")
        lon_tag = tags.get("GPS GPSLongitude"); lon_ref = tags.get("GPS GPSLongitudeRef")
        if lat_tag and lon_tag and lat_ref and lon_ref:
            lat = _dms_to_decimal(lat_tag.values, str(lat_ref))
            lon = _dms_to_decimal(lon_tag.values, str(lon_ref))
            # (0,0) is "Null Island" — some cameras/apps write this instead of
            # omitting the GPS tags entirely when a GPS lock fails. Treating
            # it as real would reverse-geocode a lock failure into a bogus
            # Gulf-of-Guinea location and mark the photo confidently "gps".
            if lat is not None and lon is not None and (abs(lat) > 1e-6 or abs(lon) > 1e-6):
                result["lat"] = lat; result["lon"] = lon; result["has_gps"] = True
        if "Image ImageDescription" in tags:
            desc = str(tags["Image ImageDescription"]).strip()
            if not _is_junk_description(desc):
                result["location_name"] = desc

        # Camera/lens/exposure info — exifread already parsed all of this
        # out of the same file read above; it just wasn't kept before now.
        make  = str(tags.get("Image Make", "")).strip()
        model = str(tags.get("Image Model", "")).strip()
        # Some cameras write the make as a prefix of the model (e.g. make
        # "Canon", model "Canon EOS R5") — joining both unconditionally
        # would show "Canon Canon EOS R5".
        if model and make and model.lower().startswith(make.lower()):
            result["camera"] = model
        elif make or model:
            result["camera"] = f"{make} {model}".strip()
        lens = tags.get("EXIF LensModel")
        if lens:
            result["lens"] = str(lens).strip()
        fnumber = _exif_ratio_float(tags.get("EXIF FNumber"))
        if fnumber:
            result["aperture"] = f"f/{fnumber:g}"
        exposure = tags.get("EXIF ExposureTime")
        if exposure:
            try:
                r = exposure.values[0]
                if r.num and r.den:
                    result["shutter"] = f"{r.num}/{r.den}s" if r.num < r.den else f"{r.num/r.den:g}s"
            except Exception:
                pass
        iso = tags.get("EXIF ISOSpeedRatings")
        if iso:
            result["iso"] = str(iso)
        focal = _exif_ratio_float(tags.get("EXIF FocalLength"))
        if focal:
            result["focal_length"] = f"{focal:g}mm"
    except Exception as e:
        result["error"] = str(e)

    # Fall back to filesystem dates when EXIF has no date
    if not result["date_taken"]:
        try:
            stat = Path(filepath).stat()
            # Use the earlier of mtime/ctime as a best guess for creation date
            ts = min(stat.st_mtime, stat.st_ctime)
            result["date_taken"] = datetime.fromtimestamp(ts).isoformat()
            result["date_source"] = "filesystem"
        except Exception:
            pass

    return result

def compute_perceptual_hashes(filepath):
    """
    Return (phash_str, dhash_str) — visual-similarity fingerprints only,
    never evidence that two files are identical.
    Two perceptual hashes are computed because they fail in different ways:
    phash (DCT) is strong on general perceptual similarity but weak on
    high-frequency/noisy images; dhash (gradient) is strong on structure and
    robust to brightness and resize. Matching on either catches far more
    real-world duplicates than one alone.
    """
    phash_str = dhash_str = None
    try:
        with Image.open(filepath) as img:
            phash_str = str(imagehash.phash(img))
            dhash_str = str(imagehash.dhash(img))
    except Exception: pass
    return phash_str, dhash_str

FILE_HASH_ALGO = "sha256"
_HASH_CHUNK = 1024 * 1024

class FileUnstableError(OSError):
    """The file changed while it was being hashed."""

def compute_file_sha256(filepath, attempts=3):
    """
    Full-content SHA-256 of a file, returned as (hexdigest, size, mtime).
    The hash only counts if the file is demonstrably the same file, unchanged,
    from before the first byte to after the last: size and mtime (ns) are
    compared on the open handle before and after, and the number of bytes
    read must equal the size. A file being copied in or edited mid-hash is
    retried, then reported as unstable rather than given a hash that
    describes no version of it.
    """
    for _ in range(attempts):
        with open(filepath, "rb") as f:
            before = os.fstat(f.fileno())
            h = hashlib.sha256()
            nread = 0
            while True:
                chunk = f.read(_HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
                nread += len(chunk)
            after = os.fstat(f.fileno())
        try:
            on_disk = os.stat(filepath)
        except OSError:
            on_disk = None
        stable = (nread == before.st_size == after.st_size
                  and before.st_mtime_ns == after.st_mtime_ns
                  and on_disk is not None
                  and on_disk.st_size == after.st_size
                  and on_disk.st_mtime_ns == after.st_mtime_ns
                  # Same file still at that path (not replaced mid-hash).
                  # Skipped where a platform doesn't report inode numbers.
                  and (not on_disk.st_ino or not after.st_ino or on_disk.st_ino == after.st_ino))
        if stable:
            return h.hexdigest(), after.st_size, after.st_mtime
        time.sleep(0.05)
    raise FileUnstableError(f"{filepath} kept changing while it was being hashed")

# ─── Geocoder providers ────────────────────────────────────────────────────
# Nominatim is the zero-config default (free, no key, ~1 req/sec usage
# policy) — but that 1/sec pace is the single biggest fixed cost in a scan
# with a large GPS backlog (500 photos ≈ 10 min, unavoidably). Every
# provider below is pluggable behind the same reverse/forward interface so
# someone with a key for a faster service can opt in from Settings without
# anyone else's zero-config setup breaking. "delay" is each provider's own
# published free-tier rate limit (kept conservative on purpose — better to
# under-use a free tier than get the key throttled/banned).
GEOCODER_PROVIDERS = {
    "nominatim":  {"label": "Nominatim (OpenStreetMap) — free, no key",
                   "needs_key": False, "delay": 1.1,  "signup_url": None},
    "locationiq": {"label": "LocationIQ — free tier, 5,000/day",
                   "needs_key": True,  "delay": 0.55, "signup_url": "https://locationiq.com"},
    "opencage":   {"label": "OpenCage — free tier, 2,500/day",
                   "needs_key": True,  "delay": 1.05, "signup_url": "https://opencagedata.com"},
    "mapbox":     {"label": "Mapbox — free tier, 100,000/mo",
                   "needs_key": True,  "delay": 0.15, "signup_url": "https://www.mapbox.com"},
    "google":     {"label": "Google Maps — paid (billing required), $200/mo credit",
                   "needs_key": True,  "delay": 0.05, "signup_url": "https://console.cloud.google.com/google/maps-apis"},
}
_GEOCODE_UA = {"User-Agent": "PhotoTagger/1.0"}

def get_geocoder_provider():
    p = get_setting("geocoder_provider", "nominatim")
    return p if p in GEOCODER_PROVIDERS else "nominatim"

def get_geocoder_api_key():
    key = get_setting("geocoder_api_key", "") or ""
    _register_secret(key)
    return key

def _geocode_failure(provider, op, e):
    """Log a geocoder failure with enough to diagnose it (provider, HTTP
    status, endpoint) and nothing that can leak the key — redact() also
    runs on every log line, this just avoids handing it the raw URL."""
    detail = type(e).__name__
    resp = getattr(e, "response", None)
    if resp is not None:
        detail += f" HTTP {resp.status_code}"
        with contextlib.suppress(Exception):
            parts = urlsplit(resp.url)
            detail += f" from {parts.scheme}://{parts.netloc}{parts.path}"
    elif str(e):
        detail += f": {e}"
    _log(f"[geocode] {provider} {op} failed: {redact(detail)}")

def _clean_geocode_results(results):
    """Provider JSON is untrusted: keep only well-formed numeric coords."""
    out = []
    for r in results or []:
        try:
            lat, lon = float(r["lat"]), float(r["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            out.append({"name": str(r.get("name") or "")[:300], "lat": lat, "lon": lon})
    return out

def _active_geocoder():
    """Resolve (provider, key) for the next call. Fails safe: a provider
    that needs a key but has none configured silently falls back to
    Nominatim rather than erroring on every single geocode call — the same
    "never break the zero-config path" approach as dry_run/ai_model."""
    provider = get_geocoder_provider()
    key = get_geocoder_api_key()
    if GEOCODER_PROVIDERS[provider]["needs_key"] and not key:
        return "nominatim", ""
    return provider, key

def _geocode_throttle(provider):
    """Every call that hits a geocoder (reverse or forward) goes through
    this one gate so that provider's own rate limit holds regardless of
    which endpoint/thread is calling."""
    global _last_geocode
    delay = GEOCODER_PROVIDERS.get(provider, GEOCODER_PROVIDERS["nominatim"])["delay"]
    with _geocode_lock:
        wait = delay - (time.time() - _last_geocode)
        if wait > 0: time.sleep(wait)
        _last_geocode = time.time()

def _nominatim_style_name(data):
    """Nominatim and LocationIQ (a Nominatim-compatible API) share this
    exact response shape — one parser covers both."""
    addr = data.get("address", {})
    parts = []
    for key in ("city","town","village","municipality","county"):
        if key in addr: parts.append(addr[key]); break
    if "country" in addr: parts.append(addr["country"])
    return ", ".join(parts) if parts else data.get("display_name","")

def _reverse_nominatim(lat, lon, key):
    r = requests.get("https://nominatim.openstreetmap.org/reverse",
        params={"lat":lat,"lon":lon,"format":"json","zoom":14},
        headers=_GEOCODE_UA, timeout=10)
    r.raise_for_status()
    return _nominatim_style_name(r.json())

def _reverse_locationiq(lat, lon, key):
    r = requests.get("https://us1.locationiq.com/v1/reverse",
        params={"key":key,"lat":lat,"lon":lon,"format":"json"}, timeout=10)
    r.raise_for_status()
    return _nominatim_style_name(r.json())

def _reverse_opencage(lat, lon, key):
    r = requests.get("https://api.opencagedata.com/geocode/v1/json",
        params={"q":f"{lat}+{lon}","key":key,"no_annotations":1,"limit":1}, timeout=10)
    r.raise_for_status()
    results = r.json().get("results", [])
    if not results: return None
    comp = results[0].get("components", {})
    parts = []
    for k in ("city","town","village","municipality","county"):
        if k in comp: parts.append(comp[k]); break
    if "country" in comp: parts.append(comp["country"])
    return ", ".join(parts) if parts else results[0].get("formatted")

def _reverse_mapbox(lat, lon, key):
    r = requests.get(f"https://api.mapbox.com/geocoding/v5/mapbox.places/{lon},{lat}.json",
        params={"access_token":key,"types":"place,locality,region,country"}, timeout=10)
    r.raise_for_status()
    features = r.json().get("features", [])
    return features[0].get("place_name") if features else None

def _reverse_google(lat, lon, key):
    r = requests.get("https://maps.googleapis.com/maps/api/geocode/json",
        params={"latlng":f"{lat},{lon}","key":key}, timeout=10)
    r.raise_for_status()
    data = r.json()
    # Google's /geocode/json returns HTTP 200 even for an invalid/unauthorized
    # key or a billing-disabled project — the actual failure is only visible
    # in the "status" field (REQUEST_DENIED, OVER_QUERY_LIMIT, ...), so
    # raise_for_status() alone would miss it and this would silently read as
    # zero results, same as the bug this whole change is fixing.
    if data.get("status") not in ("OK", "ZERO_RESULTS"):
        raise RuntimeError(f"Google geocode error: {data.get('status')} — {data.get('error_message','')}")
    results = data.get("results", [])
    if not results: return None
    by_type = {}
    for c in results[0].get("address_components", []):
        for t in c.get("types", []):
            by_type.setdefault(t, c.get("long_name"))
    parts = []
    for t in ("locality","postal_town","administrative_area_level_2"):
        if t in by_type: parts.append(by_type[t]); break
    if "country" in by_type: parts.append(by_type["country"])
    return ", ".join(parts) if parts else results[0].get("formatted_address")

_REVERSE_GEOCODERS = {"nominatim":_reverse_nominatim, "locationiq":_reverse_locationiq,
                      "opencage":_reverse_opencage, "mapbox":_reverse_mapbox, "google":_reverse_google}

def reverse_geocode(lat, lon):
    provider, key = _active_geocoder()
    _geocode_throttle(provider)
    try:
        name = _REVERSE_GEOCODERS[provider](lat, lon, key)
        return str(name)[:300] if name else None
    except Exception as e:
        # Logged (visible in the in-app 🪵 Logs viewer) rather than swallowed
        # silently — a bad/expired key or wrong endpoint for the selected
        # provider used to come back indistinguishable from "found nothing."
        _geocode_failure(provider, "reverse_geocode", e)
        return None

def _forward_nominatim(query, limit, key):
    r = requests.get("https://nominatim.openstreetmap.org/search",
        params={"q":query,"format":"json","limit":limit},
        headers=_GEOCODE_UA, timeout=10)
    r.raise_for_status()
    return [{"name":x.get("display_name",""),"lat":float(x["lat"]),"lon":float(x["lon"])}
            for x in r.json()]

def _forward_locationiq(query, limit, key):
    r = requests.get("https://us1.locationiq.com/v1/search",
        params={"key":key,"q":query,"format":"json","limit":limit}, timeout=10)
    r.raise_for_status()
    return [{"name":x.get("display_name",""),"lat":float(x["lat"]),"lon":float(x["lon"])}
            for x in r.json()]

def _forward_opencage(query, limit, key):
    r = requests.get("https://api.opencagedata.com/geocode/v1/json",
        params={"q":query,"key":key,"limit":limit,"no_annotations":1}, timeout=10)
    r.raise_for_status()
    out = []
    for x in r.json().get("results", []):
        g = x.get("geometry", {})
        if "lat" in g and "lng" in g:
            out.append({"name":x.get("formatted",""),"lat":g["lat"],"lon":g["lng"]})
    return out

def _forward_mapbox(query, limit, key):
    r = requests.get(f"https://api.mapbox.com/geocoding/v5/mapbox.places/{_url_quote(query, safe='')}.json",
        params={"access_token":key,"limit":limit}, timeout=10)
    r.raise_for_status()
    out = []
    for f in r.json().get("features", []):
        lon, lat = f.get("center", [None, None])
        if lat is not None and lon is not None:
            out.append({"name":f.get("place_name",""),"lat":lat,"lon":lon})
    return out

def _forward_google(query, limit, key):
    r = requests.get("https://maps.googleapis.com/maps/api/geocode/json",
        params={"address":query,"key":key}, timeout=10)
    r.raise_for_status()
    data = r.json()
    if data.get("status") not in ("OK", "ZERO_RESULTS"):
        raise RuntimeError(f"Google geocode error: {data.get('status')} — {data.get('error_message','')}")
    out = []
    for x in data.get("results", [])[:limit]:
        loc = x.get("geometry", {}).get("location", {})
        if "lat" in loc and "lng" in loc:
            out.append({"name":x.get("formatted_address",""),"lat":loc["lat"],"lon":loc["lng"]})
    return out

_FORWARD_GEOCODERS = {"nominatim":_forward_nominatim, "locationiq":_forward_locationiq,
                      "opencage":_forward_opencage, "mapbox":_forward_mapbox, "google":_forward_google}

def forward_geocode_search(query, limit=5):
    """Address/place-name -> candidate list of {name,lat,lon}, for the map
    picker's search box. Each provider's free-text "search" endpoint, not
    the reverse one reverse_geocode() uses."""
    provider, key = _active_geocoder()
    _geocode_throttle(provider)
    try:
        return _clean_geocode_results(_FORWARD_GEOCODERS[provider](query, limit, key))
    except Exception as e:
        _geocode_failure(provider, "forward_geocode_search", e)
        return None

def write_location_to_exif(filepath, location_name, lat=None, lon=None, date_str=None):
    """filepath must already be validated (see get_photo/photo_real_path)."""
    ext = Path(filepath).suffix.lower()
    if ext in (".jpg",".jpeg"):
        _write_jpeg_exif(filepath, location_name, lat, lon, date_str)
    else:
        _write_xmp_sidecar(filepath, location_name, lat, lon, date_str)

def _write_jpeg_exif(filepath, location_name, lat=None, lon=None, date_str=None):
    # piexif.load() does NOT raise just because a JPEG has no EXIF segment —
    # it only raises when a segment exists but can't be parsed (unusual
    # maker-notes, a corrupt block, etc). A bare except here would silently
    # start from an empty dict and wipe every existing EXIF field (camera,
    # lens, exposure...) on this "safe" write. Refuse instead, so the save
    # surfaces as an error the user can see rather than quietly losing data.
    original = Path(filepath).read_bytes()
    try:
        exif_dict = piexif.load(original)
    except Exception as e:
        _log(f"[exif] Refusing to write {filepath}: existing EXIF could not be "
             f"parsed ({e}) — writing anyway would discard it")
        raise
    if location_name:
        exif_dict["0th"][piexif.ImageIFD.ImageDescription] = location_name.encode("utf-8")
    if lat is not None and lon is not None:
        def to_dms(deg):
            d=int(abs(deg)); m=int((abs(deg)-d)*60)
            s=round(((abs(deg)-d)*60-m)*60*100)
            return ((d,1),(m,1),(s,100))
        exif_dict["GPS"][piexif.GPSIFD.GPSLatitudeRef]  = b"N" if lat>=0 else b"S"
        exif_dict["GPS"][piexif.GPSIFD.GPSLatitude]     = to_dms(lat)
        exif_dict["GPS"][piexif.GPSIFD.GPSLongitudeRef] = b"E" if lon>=0 else b"W"
        exif_dict["GPS"][piexif.GPSIFD.GPSLongitude]    = to_dms(lon)
    if date_str:
        try:
            dt = datetime.fromisoformat(date_str)
            exif_date = dt.strftime("%Y:%m:%d %H:%M:%S").encode("utf-8")
            exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = exif_date
            exif_dict["0th"][piexif.ImageIFD.DateTime] = exif_date
        except ValueError: pass
    out = io.BytesIO()
    piexif.insert(piexif.dump(exif_dict), original, out)
    atomic_write_bytes(filepath, out.getvalue())

# ── XMP sidecars ──────────────────────────────────────────────────────────
# A sidecar is often shared with Lightroom/Capture One/darktable and can
# hold ratings, keywords, develop settings and more. Writing one used to
# replace the whole file with a four-field template, destroying all of that.
# Now an existing sidecar is parsed and only the properties being saved are
# changed, in whichever form they already appear (attribute or element);
# everything else — other properties, namespaces and their prefixes, other
# languages of dc:description, the xpacket wrapper — is kept. A sidecar
# that can't be parsed is left untouched and the save fails visibly.
NS_RDF   = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
NS_DC    = "http://purl.org/dc/elements/1.1/"
NS_EXIF  = "http://ns.adobe.com/exif/1.0/"
NS_XMP   = "http://ns.adobe.com/xap/1.0/"
NS_XML   = "http://www.w3.org/XML/1998/namespace"
NS_XMLNS = "http://www.w3.org/2000/xmlns/"
_XMP_PREFERRED_PREFIX = {NS_DC: "dc", NS_EXIF: "exif", NS_XMP: "xmp"}
_XMP_MAX_BYTES = 16 * 1024 * 1024
_NEW_SIDECAR = ("<?xpacket begin='﻿' id='W5M0MpCehiHzreSzNTczkc9d'?>\n"
                "<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
                "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
                "<rdf:Description rdf:about=''/>"
                "</rdf:RDF></x:xmpmeta>\n<?xpacket end='w'?>")

class SidecarError(ValueError):
    """An existing sidecar can't be safely updated."""

def _xmp_gps(value, pos_ref, neg_ref):
    """XMP GPSCoordinate form "DDD,MM.mmmmmmK" (XMP spec part 2 / EXIF
    schema) — what Lightroom and exiftool read for exif:GPSLatitude."""
    ref = pos_ref if value >= 0 else neg_ref
    v = abs(value)
    d = int(v)
    m = round((v - d) * 60, 6)
    if m >= 60:
        d, m = d + 1, 0.0
    return f"{d},{m:.6f}{ref}"

def _xmp_ns_scope(el):
    chain = []
    n = el
    while n is not None and n.nodeType == n.ELEMENT_NODE:
        chain.append(n)
        n = n.parentNode
    scope = {}
    for n in reversed(chain):
        for i in range(n.attributes.length):
            a = n.attributes.item(i)
            if a.name.startswith("xmlns:"):
                scope[a.name[6:]] = a.value
            elif a.name == "xmlns":
                scope[""] = a.value
    return scope

def _xmp_prefix(el, ns):
    """A prefix bound to ns where el is, declaring one on el if needed."""
    scope = _xmp_ns_scope(el)
    for p, uri in scope.items():
        if p and uri == ns:
            return p
    base = _XMP_PREFERRED_PREFIX.get(ns, "ns")
    p, i = base, 1
    while p in scope:
        p, i = f"{base}{i}", i + 1
    el.setAttributeNS(NS_XMLNS, f"xmlns:{p}", ns)
    return p

def _xmp_children(el, ns, local):
    return [c for c in el.childNodes
            if c.nodeType == c.ELEMENT_NODE and c.namespaceURI == ns and c.localName == local]

def _xmp_set_text(el, text):
    while el.firstChild:
        el.removeChild(el.firstChild)
    el.appendChild(el.ownerDocument.createTextNode(text))

def _xmp_set_simple(doc, descs, ns, local, value):
    for d in descs:
        attr = d.getAttributeNodeNS(ns, local)
        if attr is not None:
            attr.value = value
            return
    for d in descs:
        existing = _xmp_children(d, ns, local)
        if existing:
            _xmp_set_text(existing[0], value)
            return
    target = descs[0]
    el = doc.createElementNS(ns, f"{_xmp_prefix(target, ns)}:{local}")
    el.appendChild(doc.createTextNode(value))
    target.appendChild(el)

def _xmp_set_lang_alt(doc, descs, ns, local, value):
    """Set the x-default entry of a language alternative (dc:description),
    leaving any other languages alone."""
    for d in descs:
        attr = d.getAttributeNodeNS(ns, local)
        if attr is not None:
            attr.value = value
            return
    prop = None
    for d in descs:
        found = _xmp_children(d, ns, local)
        if found:
            prop = found[0]
            break
    if prop is None:
        target = descs[0]
        prop = doc.createElementNS(ns, f"{_xmp_prefix(target, ns)}:{local}")
        target.appendChild(prop)
    alts = _xmp_children(prop, NS_RDF, "Alt")
    rdf_p = _xmp_prefix(prop, NS_RDF)
    if alts:
        alt = alts[0]
    else:
        if any(c.nodeType == c.ELEMENT_NODE for c in prop.childNodes):
            raise SidecarError(f"{local} has an unexpected structure; not modifying it")
        alt = doc.createElementNS(NS_RDF, f"{rdf_p}:Alt")
        while prop.firstChild:  # plain-text value: becomes the x-default entry below
            prop.removeChild(prop.firstChild)
        prop.appendChild(alt)
    for li in _xmp_children(alt, NS_RDF, "li"):
        if li.getAttributeNS(NS_XML, "lang") == "x-default":
            _xmp_set_text(li, value)
            return
    li = doc.createElementNS(NS_RDF, f"{rdf_p}:li")
    li.setAttributeNS(NS_XML, "xml:lang", "x-default")
    li.appendChild(doc.createTextNode(value))
    alt.insertBefore(li, alt.firstChild)

def update_xmp_packet(xml_bytes, location_name=None, lat=None, lon=None, date_str=None):
    """Return new sidecar bytes with only the given fields changed."""
    if len(xml_bytes) > _XMP_MAX_BYTES:
        raise SidecarError("Sidecar is unexpectedly large; not modifying it")
    try:
        doc = minidom.parseString(xml_bytes)
    except Exception as e:
        raise SidecarError(f"Existing sidecar is not well-formed XML ({e}); not modifying it")
    if doc.doctype is not None:
        raise SidecarError("Existing sidecar contains a DTD; not modifying it")
    rdfs = doc.getElementsByTagNameNS(NS_RDF, "RDF")
    if len(rdfs) != 1:
        raise SidecarError("Existing sidecar has no single rdf:RDF element; not modifying it")
    rdf = rdfs[0]
    descs = _xmp_children(rdf, NS_RDF, "Description")
    if not descs:
        p = _xmp_prefix(rdf, NS_RDF)
        d = doc.createElementNS(NS_RDF, f"{p}:Description")
        d.setAttributeNS(NS_RDF, f"{p}:about", "")
        rdf.appendChild(d)
        descs = [d]
    if location_name:
        _xmp_set_lang_alt(doc, descs, NS_DC, "description", location_name)
    if lat is not None and lon is not None:
        _xmp_set_simple(doc, descs, NS_EXIF, "GPSLatitude", _xmp_gps(lat, "N", "S"))
        _xmp_set_simple(doc, descs, NS_EXIF, "GPSLongitude", _xmp_gps(lon, "E", "W"))
    if date_str:
        _xmp_set_simple(doc, descs, NS_XMP, "CreateDate", date_str)
    had_decl = xml_bytes.lstrip(b"\xef\xbb\xbf").lstrip().startswith(b"<?xml")
    body = "\n".join(n.toxml() for n in doc.childNodes)
    if had_decl:
        body = '<?xml version="1.0" encoding="UTF-8"?>\n' + body
    return body.encode("utf-8")

def _write_xmp_sidecar(filepath, location_name, lat=None, lon=None, date_str=None):
    sidecar = sidecar_path_for(filepath)
    for _ in range(3):
        if sidecar.exists():
            st = sidecar.stat()
            if not stat.S_ISREG(st.st_mode):
                raise SidecarError(f"{sidecar.name} is not a regular file")
            original = sidecar.read_bytes()
        else:
            st, original = None, _NEW_SIDECAR.encode("utf-8")
        new = update_xmp_packet(original, location_name, lat, lon, date_str)
        # Don't clobber an edit another program made while we were working.
        now = sidecar.stat() if sidecar.exists() else None
        if (st is None) != (now is None) or (st and (st.st_mtime_ns, st.st_size) != (now.st_mtime_ns, now.st_size)):
            continue
        atomic_write_bytes(sidecar, new)
        return
    raise SidecarError(f"{sidecar.name} kept changing while being updated; try again")

# JPEG only: PIL can decode/re-encode a JPEG's pixels, but not a RAW format,
# so there's no way to physically rotate a CR2/NEF/etc. without a RAW codec
# this app doesn't have. Rather than fake it with an XMP orientation hint
# that many RAW viewers ignore, rotation is just not offered for RAW files
# (the UI disables the buttons) — same honesty-over-guessing approach as
# everywhere else that only does what it can actually guarantee.
ROTATABLE_EXTENSIONS = {".jpg", ".jpeg"}

def rotate_image_file(filepath, degrees):
    """
    Physically rotate a JPEG's pixels clockwise by `degrees` (90/180/270) and
    re-save. Any existing EXIF orientation flag is normalized first — via
    exif_transpose — so a photo that already carries one doesn't end up
    rotated twice (once by the flag any viewer applies, once by us); the
    flag is then reset to 1 (normal) since the pixels themselves are now
    upright. EXIF (GPS, description, dates) is preserved by re-embedding it
    after PIL's save, which otherwise drops it.
    """
    degrees = int(degrees) % 360
    if degrees == 0:
        return
    if Path(filepath).suffix.lower() not in ROTATABLE_EXTENSIONS:
        raise ValueError("Rotation is only supported for JPEG files")
    # Same reasoning as _write_jpeg_exif: an unparseable EXIF segment is a
    # reason to refuse, not to silently start from empty and drop it all.
    original = Path(filepath).read_bytes()
    try:
        exif_dict = piexif.load(original)
    except Exception as e:
        _log(f"[exif] Refusing to rotate {filepath}: existing EXIF could not be "
             f"parsed ({e}) — rotating anyway would discard it")
        raise
    with Image.open(io.BytesIO(original)) as img:
        # Captured before convert()/rotate() — an embedded Adobe RGB/ProPhoto
        # profile isn't guaranteed to survive those, and save() silently drops
        # it if it's not passed back explicitly, causing a visible color shift
        # in other viewers afterward.
        icc_profile = img.info.get("icc_profile")
        img = ImageOps.exif_transpose(img)
        # PIL's rotate() is counter-clockwise; the UI's ⟳ is clockwise, so negate.
        img = img.rotate(-degrees, expand=True)
    exif_dict["0th"][piexif.ImageIFD.Orientation] = 1
    save_kwargs = {"quality": 92, "exif": piexif.dump(exif_dict)}
    if icc_profile:
        save_kwargs["icc_profile"] = icc_profile
    out = io.BytesIO()
    img.convert("RGB").save(out, "jpeg", **save_kwargs)
    atomic_write_bytes(filepath, out.getvalue())

# ─── Rename ────────────────────────────────────────────────────────────────────────────────────────
# Batch rename by pattern (tokens: {date} {time} {location} {seq} {orig} {ext}).
# rename_log and photos.original_filename already existed in the schema for
# this before any of the code below did — added ahead of time, never wired
# up until now. Goes through the same server-authoritative dry-run gate as
# everything else: with dry run on this stages a 'rename' pending change
# (shows up in the normal Review modal, reuses its commit/discard path);
# with dry run off it renames immediately.

_RENAME_SLUG_RE = re.compile(r"[^A-Za-z0-9._ -]+")

def _slugify_for_filename(text):
    """Strip characters that are awkward or unsafe in a filename (path
    separators, colons, quotes, emoji...) and collapse whitespace to
    underscores. Not a full transliteration — just enough that a location
    like 'Rio de Janeiro, Brazil' becomes 'Rio_de_Janeiro_Brazil' instead of
    failing, or worse, smuggling a path separator into a new filename."""
    if not text:
        return ""
    return re.sub(r"\s+", "_", _RENAME_SLUG_RE.sub("", text).strip())

def _build_rename_filename(pattern, photo, seq_counters):
    """
    Expand a rename pattern for one photo row. seq_counters is shared across
    a whole batch and keyed by date, so numbering restarts each day (matching
    how people actually number a folder of trip photos) instead of growing
    unbounded across an entire multi-year library.
    """
    orig_path = Path(photo["filename"])
    ext = orig_path.suffix
    date_str, time_str = "", ""
    if photo["date_taken"]:
        try:
            dt = datetime.fromisoformat(photo["date_taken"])
            date_str, time_str = dt.strftime("%Y-%m-%d"), dt.strftime("%H%M%S")
        except ValueError:
            pass
    key = date_str or "nodate"
    seq_counters[key] = seq_counters.get(key, 0) + 1
    replacements = {
        "date": date_str or "nodate",
        "time": time_str,
        "location": _slugify_for_filename(photo["location_name"] or ""),
        "seq": f"{seq_counters[key]:03d}",
        "orig": orig_path.stem,
        "ext": ext,
    }
    name = pattern
    for token, value in replacements.items():
        name = name.replace("{" + token + "}", value)
    # A missing token (no location yet, no date yet) leaves a gap next to
    # whatever separator the pattern put around it (e.g. "2024-06-12__001")
    # rather than a broken filename — collapse repeated separators instead
    # of trying to guess which literal characters in the pattern were meant
    # as separators around which token.
    name = re.sub(r"[_ -]{2,}", "_", name).strip("_ -")
    if not name.lower().endswith(ext.lower()):
        name += ext
    return name or (orig_path.stem + ext)

_WINDOWS_RESERVED_NAMES = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                           *(f"lpt{i}" for i in range(1, 10))}

def validate_new_filename(new_filename, old_path):
    """A bare filename (no directory parts) that keeps the photo's own
    extension — a rename must not change what kind of file it is or where
    it lives."""
    name = (new_filename or "").strip() if isinstance(new_filename, str) else ""
    if (not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name
            or _CONTROL_CHARS_RE.search(name) or len(name.encode("utf-8")) > 255
            or name.startswith(".") or Path(name).stem.lower() in _WINDOWS_RESERVED_NAMES):
        raise BadInput(f"Invalid filename: {new_filename!r}")
    if Path(name).suffix.lower() != Path(old_path).suffix.lower():
        raise BadInput(f"A rename must keep the {Path(old_path).suffix} extension")
    return name

def _sidecar_shared(photo_path):
    """True if another photo file uses the same IMG.xmp sidecar name (e.g.
    IMG.CR2 + IMG.JPG) — then the sidecar can't be assumed to belong to
    the file being moved."""
    p = Path(photo_path)
    for ext in PHOTO_EXTENSIONS:
        for variant in {ext, ext.upper()}:
            if variant == p.suffix:
                continue
            sib = p.with_suffix(variant)
            # samefile: on a case-insensitive filesystem IMG.jpg and IMG.JPG are one file
            with contextlib.suppress(OSError):
                if sib.exists() and not os.path.samefile(sib, p):
                    return True
    return False

def _apply_rename(db, row, new_filename):
    """
    Physically rename a photo file — and its XMP sidecar, if any, since a
    sidecar left behind under the old name becomes invisible to whatever
    reads the renamed file — and update its DB row. id IS the relative
    path, so a rename changes the primary key; rename_log keeps old/new
    path for later tracing, and original_filename preserves the very first
    name this photo ever had (COALESCE — a second rename must not overwrite
    it with the first rename's *result*).
    """
    photo_real_path(row)  # the recorded original must still be a valid, allowed photo
    old_path = Path(row["path"])
    if old_path.is_symlink():
        raise PathNotAllowed(f"Refusing to rename a symlink: {old_path.name}")
    new_filename = validate_new_filename(new_filename, old_path)
    new_path = old_path.parent / new_filename
    if os.path.lexists(new_path):
        raise FileExistsError(f"{new_filename} already exists in {old_path.parent}")
    # Sidecar collisions are checked before anything moves, so a refusal
    # never leaves the photo renamed but its sidecar behind — and an
    # unrelated .xmp already sitting at the new name is never overwritten.
    old_sidecar = sidecar_path_for(old_path)
    move_sidecar = old_sidecar.exists() and not _sidecar_shared(old_path)
    new_sidecar = new_path.with_suffix(".xmp")
    if move_sidecar and os.path.lexists(new_sidecar):
        raise FileExistsError(f"{new_sidecar.name} already exists in {old_path.parent}; "
                              f"not renaming so its metadata isn't overwritten")
    move_no_clobber(old_path, new_path)
    if move_sidecar:
        try:
            move_no_clobber(old_sidecar, new_sidecar)
        except OSError:
            move_no_clobber(new_path, old_path)  # put the photo back; keep the pair together
            raise
    new_id = str(new_path.relative_to(Path(row["scan_root"])))
    db.execute("""UPDATE photos SET id=?, path=?, filename=?,
                  original_filename=COALESCE(original_filename,?) WHERE id=?""",
               (new_id, str(new_path), new_path.name, row["filename"], row["id"]))
    db.execute("INSERT INTO rename_log (photo_id, old_path, new_path) VALUES (?,?,?)",
               (new_id, str(old_path), str(new_path)))
    return new_id

@app.route("/api/rename_preview", methods=["POST"])
def api_rename_preview():
    data = _json_body()
    ids = data.get("ids", [])
    if not isinstance(ids, list):
        return jsonify({"error": "ids must be a list"}), 400
    pattern = clean_text(data.get("pattern") or "", "pattern", 200).strip() or "{date}_{location}_{seq}{ext}"
    db = _get_db()
    seq_counters = {}
    preview = []
    for pid in ids:
        row = db.execute("SELECT * FROM photos WHERE id=?", (pid,)).fetchone()
        if not row:
            continue
        new_name = _build_rename_filename(pattern, row, seq_counters)
        preview.append({"id": pid, "old_filename": row["filename"], "new_filename": new_name,
                         "unchanged": new_name == row["filename"]})
    return jsonify({"preview": preview})

@app.route("/api/rename_batch", methods=["POST"])
def api_rename_batch():
    """
    Apply (or, with dry run on, stage) filename changes computed by
    /api/rename_preview. A staged rename is saved as an ordinary
    field='rename' pending change, so it shows up in the normal "Review
    pending changes" modal for free — only /api/pending/commit needs to
    know 'rename' isn't an EXIF field.
    """
    data = _json_body()
    items = data.get("items", [])
    if not isinstance(items, list):
        return jsonify({"error": "items must be a list"}), 400
    dry_run = effective_dry_run(data.get("dry_run", False))
    db = _get_db()
    results = []
    for item in items:
        pid = item.get("id") if isinstance(item, dict) else None
        new_filename = item.get("new_filename") if isinstance(item, dict) else None
        new_filename = new_filename.strip() if isinstance(new_filename, str) else ""
        try:
            row, _ = get_photo(db, pid)
        except PhotoNotFound:
            results.append({"id": pid, "ok": False, "error": "not found"}); continue
        except (PathNotAllowed, OSError) as e:
            results.append({"id": pid, "ok": False, "error": safe_error(e)}); continue
        if not new_filename or new_filename == row["filename"]:
            results.append({"id": pid, "ok": True, "skipped": True}); continue
        try:
            validate_new_filename(new_filename, row["path"])
        except BadInput as e:
            results.append({"id": pid, "ok": False, "error": safe_error(e)}); continue
        if dry_run:
            db_save_pending(db, pid, "rename", row["filename"], new_filename)
            results.append({"id": pid, "ok": True, "dry_run": True})
            continue
        try:
            new_id = _apply_rename(db, row, new_filename)
            results.append({"id": pid, "ok": True, "new_id": new_id})
        except Exception as e:
            results.append({"id": pid, "ok": False, "error": safe_error(e)})
    db.commit()
    return jsonify({"results": results, "dry_run": dry_run})

# ─── Scan (background thread) ─────────────────────────────────────────────────

_scan_state = {"running":False,"phase":"","current":0,"total":0,
               "message":"","error":None,"scan_root":None}
_scan_lock  = threading.Lock()

def _log(msg): print(msg, flush=True)

def _infer_locations(conn, folder):
    """Nearest-in-time GPS match: for every photo in `folder` that isn't
    already GPS/named/inferred/history-tagged, find the closest-in-time
    GPS-tagged photo in the same scan root and — if it's within 4 hours —
    copy its coordinates in as an 'inferred' guess. Pulled out of the scan
    pipeline so it can also run on demand (see /api/infer_nearby) without
    the EXIF re-read and hashing a full scan does, so a photo tagged by
    hand a moment ago can propagate to its siblings immediately instead of
    waiting for the next scan. Returns the number of photos updated.

    Also fills in a location *name*, not just coordinates, so an inferred
    photo already reads as a place when you open it rather than bare
    lat/lon: reuses the matched neighbor's name if it has one, otherwise
    reverse-geocodes the matched coordinates once per distinct neighbor
    (cached across the whole pass — many targets typically share the same
    nearest neighbor) and reuses that. reverse_geocode() already
    self-rate-limits, so this is safe to call inline here.
    """
    _name_cache = {}
    def _name_for(neighbor):
        if neighbor.get("location_name"):
            return neighbor["location_name"]
        if neighbor["id"] not in _name_cache:
            _name_cache[neighbor["id"]] = reverse_geocode(neighbor["lat"], neighbor["lon"])
        return _name_cache[neighbor["id"]]
    all_db = rows_to_dicts(conn.execute(
        "SELECT * FROM photos WHERE scan_root=?", (folder,)).fetchall())

    # A photo tagged by hand (map pin, Save to file, etc.) with dry run on
    # — the default — doesn't touch photos.has_gps/lat/lon at all until
    # that pending change is actually committed; db_save_pending() only
    # stages a pending_changes row. Without this, a manually-tagged photo
    # wouldn't count as a source here until you'd already written it to
    # disk, unlike a photo with real EXIF GPS, which is a source the
    # moment it's scanned — exactly backwards from what "tag one, infer
    # the rest" should feel like. Treated as if already committed for the
    # purposes of this pass; nothing here writes to pending_changes or
    # touches the real lat/lon columns, so it's still just a suggestion
    # cache either way.
    pending_coords = {}
    for row in conn.execute("""
            SELECT photo_id, field, new_value FROM pending_changes
            WHERE committed=0 AND field IN ('lat','lon')
              AND photo_id IN (SELECT id FROM photos WHERE scan_root=?)
        """, (folder,)):
        pending_coords.setdefault(row["photo_id"], {})[row["field"]] = row["new_value"]

    def _effective_gps(p):
        pc = pending_coords.get(p["id"])
        if pc and "lat" in pc and "lon" in pc:
            try:
                return float(pc["lat"]), float(pc["lon"]), True
            except (TypeError, ValueError):
                pass
        return p["lat"], p["lon"], bool(p["has_gps"])

    # Pre-parse + sort every GPS photo's timestamp once, then bisect per
    # candidate. This used to re-parse every GPS photo's datetime string
    # inside the inner loop for every non-GPS candidate — an O(N×M) scan
    # with repeated parsing, the exact bug class already fixed once for
    # duplicate detection (11 min → 3 sec there). On a library with a
    # few thousand of each this was easily minutes; sorted + bisect
    # finds the same true nearest-in-time match in a couple of seconds.
    gps_ts, gps_sorted = [], []
    for p in all_db:
        lat, lon, has_gps = _effective_gps(p)
        if not (has_gps and lat is not None and lon is not None and p["date_taken"]):
            continue
        try:
            gps_ts.append((datetime.fromisoformat(p["date_taken"]) - _EPOCH).total_seconds())
            gps_sorted.append({**p, "lat":lat, "lon":lon})
        except ValueError:
            continue
    order = sorted(range(len(gps_ts)), key=lambda i: gps_ts[i])
    gps_ts     = [gps_ts[i] for i in order]
    gps_sorted = [gps_sorted[i] for i in order]

    inferred = 0
    for photo in all_db:
        # 'history' (matched against imported location history, if any)
        # is a stronger signal than a same-folder GPS-cluster guess —
        # don't let this pass clobber it back down to 'inferred'. A photo
        # with its own pending lat/lon is also skipped as a *target* here
        # (it's the other half of the source-side check above) — it
        # already has an intended location, it doesn't need a guess.
        if (photo["has_gps"] or photo["id"] in pending_coords
                or photo["status"] in ("named","inferred","history")
                or not photo["date_taken"] or not gps_ts):
            continue
        try:
            epoch = (datetime.fromisoformat(photo["date_taken"]) - _EPOCH).total_seconds()
        except ValueError:
            continue
        ins = bisect.bisect_left(gps_ts, epoch)
        best_idx, best_delta = None, float("inf")
        for j in (ins - 1, ins):
            if 0 <= j < len(gps_ts):
                delta = abs(gps_ts[j] - epoch)
                if delta < best_delta:
                    best_delta, best_idx = delta, j
        if best_idx is not None and best_delta <= 4*3600:
            best = gps_sorted[best_idx]
            conn.execute("""UPDATE photos SET inferred_lat=?,inferred_lon=?,
                inferred_from=?,inferred_delta_min=?,status='inferred',
                location_name=COALESCE(?,location_name)
                WHERE id=?""",
                (best["lat"],best["lon"],best["filename"],
                 round(best_delta/60),_name_for(best),photo["id"]))
            inferred += 1
    return inferred

def _scan_read_one(p):
    """
    Pure per-photo I/O + CPU work for one scan entry — read_exif,
    compute_perceptual_hashes, and a stat() — with no DB access at all, so it's safe
    to run many of these concurrently (see SCAN_WORKERS). Exceptions are
    caught and returned rather than raised so one unreadable/removed file
    (a real possibility mid-scan on a live library) can't abort the whole
    batch the way letting it propagate into a worker thread would.
    """
    try:
        exif = read_exif(str(p))
        phash_str, dhash_str = compute_perceptual_hashes(str(p))
        st = p.stat()
        return p, exif, phash_str, dhash_str, st, None
    except Exception as e:
        return p, None, None, None, None, str(e)

def _list_photo_files(base):
    """
    Every supported photo under base, without following directory symlinks
    (a link to / would otherwise pull the whole container into the library)
    and skipping file symlinks that resolve outside the allowed roots.
    _duplicates/ is where duplicate-resolution moves files (see
    _move_to_duplicates_folder) — it lives inside the scan root for
    simplicity, so it must be excluded here or a rescan would just
    re-import everything just moved out of the library as "new" photos.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(str(base), followlinks=False):
        # Also prune by resolved location: not every redirecting directory
        # is a symlink (Windows junctions, for one), and os.walk would
        # otherwise descend into it.
        dirnames[:] = [d for d in dirnames
                       if d != "_duplicates" and path_is_allowed(os.path.join(dirpath, d))]
        for name in filenames:
            if Path(name).suffix.lower() not in PHOTO_EXTENSIONS:
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full) and not path_is_allowed(full):
                _log(f"[scan] Skipping {full}: symlink points outside the allowed folders")
                continue
            found.append(Path(full))
    return sorted(found)

def _run_scan(folder, rescan=False):
    base = Path(folder)
    now_iso = datetime.now().isoformat()

    try:
        # ── Count ──────────────────────────────────────────────────
        with _scan_lock:
            _scan_state.update(phase="counting",message="Counting photo files…",
                               current=0,total=0,scan_root=folder)
        all_paths = _list_photo_files(base)
        total = len(all_paths)
        _log(f"[scan] Found {total} photos in {folder}")

        # ── Diff against DB (rescan) ───────────────────────────────
        if rescan:
            conn = _connect_db()
            existing = {r["id"]: r["file_mtime"]
                        for r in conn.execute(
                            "SELECT id,file_mtime FROM photos WHERE scan_root=?",
                            (folder,))}
            conn.close()
            new_or_changed = [p for p in all_paths
                              if str(p.relative_to(base)) not in existing
                              or abs((existing.get(str(p.relative_to(base)),0) or 0)
                                     - p.stat().st_mtime) > 1]
            skipped = total - len(new_or_changed)
            _log(f"[scan] Rescan: {len(new_or_changed)} new/changed, {skipped} unchanged")
            all_paths = new_or_changed

        with _scan_lock:
            _scan_state.update(total=len(all_paths),
                               message=f"Found {total} photos — reading EXIF…")

        # ── EXIF + hashes ──────────────────────────────────────────
        # Reading EXIF and computing two perceptual hashes per photo is both
        # I/O-bound (opening the file) and CPU-bound (imagehash) — this used
        # to fully finish one photo before even opening the next, one at a
        # time. A thread pool overlaps many files' I/O and hashing instead;
        # the sqlite writes, commits, and progress updates below all stay on
        # this one thread (db_upsert_photo/conn are never touched from a
        # worker), so nothing about the DB access here becomes concurrent —
        # only the pure read_exif/compute_perceptual_hashes work does.
        conn = _connect_db()
        total_paths = len(all_paths)
        done = 0

        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
            futures = {pool.submit(_scan_read_one, p): p for p in all_paths}
            for fut in as_completed(futures):
                p, exif, phash_str, dhash_str, st, err = fut.result()
                done += 1
                if err is not None:
                    _log(f"[scan] Skipping {p.name}: {err}")
                else:
                    photo = {
                        "id":           str(p.relative_to(base)),
                        "path":         str(p),
                        "filename":     p.name,
                        "folder":       str(p.parent.relative_to(base)),
                        "size_kb":      round(st.st_size/1024),
                        "file_size":    st.st_size,
                        "file_mtime":   st.st_mtime,
                        "date_taken":   exif["date_taken"],
                        "lat":          exif["lat"],
                        "lon":          exif["lon"],
                        "location_name":exif["location_name"],
                        "has_gps":      1 if exif["has_gps"] else 0,
                        "status":       "gps" if exif["has_gps"] else ("named" if exif["location_name"] else "unknown"),
                        "camera":       exif.get("camera"),
                        "lens":         exif.get("lens"),
                        "aperture":     exif.get("aperture"),
                        "shutter":      exif.get("shutter"),
                        "iso":          exif.get("iso"),
                        "focal_length": exif.get("focal_length"),
                        "phash":        phash_str,
                        "dhash":        dhash_str,
                        # Content hashes are computed lazily, and in full,
                        # by the duplicate job — see _verified_exact_groups.
                        "file_hash":    None,
                        "file_hash_algo": None,
                        "hash_mtime":   None,
                        "inferred_lat": None,"inferred_lon":None,
                        "inferred_from":None,"inferred_delta_min":None,
                        "scan_root":    folder,
                        "last_scanned": now_iso,
                        "date_source":  exif.get("date_source"),
                    }
                    db_upsert_photo(conn, photo)

                # Checked by `done` reaching a checkpoint, not gated on this
                # particular file having succeeded — otherwise the very last
                # file in the scan erroring would skip the final commit and
                # progress update entirely.
                if done % 50 == 0 or done == total_paths:
                    conn.commit()
                    _log(f"[scan] EXIF {done}/{total_paths}  {p.name}")
                    with _scan_lock:
                        _scan_state.update(phase="reading", current=done,
                            message=f"Reading EXIF: {done} / {total_paths}  ({p.name})")

        # ── Infer locations ────────────────────────────────────────
        with _scan_lock:
            _scan_state.update(phase="inferring",
                               message="Inferring locations from GPS clusters…")
        _log("[scan] Inferring locations…")

        inferred = _infer_locations(conn, folder)
        conn.commit()
        _log(f"[scan] Inferred {inferred} locations")

        # ── Geocode ────────────────────────────────────────────────
        # No cap here anymore — a cap meant a library with 1,000+ ungeocoded
        # GPS photos needed several full rescans just to advance it. The
        # rate limit (GEOCODER_PROVIDERS[provider]["delay"], ~1.1s/request
        # on the default Nominatim per its usage policy — faster on an
        # opted-in provider with its own key, see Settings) is the real,
        # already-documented pace ("Geocoding 500 photos takes ~10 min" —
        # README, Nominatim case); this just lets a scan finish the whole
        # backlog instead of stopping partway through it.
        # Queried fresh rather than reusing a stale in-memory snapshot from
        # before _infer_locations() ran — _infer_locations() used to leave
        # its `all_db` list lying around in this same scope for exactly this
        # filter to reuse, but now that it's a separate function that
        # variable no longer exists here at all (a NameError on every scan
        # that reached this phase, until this was caught: extracting a
        # helper and missing a call site that depended on its leftover
        # local state).
        needs_geo = rows_to_dicts(conn.execute(
            """SELECT * FROM photos WHERE scan_root=? AND has_gps=1
               AND (location_name IS NULL OR location_name='')""", (folder,)).fetchall())
        _log(f"[scan] Geocoding {len(needs_geo)} GPS photos…")
        for i, photo in enumerate(needs_geo):
            with _scan_lock:
                _scan_state.update(phase="geocoding", current=i+1, total=len(needs_geo),
                    message=f"Geocoding: {i+1}/{len(needs_geo)}  ({photo['filename']})")
            name = reverse_geocode(photo["lat"], photo["lon"])
            if name:
                conn.execute("UPDATE photos SET location_name=?,status='gps' WHERE id=?",
                             (name, photo["id"]))
                if (i+1)%20==0: conn.commit()
            _log(f"[scan] Geocode {i+1}/{len(needs_geo)}: {photo['filename']} → {name}")
        conn.commit()

        # Queried fresh for the same reason needs_geo is above — the old
        # in-memory `all_db` this used to read was current as of before
        # inferring/geocoding even ran, and no longer exists in this scope
        # at all now that population is _infer_locations()'s job.
        counts = {}
        for row in conn.execute(
                "SELECT status, COUNT(*) c FROM photos WHERE scan_root=? GROUP BY status", (folder,)):
            counts[row["status"]] = row["c"]
        conn.close()
        _log(f"[scan] Done. {counts}")
        with _scan_lock:
            _scan_state.update(running=False, phase="done",
                message=f"Done! {total} photos in library.",
                current=total, total=total)

    except Exception as e:
        import traceback; traceback.print_exc()
        _log(f"[scan] ERROR: {e}")
        with _scan_lock:
            _scan_state.update(running=False, phase="error",
                               error=str(e), message=f"Error: {e}")

# ─── Request guards ───────────────────────────────────────────────────────────
# There is deliberately no login (trusted LAN app). What these stop is a
# *different* website open in the same browser silently driving this API —
# e.g. an auto-submitting form POSTing /api/reset_database. Every state-
# changing request must carry a token that only a page served by this app
# can read (same-origin policy), and must not come from a foreign Origin.
# The page's fetch() wrapper adds the token automatically, so normal use
# never sees any of this.

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Endpoints whose bodies are uploads, bounded by MAX_UPLOAD_MB instead of
# MAX_JSON_MB.
_UPLOAD_ENDPOINTS = {"api_history_import"}
_AI_ENDPOINTS = {"api_ai_infer", "api_ai_infer_with_coords"}

_csrf_cache = (None, None)

def _csrf_token():
    """Per-install random token, persisted so a container restart doesn't
    invalidate open tabs. Created with INSERT OR IGNORE so two first
    requests racing each other can't each store a different token."""
    global _csrf_cache
    db_path, token = _csrf_cache
    if db_path == DB_PATH and token:
        return token
    token = get_setting("csrf_token")
    if not token:
        conn = _connect_db()
        try:
            conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('csrf_token', ?)",
                         (secrets.token_urlsafe(32),))
            conn.commit()
        finally:
            conn.close()
        token = get_setting("csrf_token")
    _csrf_cache = (DB_PATH, token)
    return token

def _forbidden(code, message):
    resp = jsonify({"error": message, "code": code})
    resp.status_code = 403
    return resp

def _origin_ok():
    """True unless the request names a foreign origin. Origin is sent by
    every modern browser on fetch() POSTs; Referer is the fallback."""
    origin = request.headers.get("Origin")
    if origin is None:
        ref = request.headers.get("Referer")
        if not ref:
            return True  # non-browser client; the token check still applies
        parts = urlsplit(ref)
        origin = f"{parts.scheme}://{parts.netloc}"
    origin = origin.strip().lower().rstrip("/")
    if origin == "null":
        return False
    if origin in TRUSTED_ORIGINS:
        return True
    return urlsplit(origin).netloc == request.host.lower()

@app.before_request
def _request_guards():
    if ALLOWED_HOSTS and request.host.lower() not in ALLOWED_HOSTS:
        return _forbidden("host", f"Host {request.host!r} is not in ALLOWED_HOSTS")
    if request.method in _SAFE_METHODS:
        return None
    # Body limits. The upload endpoint relies on MAX_CONTENT_LENGTH.
    if request.endpoint not in _UPLOAD_ENDPOINTS:
        limit = (AI_MAX_REQUEST_KB * 1024 if request.endpoint in _AI_ENDPOINTS
                 else MAX_JSON_MB * 1024 * 1024)
        if request.content_length is None and request.headers.get("Transfer-Encoding"):
            return jsonify({"error": "Chunked request bodies are not accepted"}), 411
        if (request.content_length or 0) > limit:
            return jsonify({"error": f"Request too large (limit {limit // 1024} KB)"}), 413
    if not _origin_ok():
        return _forbidden("origin", "Cross-site request refused")
    sent = request.headers.get(CSRF_HEADER, "")
    if not sent or not hmac.compare_digest(sent, _csrf_token()):
        return _forbidden("csrf", "Missing or stale page token — reload the page and try again")
    return None

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https://cdnjs.cloudflare.com "
        "https://*.tile.openstreetmap.org https://server.arcgisonline.com; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'")
    return resp

@app.teardown_request
def _cleanup_upload_spools(exc=None):
    """Delete upload spool files nobody claimed (a rejected, failed or
    abandoned upload). A successful import renames its spool away first."""
    for f in g.pop("_upload_spools", []):
        with contextlib.suppress(Exception):
            f.close()
        with contextlib.suppress(OSError):
            os.unlink(f.name)

@app.errorhandler(BadInput)
def _bad_input(e):
    return jsonify({"error": safe_error(e)}), 400

@app.errorhandler(PathNotAllowed)
def _path_not_allowed(e):
    return jsonify({"error": safe_error(e)}), 403

@app.errorhandler(PhotoNotFound)
def _photo_not_found(e):
    return jsonify({"error": safe_error(e)}), 404

@app.errorhandler(FileNotFoundError)
def _file_not_found(e):
    return jsonify({"error": safe_error(e)}), 404

@app.errorhandler(413)
def _too_large(e):
    return jsonify({"error": f"Upload too large (limit {MAX_UPLOAD_MB} MB, see MAX_UPLOAD_MB)"}), 413

def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}

def _clear_stale_upload_spools():
    """Nothing can be mid-upload at startup, so anything left in the upload
    dir is debris from a crash or an interrupted upload."""
    if UPLOAD_TMP_DIR.is_dir():
        for p in UPLOAD_TMP_DIR.iterdir():
            if p.is_file() and (p.name.startswith("spool_") or p.name.startswith("upload_")):
                with contextlib.suppress(OSError):
                    p.unlink()

_clear_stale_upload_spools()

def _warn_scan_roots_outside_allowed():
    """Upgrade aid: sessions/scans recorded before ALLOWED_ROOTS existed may
    point somewhere that's now refused — say so once, at startup."""
    with contextlib.suppress(Exception):
        conn = _connect_db()
        try:
            roots = {r[0] for r in conn.execute(
                "SELECT DISTINCT scan_root FROM photos UNION SELECT DISTINCT scan_root FROM sessions") if r[0]}
        finally:
            conn.close()
        outside = sorted(r for r in roots if not path_is_allowed(r))
        if outside:
            _log(f"[startup] WARNING: these saved folders are outside ALLOWED_ROOTS "
                 f"({os.pathsep.join(ALLOWED_ROOTS)}) and can't be scanned or written until it "
                 f"includes them: {', '.join(outside)}")

_warn_scan_roots_outside_allowed()
_log(f"[startup] Allowed photo folders: {os.pathsep.join(ALLOWED_ROOTS)}")

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return render_template("index.html", version=APP_VERSION, csrf_token=_csrf_token())

@app.route("/api/version")
def api_version(): return jsonify({"version": APP_VERSION})

@app.route("/api/config")
def api_config():
    # Fail safe: every fresh page load re-arms dry run. A metadata writer
    # should never come back from a reload silently ready to write.
    set_setting("dry_run", "true")
    _log("[safety] Page load — dry run re-armed to ON")
    return jsonify({
        "default_photo_root": DEFAULT_PHOTO_ROOT,
        "has_ai_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "ai_usage": _ai_usage_info(),
        "ai_model": get_ai_model(),
        "ai_model_default": AI_MODEL,
        "dry_run": True,
        "geocoder_provider": get_geocoder_provider(),
        "has_geocoder_key": bool(get_geocoder_api_key()),
        "geocoder_providers": [{"id": pid, **meta} for pid, meta in GEOCODER_PROVIDERS.items()],
        "allowed_roots": ALLOWED_ROOTS,
        "max_upload_mb": MAX_UPLOAD_MB,
    })

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """User-configurable settings that aren't safety-critical enough to need
    their own endpoint (c.f. /api/dry_run, which is deliberately separate
    and more defensive). Add keys here as the settings surface grows."""
    if request.method == "POST":
        data = _json_body()
        if "ai_model" in data:
            model = (clean_text(data.get("ai_model") or "", "ai_model", 100)).strip()
            if model and not re.fullmatch(r"[A-Za-z0-9._:@/\-]+", model):
                raise BadInput("ai_model contains unexpected characters")
            set_setting("ai_model", model or AI_MODEL)
            _log(f"[settings] AI model set to {model or AI_MODEL}")
        if "geocoder_provider" in data:
            provider = (data.get("geocoder_provider") or "").strip() if isinstance(data.get("geocoder_provider"), str) else ""
            if provider in GEOCODER_PROVIDERS:
                set_setting("geocoder_provider", provider)
                _log(f"[settings] Geocoder provider set to {provider}")
        if data.get("clear_geocoder_key"):
            set_setting("geocoder_api_key", "")
            _log("[settings] Geocoder API key cleared")
        # Only overwrite a saved key when a new non-blank one is actually
        # sent — the Settings form never re-populates the key field with
        # the real value (see api_settings GET / has_geocoder_key below),
        # so a blank submit here means "unchanged", not "clear the key".
        elif data.get("geocoder_api_key"):
            key = clean_text(data["geocoder_api_key"], "geocoder_api_key", 512).strip()
            if not re.fullmatch(r"[\x21-\x7e]+", key):
                raise BadInput("API key must be printable ASCII without spaces")
            _register_secret(key)
            set_setting("geocoder_api_key", key)
            _log("[settings] Geocoder API key updated")
    return jsonify({
        "ai_model": get_ai_model(),
        "geocoder_provider": get_geocoder_provider(),
        "has_geocoder_key": bool(get_geocoder_api_key()),
    })

@app.route("/api/logs")
def api_logs():
    """
    Tail server stdout/stderr for the in-app Logs view.
    Pass `since` (last `id` you've already seen) to long-poll-style fetch
    only new lines; omit it (or pass 0) for an initial backfill of the last
    `limit` lines. Cheap: it's just filtering an in-memory deque.
    """
    since = request.args.get("since", 0, type=int)
    limit = max(1, min(_LOG_BUFFER_MAX, request.args.get("limit", 500, type=int)))
    with _log_buffer_lock:
        lines = [l for l in _log_buffer if l["id"] > since]
        if since <= 0:
            lines = lines[-limit:]
        last_id = _log_buffer[-1]["id"] if _log_buffer else since
    return jsonify({"lines": lines, "last_id": last_id})

@app.route("/api/dry_run", methods=["GET", "POST"])
def api_dry_run():
    """Read or set the server-side dry run flag. Survives scans and navigation."""
    if request.method == "POST":
        data = _json_body()
        val = data.get("dry_run", True) is not False  # only an explicit false turns it off
        set_setting("dry_run", "true" if val else "false")
        _log(f"[safety] Dry run set to {'ON' if val else 'OFF'}")
    return jsonify({"dry_run": get_dry_run()})

# ── Folder browser ────────────────────────────────────────────────
@app.route("/api/browse")
def api_browse():
    path = request.args.get("path") or DEFAULT_PHOTO_ROOT
    try:
        resolve_allowed_path(path, kind="dir")
        p = Path(os.path.abspath(path))
        # Directory symlinks that lead outside the allowed folders aren't
        # offered — choosing one would only be refused by /api/scan.
        dirs = sorted([str(d.name) for d in p.iterdir()
                       if d.is_dir() and not d.name.startswith(".") and path_is_allowed(str(d))])
        parent = str(p.parent) if str(p.parent) != str(p) and path_is_allowed(str(p.parent)) else None
        return jsonify({"path": str(p), "parent": parent, "dirs": dirs, "roots": ALLOWED_ROOTS})
    except PathNotAllowed as e:
        return jsonify({"error": safe_error(e), "roots": ALLOWED_ROOTS}), 403
    except FileNotFoundError as e:
        return jsonify({"error": safe_error(e), "roots": ALLOWED_ROOTS}), 400
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403

# ── Sessions ──────────────────────────────────────────────────────
@app.route("/api/sessions")
def api_sessions():
    db = _get_db()
    rows = db.execute("SELECT * FROM sessions ORDER BY last_used DESC").fetchall()
    return jsonify({"sessions": rows_to_dicts(rows)})

@app.route("/api/sessions", methods=["POST"])
def api_create_session():
    data = _json_body()
    name = (clean_text(data.get("name") or "", "name", 200) or "").strip()
    root = (clean_text(data.get("scan_root") or "", "scan_root", 4096) or "").strip()
    if not name or not root:
        return jsonify({"error":"name and scan_root required"}), 400
    resolve_allowed_path(root, kind="dir")
    db = _get_db()
    cur = db.execute("INSERT INTO sessions (name,scan_root) VALUES (?,?)", (name,root))
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "scan_root": root})

@app.route("/api/sessions/<int:sid>/use", methods=["POST"])
def api_use_session(sid):
    db = _get_db()
    db.execute("UPDATE sessions SET last_used=datetime('now') WHERE id=?", (sid,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/sessions/<int:sid>", methods=["DELETE"])
def api_delete_session(sid):
    db = _get_db()
    db.execute("DELETE FROM sessions WHERE id=?", (sid,))
    db.commit()
    return jsonify({"ok": True})

# ── Reset library data ──────────────────────────────────────────────
def _reset_library_data():
    """
    Wipe all tracked library data — scanned photos, pending dry-run
    changes, sessions, duplicate results, rename log, and imported
    location history/points — back to an empty database, as if freshly
    installed. Deliberately leaves the settings table alone (dry_run
    default, AI model, geocoder provider/key): those are app
    configuration, not library data, and losing a saved API key isn't
    the point of "start over with my photos." Actual photo files on disk
    are never touched — this only clears what PhotoTagger has recorded
    about them.
    """
    conn = _connect_db()
    try:
        conn.executescript("""
            DELETE FROM location_points;
            DELETE FROM location_imports;
            DELETE FROM rename_log;
            DELETE FROM pending_changes;
            DELETE FROM sessions;
            DELETE FROM photos;
        """)
        conn.commit()
    finally:
        conn.close()
    # Cached thumbnails are keyed by (path, size) alone — harmless to leave,
    # since a rescan of the same folder would just re-populate matching
    # cache hits, but "start from scratch" reasonably includes not leaving
    # gigabytes of derived thumbnail data behind for a library that's about
    # to be un-tracked.
    if THUMB_CACHE_DIR.is_dir():
        shutil.rmtree(THUMB_CACHE_DIR, ignore_errors=True)

# The reset confirmation lives on the server, not just in the browser's
# dialog: /prepare issues a single-use token (valid briefly) together with
# what would be deleted; the reset itself only proceeds with that token
# echoed back plus the literal confirmation phrase. A stray or scripted
# POST can't wipe the library on its own.
RESET_CONFIRM_PHRASE = "RESET LIBRARY DATA"
_RESET_TOKEN_TTL = 120
_reset_tokens = {}
_reset_tokens_lock = threading.Lock()

@app.route("/api/reset_database/prepare", methods=["POST"])
def api_reset_database_prepare():
    db = _get_db()
    counts = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("photos", "pending_changes", "sessions", "location_imports")}
    token = secrets.token_urlsafe(24)
    now = time.time()
    with _reset_tokens_lock:
        for k in [k for k, exp in _reset_tokens.items() if exp < now]:
            del _reset_tokens[k]
        _reset_tokens[token] = now + _RESET_TOKEN_TTL
    return jsonify({"confirm_token": token, "confirm_phrase": RESET_CONFIRM_PHRASE,
                    "expires_in": _RESET_TOKEN_TTL, "counts": counts})

def _consume_reset_token(token):
    if not isinstance(token, str) or not token:
        return False
    with _reset_tokens_lock:
        exp = _reset_tokens.pop(token, None)  # single use, valid or not
    return exp is not None and exp >= time.time()

@app.route("/api/reset_database", methods=["POST"])
def api_reset_database():
    """
    Refuses while any background job is running: each of those threads
    holds its own sqlite connection and writes mid-job assuming the rows
    it started with still exist — wiping the tables out from under a live
    scan/dup-scan/history job would corrupt its state or crash it, not
    just get skipped cleanly.
    """
    data = _json_body()
    token_ok = _consume_reset_token(data.get("confirm_token"))  # spent by any attempt
    if not token_ok or data.get("confirm") != RESET_CONFIRM_PHRASE:
        return jsonify({"error": "Reset not confirmed (missing, expired or reused confirmation)",
                        "code": "confirm"}), 400
    with _scan_lock:
        if _scan_state["running"]:
            return jsonify({"error": "A scan is running — wait for it to finish first"}), 409
    with _dup_lock:
        if _dup_state["running"]:
            return jsonify({"error": "Duplicate detection is running — wait for it to finish first"}), 409
    with _hist_import_lock:
        if _hist_import_state["running"]:
            return jsonify({"error": "A location history import is running — wait for it to finish first"}), 409
    with _hist_match_lock:
        if _hist_match_state["running"]:
            return jsonify({"error": "A location history match is running — wait for it to finish first"}), 409

    _reset_library_data()

    # Also clear in-memory job state — a stale "done"/"error" result left
    # over from before the wipe would otherwise reference a scan_root or
    # import_id that no longer has a single row behind it.
    with _scan_lock:
        _scan_state.update(running=False, phase="", current=0, total=0,
                            message="", error=None, scan_root=None)
    with _dup_lock:
        _dup_state.update(running=False, phase="", current=0, total=0,
                           message="", error=None, folder=None, result=None)
    with _hist_import_lock:
        _hist_import_state.update(running=False, phase="", current=0, total=0,
                                   message="", error=None, import_id=None)
    with _hist_match_lock:
        _hist_match_state.update(running=False, phase="", current=0, total=0,
                                  message="", error=None, result=None)

    _log("[reset] Library data wiped — photos, pending changes, sessions, duplicates, rename log, location history")
    return jsonify({"ok": True})

# ── Scan ──────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = _json_body()
    folder  = data.get("folder") if isinstance(data.get("folder"), str) else ""
    folder  = folder.strip()
    rescan  = data.get("rescan", False) is True
    if not folder:
        return jsonify({"error": "Folder not found: (empty)"}), 400
    try:
        resolve_allowed_path(folder, kind="dir")
    except FileNotFoundError:
        return jsonify({"error": f"Folder not found: {folder}"}), 400
    with _scan_lock:
        if _scan_state["running"]:
            return jsonify({"error":"Scan already in progress"}), 409
        _scan_state.update(running=True, phase="counting", current=0, total=0,
                           message="Starting…", error=None, scan_root=folder)
    threading.Thread(target=_run_scan, args=(folder, rescan), daemon=True).start()
    return jsonify({"started": True})

@app.route("/api/scan_progress")
def api_scan_progress():
    with _scan_lock:
        s = dict(_scan_state)
    return jsonify(s)

@app.route("/api/scan_result")
def api_scan_result():
    folder = request.args.get("folder","")
    if not folder:
        with _scan_lock:
            folder = _scan_state.get("scan_root","")
    db = _get_db()
    rows = db.execute("SELECT * FROM photos WHERE scan_root=? ORDER BY date_taken",
                      (folder,)).fetchall()
    photos = rows_to_dicts(rows)
    # The grid UI never reads these — they're internal to duplicate
    # detection, which queries them itself straight from the DB — but they
    # were shipped to the browser anyway on every load/rescan of a library
    # that can run to thousands of photos. True pagination would mean
    # moving filter/sort/search server-side, a bigger rework than this
    # pass; dropping the three unused, large fields is the safe win.
    for p in photos:
        p.pop("phash", None); p.pop("dhash", None); p.pop("file_hash", None)
    return jsonify({"photos": photos, "total": len(photos)})

# ── Pending changes (dry run persistence) ────────────────────────
@app.route("/api/pending")
def api_pending():
    folder = request.args.get("folder","")
    db = _get_db()
    # (The duplicate-row self-heal that used to run here, on a GET, now
    # runs once in init_db(); db_save_pending() prevents new duplicates.)
    rows = db.execute("""
        SELECT pc.id, pc.photo_id, pc.field, pc.old_value, pc.new_value,
               pc.created_at, p.filename, p.folder, p.path
        FROM pending_changes pc
        JOIN photos p ON p.id = pc.photo_id
        WHERE pc.committed=0 AND p.scan_root=?
        ORDER BY p.filename, pc.field
    """, (folder,)).fetchall()

    # Group by photo for easier display
    by_photo = {}
    for r in rows:
        pid = r["photo_id"]
        if pid not in by_photo:
            by_photo[pid] = {
                "photo_id": pid,
                "filename": r["filename"],
                "folder":   r["folder"],
                "path":     r["path"],
                "changes":  []
            }
        by_photo[pid]["changes"].append({
            "id":        r["id"],
            "field":     r["field"],
            "old_value": r["old_value"],
            "new_value": r["new_value"],
        })

    return jsonify({
        "pending":      list(by_photo.values()),
        "count":        len(rows),
        "photo_count":  len(by_photo),
    })

@app.route("/api/pending/commit", methods=["POST"])
def api_commit_pending():
    """Write all pending dry-run changes to actual files."""
    data = _json_body()
    ids  = data.get("ids")   # optional list of specific pending IDs
    if ids is not None and (not isinstance(ids, list) or not all(isinstance(i, int) for i in ids)):
        return jsonify({"error": "ids must be a list of integers"}), 400
    db   = _get_db()
    q = "SELECT pc.* FROM pending_changes pc JOIN photos p ON p.id=pc.photo_id WHERE pc.committed=0"
    rows = db.execute(q + (" AND pc.id IN ({})".format(",".join("?"*len(ids))) if ids else ""),
                      ids or []).fetchall()
    results = []
    by_photo = {}
    for r in rows:
        by_photo.setdefault(r["photo_id"], {})[r["field"]] = r["new_value"]

    for photo_id, fields in by_photo.items():
        try:
            # Resolved from the library row and re-validated at commit time:
            # the staged values were recorded earlier and the filesystem may
            # have changed since.
            row, real_path = get_photo(db, photo_id)
            # A photo marked for duplicate cleanup is leaving the library —
            # any other pending field for it (a location edit made before it
            # was flagged as a dup, say) is moot, so skip straight to the
            # move and mark everything for this photo committed together.
            if fields.get("move_to_duplicates"):
                _move_to_duplicates_folder(db, row)
                db.execute("UPDATE pending_changes SET committed=1 WHERE photo_id=? AND committed=0",
                           (photo_id,))
                results.append({"photo_id":photo_id,"ok":True})
                continue
            location_name = clean_text(fields.get("location_name"), "location_name", 1000)
            lat = clean_coord(fields.get("lat"), "lat", 90)
            lon = clean_coord(fields.get("lon"), "lon", 180)
            date_taken = clean_date(fields.get("date_taken"))
            rotation = clean_rotation(fields.get("rotate_degrees"))
            # write_location_to_exif unconditionally reloads+resaves the EXIF
            # segment even when nothing changed — fine for a real edit, but
            # a rename-only or rotate-only pending change would otherwise
            # re-encode the file for no reason.
            if location_name or lat is not None or lon is not None or date_taken:
                write_location_to_exif(real_path, location_name, lat, lon, date_taken)
            if rotation:
                rotate_image_file(real_path, rotation)
            # Renamed last: every write above already targeted the
            # pre-rename path, so doing this last means order here doesn't
            # matter for any of them.
            if fields.get("rename"):
                _apply_rename(db, row, fields["rename"])
            db.execute("UPDATE pending_changes SET committed=1 WHERE photo_id=? AND committed=0",
                       (photo_id,))
            results.append({"photo_id":photo_id,"ok":True})
        except Exception as e:
            results.append({"photo_id":photo_id,"ok":False,"error":safe_error(e)})
    db.commit()
    return jsonify({"results":results,"committed":sum(1 for r in results if r["ok"])})

@app.route("/api/pending/discard", methods=["POST"])
def api_discard_pending():
    data = _json_body()
    ids  = data.get("ids")
    if ids is not None and (not isinstance(ids, list) or not all(isinstance(i, int) for i in ids)):
        return jsonify({"error": "ids must be a list of integers"}), 400
    db   = _get_db()
    if ids:
        db.execute("DELETE FROM pending_changes WHERE id IN ({})".format(",".join("?"*len(ids))), ids)
    else:
        db.execute("DELETE FROM pending_changes WHERE committed=0")
    db.commit()
    return jsonify({"ok":True})

# ── Geocode ───────────────────────────────────────────────────────
@app.route("/api/geocode", methods=["POST"])
def api_geocode():
    data = _json_body()
    lat = clean_coord(data.get("lat"), "lat", 90)
    lon = clean_coord(data.get("lon"), "lon", 180)
    if lat is None or lon is None:
        return jsonify({"error":"lat/lon required"}), 400
    return jsonify({"location_name": reverse_geocode(lat,lon)})

@app.route("/api/geocode_search")
def api_geocode_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results":[]})
    q = clean_text(q, "q", 300)
    results = forward_geocode_search(q)
    if results is None:
        return jsonify({"error":"Search failed","results":[]}), 502
    return jsonify({"results":results})

# ── Saved / frequent locations ──────────────────────────────────────
# "Saved" is a short, explicit, user-curated list (places worth a single
# click forever, like home) stored as JSON in the same settings table
# everything else app-wide already lives in — a handful of entries never
# justified a whole new table. "Frequent" isn't stored at all; it's
# recomputed from however location_name is already actually being used
# in the current library, so it's useful immediately with zero setup and
# never goes stale relative to the real data.
def _get_saved_locations():
    raw = get_setting("saved_locations")
    try:
        return json.loads(raw) if raw else []
    except (TypeError, ValueError):
        return []

def _set_saved_locations(locs):
    set_setting("saved_locations", json.dumps(locs))

@app.route("/api/saved_locations")
def api_saved_locations():
    folder = request.args.get("folder","")
    frequent = []
    if folder:
        rows = _get_db().execute("""
            SELECT location_name AS name, AVG(lat) AS lat, AVG(lon) AS lon, COUNT(*) AS count
            FROM photos
            WHERE scan_root=? AND location_name IS NOT NULL AND location_name!=''
                  AND lat IS NOT NULL AND lon IS NOT NULL
            GROUP BY location_name
            ORDER BY count DESC
            LIMIT 8
        """, (folder,)).fetchall()
        frequent = rows_to_dicts(rows)
    return jsonify({"saved": _get_saved_locations(), "frequent": frequent})

@app.route("/api/saved_locations", methods=["POST"])
def api_saved_locations_add():
    data = _json_body()
    name = clean_text(data.get("name"), "name", 300)
    lat = clean_coord(data.get("lat"), "lat", 90)
    lon = clean_coord(data.get("lon"), "lon", 180)
    if not name or lat is None or lon is None:
        return jsonify({"error":"name, lat, lon required"}), 400
    locs = _get_saved_locations()
    locs = [l for l in locs if l.get("name") != name]  # re-saving a name updates it, doesn't duplicate it
    locs.insert(0, {"name":name, "lat":lat, "lon":lon})
    locs = locs[:50]  # a sane cap — this is a quick-pick list, not a gazetteer
    _set_saved_locations(locs)
    return jsonify({"ok":True, "saved":locs})

@app.route("/api/saved_locations/delete", methods=["POST"])
def api_saved_locations_delete():
    data = _json_body()
    idx = data.get("index")
    locs = _get_saved_locations()
    if not isinstance(idx,int) or not (0 <= idx < len(locs)):
        return jsonify({"error":"invalid index"}), 400
    locs.pop(idx)
    _set_saved_locations(locs)
    return jsonify({"ok":True, "saved":locs})

# ── Save ──────────────────────────────────────────────────────────
@app.route("/api/save", methods=["POST"])
def api_save():
    data          = _json_body()
    location_name = clean_text(data.get("location_name"), "location_name", 1000)
    lat           = clean_coord(data.get("lat"), "lat", 90)
    lon           = clean_coord(data.get("lon"), "lon", 180)
    date_str      = clean_date(data.get("date_taken"))
    rotate_deg    = clean_rotation(data.get("rotate_degrees"))
    dry_run       = effective_dry_run(data.get("dry_run", False))
    client_path   = data.get("path") if isinstance(data.get("path"), str) else None

    db = _get_db()
    # The photo is identified by its library id; the file path always comes
    # from the library row (a supplied path must match it).
    row, filepath = get_photo(db, data.get("id"), client_path)
    photo_id = row["id"]

    if dry_run:
        _log(f"[dry-run] Would write: {filepath}")
        for field, new_val in [("location_name",location_name),
                                ("lat",lat),("lon",lon),("date_taken",date_str),
                                ("rotate_degrees", rotate_deg or None)]:
            if new_val is not None:
                # rotate_degrees has no photos.* column of its own (it's an
                # action, not a stored field) — row[field] would KeyError.
                old_val = row[field] if field in row.keys() else None
                db_save_pending(db, photo_id, field, old_val, new_val)
        db.commit()
        return jsonify({"ok":True,"dry_run":True})

    try:
        write_location_to_exif(filepath, location_name, lat, lon, date_str)
        if rotate_deg:
            rotate_image_file(filepath, rotate_deg)
        db.execute("""UPDATE photos SET location_name=?,lat=?,lon=?,date_taken=?,
                      has_gps=?,status=? WHERE id=?""",
                   (location_name, lat, lon, date_str,
                    1 if (lat is not None and lon is not None) else 0,
                    "gps" if (lat is not None and lon is not None) else ("named" if location_name else "unknown"),
                    photo_id))
        db.commit()
        return jsonify({"ok":True})
    except Exception as e:
        return jsonify({"error":safe_error(e)}), 500

@app.route("/api/save_batch", methods=["POST"])
def api_save_batch():
    data    = _json_body()
    photos  = data.get("photos",[])
    if not isinstance(photos, list):
        return jsonify({"error": "photos must be a list"}), 400
    dry_run = effective_dry_run(data.get("dry_run", False))
    db      = _get_db()
    results = []
    for p in photos:
        if not isinstance(p, dict):
            results.append({"id":None,"ok":False,"error":"invalid entry"})
            continue
        pid = p.get("id")
        try:
            # Every entry must name an existing library photo; its file path
            # comes from the library, never from the request.
            row, filepath = get_photo(db, pid, p.get("path") if isinstance(p.get("path"), str) else None)
            location_name = clean_text(p.get("location_name"), "location_name", 1000)
            lat = clean_coord(p.get("lat"), "lat", 90)
            lon = clean_coord(p.get("lon"), "lon", 180)
            date_taken = clean_date(p.get("date_taken"))
        except (PhotoNotFound, PathNotAllowed, BadInput, OSError) as e:
            results.append({"id":pid,"ok":False,"error":safe_error(e)})
            continue
        if dry_run:
            _log(f"[dry-run] Would write: {filepath}")
            for field, new_val in [("location_name",location_name),
                                    ("lat",lat),("lon",lon),
                                    ("date_taken",date_taken)]:
                if new_val is not None:
                    db_save_pending(db, pid, field, row[field], new_val)
            results.append({"id":pid,"ok":True,"dry_run":True})
        else:
            try:
                write_location_to_exif(filepath, location_name, lat, lon, date_taken)
                db.execute("""UPDATE photos SET location_name=?,lat=?,lon=?,
                              has_gps=?,status=? WHERE id=?""",
                           (location_name, lat, lon,
                            1 if (lat is not None and lon is not None) else 0,
                            "gps" if (lat is not None and lon is not None)
                            else ("named" if location_name else "unknown"),
                            pid))
                results.append({"id":pid,"ok":True})
            except Exception as e:
                results.append({"id":pid,"ok":False,"error":safe_error(e)})
    db.commit()
    return jsonify({"results":results,"dry_run":dry_run})

# ── Thumbnail ─────────────────────────────────────────────────────
@app.route("/api/thumbnail")
def api_thumbnail():
    """
    Every grid render, scroll, and duplicate-group view was decoding the
    full-resolution source image and re-encoding a JPEG from scratch, on
    every single request — with a library of any size and a browser that
    doesn't cache the response (no Cache-Control was ever sent), the same
    photo gets fully re-decoded over and over just scrolling around.

    Cached to disk, one file per (path, size): keying on path+size only
    (not mtime) means a rotate/EXIF-write that changes mtime overwrites
    that same cache file in place via os.replace() rather than leaving the
    old version behind as an orphan — cache footprint stays proportional to
    "distinct photos x thumbnail sizes actually requested", not to how many
    times a photo has ever been touched. Freshness is just "is the cached
    file newer than the source file" — no separate metadata store needed.
    """
    photo_id = request.args.get("id", "")
    try:
        size = int(request.args.get("size", 280))
    except ValueError:
        size = None
    if size not in THUMB_SIZES:
        return jsonify({"error": f"size must be one of {sorted(THUMB_SIZES)}"}), 400
    try:
        _, filepath = get_photo(_get_db(), photo_id)
        src_mtime = os.path.getmtime(filepath)
    except PhotoNotFound:
        return "", 404
    except (PathNotAllowed, FileNotFoundError):
        return "", 404
    except OSError as e:
        return safe_error(e), 500

    cache_key = hashlib.md5(f"{filepath}|{size}".encode("utf-8")).hexdigest()
    cache_path = THUMB_CACHE_DIR / f"{cache_key}.jpg"
    try:
        if cache_path.is_file() and cache_path.stat().st_mtime >= src_mtime:
            # Bump mtime so eviction (oldest first) approximates LRU. Still
            # >= src_mtime, so the freshness check above is unaffected.
            with contextlib.suppress(OSError):
                os.utime(cache_path)
            return send_file(cache_path, mimetype="image/jpeg",
                              max_age=31536000, conditional=True)
    except OSError:
        pass  # cache file vanished between the is_file() and stat() checks — fall through and regenerate

    # Full-size decodes are the expensive, memory-hungry part; a fast scroll
    # through a big grid used to start one per visible card all at once.
    if not _thumb_semaphore.acquire(timeout=30):
        return jsonify({"error": "Thumbnail generator busy"}), 503
    THUMB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    # Write to a per-request unique temp name and rename into place: two
    # requests for the same never-before-cached thumbnail racing each
    # other must not let one see the other's half-written file.
    tmp_path = cache_path.with_name(f"{cache_key}.{uuid.uuid4().hex}.tmp")
    try:
        with Image.open(filepath) as img:
            img.draft("RGB", (size, size))  # JPEG: decode at reduced scale, much cheaper
            img.thumbnail((size,size), Image.LANCZOS)
            img.convert("RGB").save(tmp_path, "JPEG", quality=75)
        os.replace(tmp_path, cache_path)
        _thumb_cache_note_write(cache_path)
        return send_file(cache_path, mimetype="image/jpeg",
                          max_age=31536000, conditional=True)
    except Exception as e:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        return safe_error(e), 500
    finally:
        _thumb_semaphore.release()

_thumb_semaphore = threading.BoundedSemaphore(THUMB_WORKERS)
_thumb_cache_lock = threading.Lock()
_thumb_cache_bytes = None   # running estimate; None until the first full count
_thumb_evicting = threading.Lock()

def _thumb_cache_note_write(path):
    global _thumb_cache_bytes
    if THUMB_CACHE_MAX_MB <= 0:
        return
    with contextlib.suppress(OSError):
        n = path.stat().st_size
        with _thumb_cache_lock:
            if _thumb_cache_bytes is not None:
                _thumb_cache_bytes += n
            over = _thumb_cache_bytes is None or _thumb_cache_bytes > THUMB_CACHE_MAX_MB * 1024 * 1024
        if over:
            evict_thumb_cache()

def evict_thumb_cache():
    """Trim the thumbnail cache to 80% of THUMB_CACHE_MAX_MB, oldest
    (least recently served) first. Also clears temp files orphaned by a
    crash. Single-flight: concurrent callers just skip."""
    global _thumb_cache_bytes
    if THUMB_CACHE_MAX_MB <= 0 or not _thumb_evicting.acquire(blocking=False):
        return
    try:
        cap = THUMB_CACHE_MAX_MB * 1024 * 1024
        entries, total, now = [], 0, time.time()
        if THUMB_CACHE_DIR.is_dir():
            for e in os.scandir(THUMB_CACHE_DIR):
                with contextlib.suppress(OSError):
                    st = e.stat()
                    if e.name.endswith(".tmp"):
                        if now - st.st_mtime > 3600:
                            os.unlink(e.path)
                        continue
                    entries.append((st.st_mtime, st.st_size, e.path))
                    total += st.st_size
        if total > cap:
            target = int(cap * 0.8)
            entries.sort()
            removed = 0
            for _mtime, size, path in entries:
                if total <= target:
                    break
                with contextlib.suppress(OSError):
                    os.unlink(path)
                    total -= size
                    removed += 1
            _log(f"[thumbs] Cache over {THUMB_CACHE_MAX_MB} MB — evicted {removed} thumbnail(s)")
        with _thumb_cache_lock:
            _thumb_cache_bytes = total
    finally:
        _thumb_evicting.release()

# ── Duplicates ────────────────────────────────────────────────────
# ── Duplicates (background job) ───────────────────────────────────
# Previously this ran inline and re-parsed every hash inside an O(n^2) loop,
# which measured ~11 minutes on 5,900 photos with no progress feedback.
# Hashes are now compared as ints via XOR + bit_count: ~2s for the same set.

_dup_state = {"running": False, "phase": "", "current": 0, "total": 0,
              "message": "", "error": None, "folder": None, "result": None}
_dup_lock  = threading.Lock()

PHASH_THRESHOLD = 10  # max hamming distance out of 64 bits (DCT hash)
DHASH_THRESHOLD = 8   # max hamming distance out of 64 bits (gradient hash)

def _verified_exact_groups(rows):
    """
    Groups of files with identical contents. Files are only compared when
    their current on-disk sizes are equal, and only by a full-content
    SHA-256 (compute_file_sha256). A stored hash is reused only if it's a
    full SHA-256 computed from a file with exactly the current size and
    mtime; legacy partial hashes, or hashes of a file that has since been
    edited, are recomputed. Files that are missing, outside the allowed
    folders or changing while being read are left out rather than guessed.
    Mutates each grouped row's file_hash fields and persists new hashes.
    """
    from collections import defaultdict
    by_size = defaultdict(list)
    for r in rows:
        try:
            real = photo_real_path(r)
            st = os.stat(real)
        except (PathNotAllowed, OSError):
            continue
        r["_real"], r["_st"] = real, st
        by_size[st.st_size].append(r)
    candidates = [r for group in by_size.values() if len(group) > 1 for r in group]

    def need_hash(r):
        st = r["_st"]
        return not (r.get("file_hash_algo") == FILE_HASH_ALGO and r.get("file_hash")
                    and r.get("file_size") == st.st_size
                    and r.get("hash_mtime") is not None and abs(r["hash_mtime"] - st.st_mtime) < 1e-6)

    to_hash = [r for r in candidates if need_hash(r)]
    if to_hash:
        _log(f"[dup] Hashing {len(to_hash)} same-size file(s) in full (SHA-256)…")
        with _dup_lock:
            _dup_state.update(message=f"Verifying {len(to_hash)} same-size files (full SHA-256)…",
                              current=0, total=len(to_hash))

        def work(r):
            try:
                return r, compute_file_sha256(r["_real"]), None
            except OSError as e:
                return r, None, e
        conn = _connect_db()
        try:
            done = 0
            with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
                for r, result, err in pool.map(work, to_hash):
                    done += 1
                    if err is not None:
                        _log(f"[dup] Not comparing {r['filename']}: {safe_error(err)}")
                        r["file_hash"] = None
                    else:
                        digest, size, mtime = result
                        r.update(file_hash=digest, file_hash_algo=FILE_HASH_ALGO,
                                 file_size=size, hash_mtime=mtime)
                        conn.execute("""UPDATE photos SET file_hash=?, file_hash_algo=?,
                                        file_size=?, hash_mtime=? WHERE id=?""",
                                     (digest, FILE_HASH_ALGO, size, mtime, r["id"]))
                    if done % 50 == 0:
                        conn.commit()
                        with _dup_lock:
                            _dup_state.update(current=done)
            conn.commit()
        finally:
            conn.close()

    exact = defaultdict(list)
    for r in candidates:
        if r.get("file_hash_algo") == FILE_HASH_ALGO and r.get("file_hash"):
            exact[(r["file_size"], r["file_hash"])].append(r)
    for r in rows:
        r.pop("_real", None)
        r.pop("_st", None)
    return [list(group) for group in exact.values() if len(group) > 1]

def _run_dup_scan(folder):
    from collections import defaultdict
    try:
        with _dup_lock:
            _dup_state.update(phase="loading", message="Loading hashes from database…",
                              current=0, total=0)

        conn = _connect_db()
        rows = rows_to_dicts(conn.execute(
            "SELECT id,path,filename,folder,size_kb,date_taken,phash,dhash,file_hash,"
            "file_hash_algo,file_size,hash_mtime,status,location_name "
            "FROM photos WHERE scan_root=?", (folder,)).fetchall())
        conn.close()

        n = len(rows)
        _log(f"[dup] Loaded {n} photos for duplicate analysis")

        # ── 1. Exact duplicates: verified full-content SHA-256 ────────
        with _dup_lock:
            _dup_state.update(phase="exact", message="Finding identical files…", total=n)
        exact_groups = _verified_exact_groups(rows)
        _log(f"[dup] {len(exact_groups)} exact-duplicate groups (full SHA-256, equal size)")

        # ── 2. Filename-pattern duplicates: IMG_4502 vs IMG_4502 (1) ──
        with _dup_lock:
            _dup_state.update(phase="filenames", message="Checking filename patterns…")
        name_pattern = re.compile(r"^(.+?)(\s*\(\d+\))(\.[^.]+)$")
        fname = defaultdict(list)
        for r in rows:
            m = name_pattern.match(r["filename"])
            base = (m.group(1) + m.group(3)) if m else r["filename"]
            fname[base.lower()].append(r)
        fname_groups = [v for v in fname.values() if len(v) > 1]
        _log(f"[dup] {len(fname_groups)} filename-pattern groups")

        # ── 3. Perceptual near-duplicates ─────────────────────────────
        cand = [r for r in rows if r.get("phash") or r.get("dhash")]
        pints, dints, valid = [], [], []
        for r in cand:
            try:
                pv = int(r["phash"], 16) if r.get("phash") else None
                dv = int(r["dhash"], 16) if r.get("dhash") else None
            except (ValueError, TypeError):
                continue
            if pv is None and dv is None:
                continue
            pints.append(pv); dints.append(dv); valid.append(r)

        m = len(valid)
        with _dup_lock:
            _dup_state.update(phase="perceptual", total=m, current=0,
                              message=f"Comparing {m} image fingerprints…")
        _log(f"[dup] Comparing {m} perceptual hashes (threshold {PHASH_THRESHOLD})")

        used = [False] * m
        phash_groups = []
        for i in range(m):
            if i % 250 == 0:
                with _dup_lock:
                    _dup_state.update(current=i,
                        message=f"Comparing fingerprints: {i} / {m}")
            if used[i]:
                continue
            pa, da = pints[i], dints[i]
            group = None
            for j in range(i + 1, m):
                if used[j]:
                    continue
                pd = (pa ^ pints[j]).bit_count() if (pa is not None and pints[j] is not None) else 99
                dd = (da ^ dints[j]).bit_count() if (da is not None and dints[j] is not None) else 99
                # Either hash agreeing is enough — they fail on different inputs.
                if pd <= PHASH_THRESHOLD or dd <= DHASH_THRESHOLD:
                    best = min(pd, dd)
                    if group is None:
                        group = [dict(valid[i], similarity=100)]
                        used[i] = True
                    group.append(dict(valid[j], similarity=round((1 - best / 64) * 100),
                                      match_on=("dhash" if dd < pd else "phash")))
                    used[j] = True
            if group:
                phash_groups.append(group)

        _log(f"[dup] {len(phash_groups)} perceptual groups")

        # Don't report the same set twice under two headings
        exact_ids = {p["id"] for g in exact_groups for p in g}
        phash_groups = [g for g in phash_groups
                        if not all(p["id"] in exact_ids for p in g)]

        result = {
            "exact_groups":  exact_groups,
            "phash_groups":  phash_groups,
            "fname_groups":  fname_groups,
            "total_groups":  len(exact_groups) + len(phash_groups) + len(fname_groups),
            "scanned":       n,
        }
        with _dup_lock:
            _dup_state.update(running=False, phase="done", current=m,
                              message=f"Found {result['total_groups']} duplicate groups",
                              result=result, folder=folder)
        _log(f"[dup] Done. {result['total_groups']} groups total")

    except Exception as e:
        import traceback; traceback.print_exc()
        _log(f"[dup] ERROR: {e}")
        with _dup_lock:
            _dup_state.update(running=False, phase="error", error=str(e),
                              message=f"Error: {e}")

@app.route("/api/duplicates/start", methods=["POST"])
def api_duplicates_start():
    data = _json_body()
    folder = data.get("folder") if isinstance(data.get("folder"), str) else ""
    folder = folder.strip()
    force  = data.get("force", False) is True
    if not folder:
        return jsonify({"error": "folder required"}), 400
    with _dup_lock:
        if _dup_state["running"]:
            return jsonify({"started": False, "already_running": True})
        # Serve cached result for the same folder unless a refresh was asked for
        if not force and _dup_state["folder"] == folder and _dup_state["result"]:
            return jsonify({"started": False, "cached": True})
        _dup_state.update(running=True, phase="loading", current=0, total=0,
                          message="Starting…", error=None, folder=folder, result=None)
    threading.Thread(target=_run_dup_scan, args=(folder,), daemon=True).start()
    return jsonify({"started": True})

@app.route("/api/duplicates/progress")
def api_duplicates_progress():
    with _dup_lock:
        s = {k: v for k, v in _dup_state.items() if k != "result"}
        s["has_result"] = _dup_state["result"] is not None
    return jsonify(s)

@app.route("/api/duplicates/result")
def api_duplicates_result():
    with _dup_lock:
        if not _dup_state["result"]:
            return jsonify({"error": "No duplicate scan result available"}), 409
        return jsonify(_dup_state["result"])

def _move_to_duplicates_folder(db, row):
    """
    Move one photo's file (and its XMP sidecar, if any) into a
    _duplicates/<original subfolder>/ tree under its scan root, then drop
    its row from the library. This is a move, not a delete — nothing is
    destroyed, so a bad call is recoverable by hand from _duplicates/.
    Preserving the original subfolder avoids most collisions between
    same-named duplicates from different folders (often exactly *why*
    they're duplicates); a numeric suffix covers the rest, e.g. resolving
    the same group twice.
    """
    photo_real_path(row)
    src = Path(row["path"])
    if src.is_symlink():
        raise PathNotAllowed(f"Refusing to move a symlink: {src.name}")
    scan_root = resolve_allowed_path(row["scan_root"], kind="dir")
    dup_root = Path(scan_root) / "_duplicates"
    folder = row["folder"] or ""
    if folder in (".", ""):
        folder = ""
    if os.path.isabs(folder) or ".." in Path(folder).parts:
        raise PathNotAllowed(f"Unexpected folder value {folder!r}")
    dest_dir = dup_root / folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    # mkdir follows symlinks; make sure we're still inside _duplicates/.
    if not _is_within(_norm_real(dest_dir), _norm_real(dup_root)):
        raise PathNotAllowed(f"{dest_dir} resolves outside {dup_root}")
    sidecar = sidecar_path_for(src)
    move_sidecar = sidecar.exists() and not _sidecar_shared(src)
    # Pick a name free for BOTH the photo and (if it has one) its sidecar,
    # so an unrelated .xmp already in _duplicates/ is never overwritten.
    dest = dest_dir / src.name
    n = 1
    while os.path.lexists(dest) or (move_sidecar and os.path.lexists(dest.with_suffix(".xmp"))):
        dest = dest_dir / f"{src.stem} ({n}){src.suffix}"
        n += 1
        if n > 10000:
            raise FileExistsError(f"No free name for {src.name} in {dest_dir}")
    move_no_clobber(src, dest)
    if move_sidecar:
        try:
            move_no_clobber(sidecar, dest.with_suffix(".xmp"))
        except OSError:
            move_no_clobber(dest, src)  # keep photo and sidecar together
            raise
    db.execute("DELETE FROM photos WHERE id=?", (row["id"],))
    db.execute("DELETE FROM pending_changes WHERE photo_id=?", (row["id"],))

@app.route("/api/duplicates/resolve", methods=["POST"])
def api_duplicates_resolve():
    """
    Move every photo in move_ids to _duplicates/ (see
    _move_to_duplicates_folder) — the "keep" copy of each group is simply
    never included. Server-authoritative dry_run gate like every other
    write: with dry run on, each id is staged as a field='move_to_duplicates'
    pending change instead (reviewed and committed the normal way).
    """
    data = _json_body()
    move_ids = data.get("move_ids", [])
    dry_run = effective_dry_run(data.get("dry_run", False))
    if not move_ids or not isinstance(move_ids, list):
        return jsonify({"error": "move_ids required"}), 400
    db = _get_db()
    results = []
    for pid in move_ids:
        try:
            row, _ = get_photo(db, pid)
        except PhotoNotFound:
            results.append({"id": pid, "ok": False, "error": "not found"}); continue
        except (PathNotAllowed, OSError) as e:
            results.append({"id": pid, "ok": False, "error": safe_error(e)}); continue
        if dry_run:
            db_save_pending(db, pid, "move_to_duplicates", None, "1")
            results.append({"id": pid, "ok": True, "dry_run": True})
            continue
        try:
            _move_to_duplicates_folder(db, row)
            results.append({"id": pid, "ok": True})
        except Exception as e:
            results.append({"id": pid, "ok": False, "error": safe_error(e)})
    db.commit()
    return jsonify({"results": results, "dry_run": dry_run})

# ─── Location history import ───────────────────────────────────────────────
# Fills GPS gaps using an imported location history (Google Takeout
# Records.json, or a GPX track) instead of guessing from nearby photos or
# folder/filename text: it's ground truth about where the *person* was.
# This only ever produces suggestions (history_lat/lon + a time-gap on the
# photo row) — nothing is written to a file except through the normal
# dry-run → review → /api/save(_batch) path everything else already uses.
#
# Records.json can be 1GB+ with millions of points, so this never loads the
# whole file into memory: parsing is streamed (ijson), points are inserted
# in batches, and matching loads only compact array('d', ...) columns
# (~70MB for ~3M points, vs 300MB+ as plain Python floats/tuples) sorted by
# time for an O(log n) bisect per photo instead of an O(n) scan.

def _parse_takeout_json(filepath):
    """
    Google Takeout Records.json: {"locations": [{"latitudeE7":.., "longitudeE7":..,
    "timestamp":"...Z", ...possibly nested objects with their own "timestamp",
    e.g. "activity":[...]}, ...]}.

    ijson.items(f, "locations.item") reconstructs each array element as one
    complete Python dict before handing it back, so item["timestamp"] is
    unambiguously the record's own field — a nested "activity" sub-object's
    "timestamp" key never gets confused with it, unlike a naive text/regex
    scan would risk. Only one item is materialized in memory at a time.
    """
    with open(filepath, "rb") as f:
        for item in ijson.items(f, "locations.item"):
            ts_raw = item.get("timestamp")
            lat_e7 = item.get("latitudeE7")
            lon_e7 = item.get("longitudeE7")
            if ts_raw is None or lat_e7 is None or lon_e7 is None:
                continue
            try:
                dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                epoch = dt.timestamp()  # tz-aware -> exact epoch, independent of host TZ
            except (ValueError, TypeError):
                continue
            yield epoch, lat_e7 / 1e7, lon_e7 / 1e7

def _parse_gpx(filepath):
    """
    GPX track: <trkpt lat=".." lon=".."><time>...</time></trkpt>, one per
    recorded fix. Streamed with iterparse + per-point clearing so a large
    track doesn't build the whole XML tree in memory.
    """
    # GPX never needs a DTD; refusing one up front rules out entity-
    # expansion tricks regardless of the XML parser's own protections.
    with open(filepath, "rb") as f:
        head = f.read(64 * 1024)
    if re.search(rb"<!(DOCTYPE|ENTITY)", head, re.IGNORECASE):
        raise ValueError("GPX files with a DOCTYPE/ENTITY declaration are not accepted")
    for _event, elem in ET.iterparse(filepath, events=("end",)):
        tag = elem.tag.rsplit("}", 1)[-1]  # strip the GPX XML namespace
        if tag != "trkpt":
            continue
        lat, lon = elem.get("lat"), elem.get("lon")
        time_text = None
        for child in elem:
            if child.tag.rsplit("}", 1)[-1] == "time":
                time_text = child.text
                break
        if lat and lon and time_text:
            try:
                dt = datetime.fromisoformat(time_text.strip().replace("Z", "+00:00"))
                yield dt.timestamp(), float(lat), float(lon)
            except (ValueError, TypeError):
                pass
        elem.clear()

# Pluggable by file extension so another format can be added without
# touching the import job or the matching logic below.
LOCATION_PARSERS      = {".json": _parse_takeout_json, ".gpx": _parse_gpx}
LOCATION_SOURCE_LABEL = {".json": "google_takeout",    ".gpx": "gpx"}

def _wallclock_epoch(dt):
    """
    Epoch-like seconds from a naive datetime's literal wall-clock fields —
    NOT the host container's timezone (that's what plain .timestamp() on a
    naive datetime would use, which would make matches silently depend on
    how the container happens to be configured).

    EXIF dates have no timezone at all, so this is the best available
    without more metadata than the app has today: it compares the camera's
    wall-clock reading directly against the location history's wall-clock
    reading. That's exact if both are in the same zone (both UTC is the
    safe case) and off by a fixed offset otherwise.
    """
    return calendar.timegm(dt.timetuple())

def _insert_points_batch(conn, import_id, batch):
    conn.executemany(
        "INSERT INTO location_points (import_id, timestamp_epoch, lat, lon) VALUES (?,?,?,?)",
        [(import_id, ts, lat, lon) for ts, lat, lon in batch])

def _load_sorted_points(conn):
    """
    All imported points (across every import) as parallel array('d'/'q')
    columns sorted by time, for a bisect-based nearest-in-time lookup.
    Fetched in chunks rather than one big fetchall() to keep peak memory
    bounded even at millions of rows.
    """
    ts, lat, lon, imp = array("d"), array("d"), array("d"), array("q")
    cur = conn.execute(
        "SELECT timestamp_epoch, lat, lon, import_id FROM location_points ORDER BY timestamp_epoch")
    while True:
        rows = cur.fetchmany(20000)
        if not rows:
            break
        for r in rows:
            ts.append(r[0]); lat.append(r[1]); lon.append(r[2]); imp.append(r[3])
    return ts, lat, lon, imp

def _find_nearest_point(ts_arr, epoch):
    """Nearest point in time to `epoch`. Checks both neighbors around the
    bisect insertion point and returns (delta_seconds, index)."""
    n = len(ts_arr)
    if n == 0:
        return None, None
    i = bisect.bisect_left(ts_arr, epoch)
    candidates = [j for j in (i - 1, i) if 0 <= j < n]
    best = min(candidates, key=lambda j: abs(ts_arr[j] - epoch))
    return abs(ts_arr[best] - epoch), best

# ── Import job (background thread) ─────────────────────────────────
_hist_import_state = {"running": False, "phase": "", "current": 0, "total": 0,
                       "message": "", "error": None, "import_id": None}
_hist_import_lock  = threading.Lock()
_HIST_BATCH_SIZE   = 5000

def _run_history_import(import_id, filepath, ext, cleanup_path=None):
    conn = _connect_db()
    count = 0
    batch = []
    try:
        with _hist_import_lock:
            _hist_import_state.update(phase="parsing", message="Parsing…", current=0, total=0)
        for epoch, lat, lon in LOCATION_PARSERS[ext](filepath):
            batch.append((epoch, lat, lon))
            if len(batch) >= _HIST_BATCH_SIZE:
                _insert_points_batch(conn, import_id, batch)
                conn.commit()
                count += len(batch)
                batch = []
                with _hist_import_lock:
                    _hist_import_state.update(current=count, message=f"Imported {count:,} points…")
        if batch:
            _insert_points_batch(conn, import_id, batch)
            conn.commit()
            count += len(batch)

        conn.execute("UPDATE location_imports SET point_count=?, status='done' WHERE id=?",
                     (count, import_id))
        conn.commit()
        _log(f"[history] Import #{import_id} done: {count:,} points from {filepath}")
        with _hist_import_lock:
            _hist_import_state.update(running=False, phase="done", current=count, total=count,
                                       message=f"Imported {count:,} location points")
    except Exception as e:
        import traceback; traceback.print_exc()
        err = safe_error(e)
        conn.execute("UPDATE location_imports SET status='error', error=? WHERE id=?",
                     (err, import_id))
        conn.commit()
        _log(f"[history] Import #{import_id} FAILED: {err}")
        with _hist_import_lock:
            _hist_import_state.update(running=False, phase="error", error=err, message=f"Error: {err}")
    finally:
        conn.close()
        if cleanup_path:
            try: os.remove(cleanup_path)
            except OSError: pass

# ── Matching job (background thread) ───────────────────────────────
_hist_match_state = {"running": False, "phase": "", "current": 0, "total": 0,
                      "message": "", "error": None, "result": None}
_hist_match_lock  = threading.Lock()

def _run_history_match(folder, tolerance_minutes):
    conn = _connect_db()
    try:
        with _hist_match_lock:
            _hist_match_state.update(phase="loading", message="Loading location history…",
                                      current=0, total=0)
        ts_arr, lat_arr, lon_arr, imp_arr = _load_sorted_points(conn)
        if not ts_arr:
            with _hist_match_lock:
                _hist_match_state.update(running=False, phase="done",
                    message="No location history imported yet.",
                    result={"matched": 0, "candidates": 0})
            return

        # Eligible = no embedded GPS and no confirmed name yet. This also
        # covers photos currently 'inferred' from a sibling-photo cluster —
        # a history match is ground truth about the *person*, not a guess
        # from nearby files, so it's allowed to supersede that weaker guess.
        rows = rows_to_dicts(conn.execute("""
            SELECT id, date_taken FROM photos
            WHERE scan_root=? AND has_gps=0
              AND (location_name IS NULL OR location_name='')
              AND date_taken IS NOT NULL
        """, (folder,)).fetchall())

        tol_seconds = tolerance_minutes * 60
        total = len(rows)
        matched = 0
        with _hist_match_lock:
            _hist_match_state.update(phase="matching", total=total, current=0,
                                      message=f"Matching {total} candidate photos…")

        for i, row in enumerate(rows):
            try:
                dt = datetime.fromisoformat(row["date_taken"])
            except ValueError:
                continue
            delta, idx = _find_nearest_point(ts_arr, _wallclock_epoch(dt))
            if delta is not None and delta <= tol_seconds:
                conn.execute("""UPDATE photos SET history_lat=?, history_lon=?,
                    history_delta_min=?, history_import_id=?, status='history' WHERE id=?""",
                    (lat_arr[idx], lon_arr[idx], round(delta / 60), imp_arr[idx], row["id"]))
                matched += 1
            if i % 200 == 0:
                conn.commit()
                with _hist_match_lock:
                    _hist_match_state.update(current=i + 1,
                        message=f"Matching: {i+1}/{total} ({matched} matched so far)")
        conn.commit()
        _log(f"[history] Match done: {matched}/{total} within {tolerance_minutes} min")
        with _hist_match_lock:
            _hist_match_state.update(running=False, phase="done", current=total, total=total,
                message=f"Matched {matched} of {total} candidate photos",
                result={"matched": matched, "candidates": total})
    except Exception as e:
        import traceback; traceback.print_exc()
        _log(f"[history] Match ERROR: {e}")
        with _hist_match_lock:
            _hist_match_state.update(running=False, phase="error", error=str(e), message=f"Error: {e}")
    finally:
        conn.close()

# ── Routes ────────────────────────────────────────────────────────
@app.route("/api/history/imports")
def api_history_imports():
    db = _get_db()
    rows = db.execute("SELECT * FROM location_imports ORDER BY imported_at DESC").fetchall()
    total_points = db.execute("SELECT COUNT(*) c FROM location_points").fetchone()["c"]
    return jsonify({"imports": rows_to_dicts(rows), "total_points": total_points})

def _prepare_history_source():
    """Returns (filepath, ext, source_name, cleanup_path) or raises
    BadInput / PathNotAllowed / FileNotFoundError."""
    upload = request.files.get("file")
    if upload and upload.filename:
        source_name = clean_text(Path(upload.filename).name, "filename", 255) or "upload"
        ext = Path(source_name).suffix.lower()
        if ext not in LOCATION_PARSERS:
            raise BadInput(f"Unsupported file type: {ext or '(none)'}")
        UPLOAD_TMP_DIR.mkdir(parents=True, exist_ok=True)
        # Unique per upload — two uploads in the same second used to share
        # one upload_<seconds>.<ext> name and overwrite each other.
        filepath = str(UPLOAD_TMP_DIR / f"upload_{uuid.uuid4().hex}{ext}")
        spool = upload.stream
        spool_name = getattr(spool, "name", None)
        spools = g.get("_upload_spools", [])
        if isinstance(spool_name, str) and any(f is spool for f in spools):
            # Already on disk in the data volume (see _PhotoTaggerRequest):
            # claim it by renaming instead of copying it a second time.
            spool.close()
            os.replace(spool_name, filepath)
            spools.remove(spool)
        else:
            try:
                upload.save(filepath)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(filepath)
                raise
        return filepath, ext, source_name, filepath
    data = request.form or request.get_json(silent=True) or {}
    path = data.get("path") if isinstance(data.get("path"), str) else ""
    path = path.strip()
    if not path:
        raise BadInput("Provide a file upload or a server-side path")
    ext = Path(path).suffix.lower()
    if ext not in LOCATION_PARSERS:
        raise BadInput(f"Unsupported file type: {ext or '(none)'}")
    real = resolve_allowed_path(path, kind="file", extra_roots=HISTORY_IMPORT_ROOTS)
    if Path(real).suffix.lower() != ext:
        raise BadInput("Unsupported file type")
    return real, ext, Path(path).name, None

@app.route("/api/history/import", methods=["POST"])
def api_history_import():
    # Reserve the single import slot BEFORE reading the (possibly huge)
    # request body. Previously the check and the "running" flag were set
    # minutes apart (around the upload), so two concurrent uploads could
    # both pass the check and run at once.
    with _hist_import_lock:
        if _hist_import_state["running"]:
            return jsonify({"error": "An import is already running"}), 409
        _hist_import_state.update(running=True, phase="uploading", current=0, total=0,
                                   message="Receiving file…", error=None, import_id=None)
    cleanup_path = None
    try:
        filepath, ext, source_name, cleanup_path = _prepare_history_source()
        db = _get_db()
        cur = db.execute("INSERT INTO location_imports (source_name, source_type, status) VALUES (?,?,'importing')",
                          (source_name, LOCATION_SOURCE_LABEL[ext]))
        db.commit()
        import_id = cur.lastrowid
        with _hist_import_lock:
            _hist_import_state.update(phase="starting", message="Starting import…", import_id=import_id)
        threading.Thread(target=_run_history_import,
                          args=(import_id, filepath, ext, cleanup_path), daemon=True).start()
        return jsonify({"started": True, "import_id": import_id})
    except BaseException as e:
        # Anything short of a started job releases the slot and removes
        # whatever was written for this upload.
        if cleanup_path:
            with contextlib.suppress(OSError):
                os.unlink(cleanup_path)
        with _hist_import_lock:
            _hist_import_state.update(running=False, phase="", message="", error=None)
        if isinstance(e, (BadInput, PathNotAllowed, FileNotFoundError)):
            status = 403 if isinstance(e, PathNotAllowed) else 400
            return jsonify({"error": safe_error(e)}), status
        raise

@app.route("/api/history/import_progress")
def api_history_import_progress():
    with _hist_import_lock:
        return jsonify(dict(_hist_import_state))

@app.route("/api/history/imports/<int:import_id>", methods=["DELETE"])
def api_delete_history_import(import_id):
    db = _get_db()
    # A removed import invalidates any suggestion it produced — reset those
    # photos rather than leaving a 'history' status backed by nothing.
    db.execute("""UPDATE photos SET history_lat=NULL, history_lon=NULL,
                  history_delta_min=NULL, history_import_id=NULL,
                  status=CASE WHEN status='history' THEN 'unknown' ELSE status END
                  WHERE history_import_id=?""", (import_id,))
    db.execute("DELETE FROM location_points WHERE import_id=?", (import_id,))
    db.execute("DELETE FROM location_imports WHERE id=?", (import_id,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/history/match", methods=["POST"])
def api_history_match():
    data = _json_body()
    folder = data.get("folder") if isinstance(data.get("folder"), str) else ""
    folder = folder.strip()
    try:
        tolerance = min(7 * 24 * 60, max(1, int(data.get("tolerance_minutes", 60))))
    except (TypeError, ValueError):
        tolerance = 60
    if not folder:
        return jsonify({"error": "folder required"}), 400
    with _hist_match_lock:
        if _hist_match_state["running"]:
            return jsonify({"error": "A match run is already in progress"}), 409
        _hist_match_state.update(running=True, phase="starting", current=0, total=0,
                                  message="Starting…", error=None, result=None)
    threading.Thread(target=_run_history_match, args=(folder, tolerance), daemon=True).start()
    return jsonify({"started": True})

@app.route("/api/history/match_progress")
def api_history_match_progress():
    with _hist_match_lock:
        return jsonify(dict(_hist_match_state))

# ── On-demand nearest-in-time infer ────────────────────────────────
@app.route("/api/infer_nearby", methods=["POST"])
def api_infer_nearby():
    data   = _json_body()
    folder = data.get("scan_root")
    if not folder or not isinstance(folder, str):
        return jsonify({"error":"scan_root required"}), 400
    db = _get_db()
    # Snapshot statuses before the pass so the response can report only
    # photos that just flipped to 'inferred' just now — not every
    # already-inferred photo from a previous scan or a previous click.
    before = {r["id"]: r["status"] for r in db.execute(
        "SELECT id,status FROM photos WHERE scan_root=?", (folder,))}
    _infer_locations(db, folder)
    db.commit()
    rows = rows_to_dicts(db.execute(
        """SELECT id,inferred_lat,inferred_lon,inferred_from,inferred_delta_min,status,location_name
           FROM photos WHERE scan_root=? AND status='inferred'""", (folder,)).fetchall())
    changed = [r for r in rows if before.get(r["id"]) != "inferred"]
    return jsonify({"ok":True, "count":len(changed), "photos":changed})

# ── AI infer ──────────────────────────────────────────────────────
# Both AI-suggest endpoints below used to be pure text: "You have NO access
# to any image files or photos" was the literal prompt, and the whole guess
# came from filename/folder/date/neighbor patterns. That's a real
# limitation — a folder full of "IMG_1234.jpg" files with no naming
# convention gave it nothing to work with no matter how it reasoned. Both
# now actually attach the photo, downscaled the same way the app's own
# thumbnails are (no reason to ship a full-resolution original for a
# question the model answers just as well from ~1024px), and fall back to
# the original text-only behavior if the file can't be decoded (RAW
# formats aren't Pillow-native — same limitation /api/thumbnail already
# has) rather than failing the request outright.
def _encode_photo_for_ai(path, max_dim=1024):
    """path must already be validated (get_photo)."""
    try:
        if os.path.getsize(path) > AI_MAX_IMAGE_MB * 1024 * 1024:
            _log(f"[ai] {Path(path).name} is larger than AI_MAX_IMAGE_MB — sending text only")
            return None
        with Image.open(path) as img:
            img.draft("RGB", (max_dim, max_dim))
            img = ImageOps.exif_transpose(img)  # a sideways-looking photo is a bad look-at-the-image clue
            img.thumbnail((max_dim, max_dim), Image.LANCZOS)
            buf = io.BytesIO()
            img.convert("RGB").save(buf, "JPEG", quality=85)
        return base64.standard_b64encode(buf.getvalue()).decode("ascii")
    except Exception as e:
        _log(f"[ai] Could not decode {path} for vision, falling back to text-only: {e}")
        return None

def _ai_image_block(b64):
    return {"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":b64}}

def _ai_text(value, limit=200):
    """Client-supplied context for a prompt: plain, short, single-line."""
    if value is None:
        return ""
    return _CONTROL_CHARS_RE.sub("", str(value)).replace("\n", " ")[:limit]

class _AiBusy(Exception):
    pass

class _AiLimit(Exception):
    pass

def _ai_call(content):
    """
    One provider call under the cost controls: a concurrency slot first,
    then a quota unit reserved atomically, then the request. The unit is
    given back only when the provider demonstrably didn't do the work (it
    returned an error status, or we never reached it); a timeout or other
    ambiguous failure keeps it counted, since it may still be billed.
    """
    import anthropic
    if not _ai_semaphore.acquire(timeout=20):
        raise _AiBusy()
    try:
        # Built before reserving: a missing/invalid key configuration fails
        # here without consuming any of today's allowance.
        client = anthropic.Anthropic(timeout=AI_TIMEOUT_SECONDS, max_retries=1)
        reserved = _ai_reserve()
        if reserved is None:
            raise _AiLimit()
        try:
            msg = client.messages.create(
                model=get_ai_model(), max_tokens=30,
                messages=[{"role":"user","content":content}])
        except anthropic.APIStatusError:
            _ai_release(reserved)
            raise
        except anthropic.APITimeoutError:
            raise
        except anthropic.APIConnectionError:
            _ai_release(reserved)
            raise
        return msg.content[0].text.strip()
    finally:
        _ai_semaphore.release()

def _ai_error_response(e):
    if isinstance(e, _AiBusy):
        return jsonify({"error": "Too many AI requests at once — try again in a moment", "busy": True}), 429
    if isinstance(e, _AiLimit):
        return jsonify({"error": f"Daily AI limit of {AI_DAILY_LIMIT} reached.", "limit_reached": True}), 429
    _log(f"[ai] Request failed: {type(e).__name__}: {safe_error(e)}")
    return jsonify({"error": safe_error(e)}), 502

def _ai_photo(db, photo):
    """The photo the AI is asked about, resolved from its library id. The
    image is loaded from the library's own path — never one the client
    named. The date may be a not-yet-saved suggestion, so it's taken from
    the request (as text)."""
    if not isinstance(photo, dict):
        raise BadInput("photo must be an object")
    row, real_path = get_photo(db, photo.get("id"))
    return row, real_path, _ai_text(photo.get("date_taken") or row["date_taken"], 40)

@app.route("/api/ai_infer", methods=["POST"])
def api_ai_infer():
    data      = _json_body()
    row, real_path, date_taken = _ai_photo(_get_db(), data.get("photo"))
    neighbors = data.get("neighbors") if isinstance(data.get("neighbors"), list) else []
    lines = []
    if date_taken:      lines.append(f"Photo taken: {date_taken}")
    if row["folder"]:   lines.append(f"Folder: {_ai_text(row['folder'])}")
    if row["filename"]: lines.append(f"Filename: {_ai_text(row['filename'])}")
    neighbors = [n for n in neighbors if isinstance(n, dict)][:6]
    if neighbors:
        lines.append("\nNearby photos with known locations:")
        for n in neighbors:
            lines.append(f"  - {_ai_text(n.get('filename'))}: {_ai_text(n.get('location_name'))} "
                         f"({_ai_text(n.get('date_taken'), 40)})")
    b64 = _encode_photo_for_ai(real_path)
    if b64:
        prompt = (
            "Look at this photo and suggest where it was most likely taken. Use whatever's "
            "visible — landmarks, architecture, signage or text, vegetation, terrain, road "
            "signs, license plates, flags — together with the filename/folder/date/nearby-photo "
            "metadata below, which may add useful context (or may just be an uninformative "
            "camera-assigned name — don't let it override strong visual evidence). "
            "Be as SPECIFIC as you can confidently be: if you recognize a landmark, monument, "
            "building, or named venue, name it (e.g. 'Lincoln Memorial, Washington, DC, USA'), "
            "not just the city — a specific, correctly-geocodable name is what lets this get "
            "pinned at the actual place instead of just the city center. Fall back to city, "
            "country only when nothing more specific is identifiable. "
            "Reply with ONLY the location name, or 'Unknown' if you "
            "genuinely can't tell even from the image. No explanation, no hedging, no mention "
            "of photos or images.\n\n" + "\n".join(lines)
        )
        content = [_ai_image_block(b64), {"type":"text","text":prompt}]
    else:
        prompt = (
            "You are a metadata assistant. The photo file couldn't be read, so you have NO "
            "access to any image content — work only from the text metadata below.\n\n"
            "Based only on the filename, folder name, date, and nearby photos listed, "
            "suggest the most likely location. Reply with ONLY the location name "
            "(city, country format — there's no landmark-level signal available from text "
            "metadata alone), or 'Unknown' if you genuinely cannot guess. "
            "No explanation, no hedging, no mention of photos or images.\n\n"
            + "\n".join(lines)
        )
        content = prompt
    try:
        suggestion = _ai_call(content)[:300]
    except Exception as e:
        return _ai_error_response(e)
    usage = _ai_usage_info()
    _log(f"[ai] {row['filename']} → {suggestion} ({usage['used']}/{usage['limit']})")
    return jsonify({"suggestion":suggestion,"ai_usage":usage})

@app.route("/api/ai_infer_with_coords", methods=["POST"])
def api_ai_infer_with_coords():
    data          = _json_body()
    row, real_path, date_taken = _ai_photo(_get_db(), data.get("photo"))
    seed_lat      = clean_coord(data.get("seed_lat"), "seed_lat", 90)
    seed_lon      = clean_coord(data.get("seed_lon"), "seed_lon", 180)
    seed_location = _ai_text(data.get("seed_location"), 300)
    lines = [
        f"Seed location (manually pinned by user): {seed_location} (GPS: {seed_lat}, {seed_lon})",
        f"Photo filename: {_ai_text(row['filename']) or 'unknown'}",
        f"Folder: {_ai_text(row['folder']) or 'unknown'}",
    ]
    if date_taken:
        lines.append(f"Date taken: {date_taken}")
    b64 = _encode_photo_for_ai(real_path)
    if b64:
        prompt = (
            "A user manually pinned a location on a map for one photo in a folder, and wants "
            "it applied to this photo too. Look at the image: does it plausibly belong at that "
            "seed location, or does what you actually see (indoors vs. outdoors, landscape vs. "
            "cityscape, climate/vegetation, any visible landmarks or signage) suggest otherwise? "
            "Combine that with the filename/folder/date metadata below. If the seed location "
            "looks right, return it as-is; if the photo clearly doesn't match it (and you can "
            "tell where it actually is instead), return your own answer instead — as specific "
            "as you can confidently be (a landmark/building/venue name, e.g. 'Eiffel Tower, "
            "Paris, France', not just the city, when one is recognizable). "
            "Reply with ONLY the location name. "
            "No explanation, no hedging, no mention of photos or images.\n\n"
            + "\n".join(lines)
        )
        content = [_ai_image_block(b64), {"type":"text","text":prompt}]
    else:
        prompt = (
            "You are a metadata assistant. The photo file couldn't be read, so you have NO "
            "access to any image content — work only from the text metadata below.\n\n"
            "A user manually pinned a location on a map for one photo in a folder. "
            "Based only on the seed location and the filename/folder/date metadata below, "
            "return the most likely location name for this photo. "
            "If the seed location is reasonable, just return it as-is. "
            "Reply with ONLY the location name (e.g. 'Paris, France'). "
            "No explanation, no hedging, no mention of photos or images.\n\n"
            + "\n".join(lines)
        )
        content = prompt
    try:
        location_name = _ai_call(content)
    except Exception as e:
        return _ai_error_response(e)
    # Reject any response that sounds like an apology/explanation
    if len(location_name) > 60 or any(w in location_name.lower() for w in
            ("i don't","i cannot","i'm unable","no access","image file","photo file")):
        location_name = seed_location  # fall back to seed
    usage = _ai_usage_info()
    _log(f"[ai-seed] {row['filename']} → {location_name}")
    return jsonify({"location_name":location_name,"ai_usage":usage})

@app.route("/api/ai_usage")
def api_ai_usage():
    return jsonify(_ai_usage_info())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
