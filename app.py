import os
import re
import sys
import time
import json
import base64
import bisect
import shutil
import calendar
import hashlib
import sqlite3
import threading
import contextlib
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from array import array
from collections import deque
from pathlib import Path
from datetime import datetime

import ijson
import exifread
import piexif
import imagehash
import requests
from flask import Flask, jsonify, request, send_file, render_template, g
from PIL import Image, ImageOps

app = Flask(__name__)

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

class _TeeStream:
    """Writes through to the real stream and also appends whole lines to
    the in-memory log buffer, so the UI can tail server output."""
    def __init__(self, real_stream, level):
        self._real = real_stream
        self._level = level
        self._partial = ""
        self._partial_lock = threading.Lock()

    def write(self, data):
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
GEOCODE_DELAY      = 1.1
_EPOCH = datetime(1970, 1, 1)  # fixed reference point for turning a naive date_taken into a sortable float
DEFAULT_PHOTO_ROOT = os.environ.get("PHOTO_ROOT", "/photos")
AI_DAILY_LIMIT     = int(os.environ.get("AI_DAILY_LIMIT", "50"))
AI_MODEL           = os.environ.get("AI_MODEL", "claude-haiku-4-5")
DB_PATH            = os.environ.get("DB_PATH", "/app/data/phototagger.db")
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
# The container now starts as root (see Dockerfile) specifically so this can
# work: we create/own the data dir as root, then drop to the requested
# uid/gid before Flask ever touches a file. /photos is a host bind mount —
# its ownership is the host's responsibility, so it's deliberately not
# chowned here (that could take a long time and rewrite a whole library).
_puid = int(os.environ.get("PUID", 0))
_pgid = int(os.environ.get("PGID", 0))
if _puid and _pgid and hasattr(os, "geteuid") and os.geteuid() == 0:
    try:
        data_dir = Path(os.environ.get("DB_PATH", "/app/data/phototagger.db")).parent
        data_dir.mkdir(parents=True, exist_ok=True)

        before = data_dir.stat()
        print(f"[startup] {data_dir} currently owned by uid={before.st_uid} "
              f"gid={before.st_gid} — target is uid={_puid} gid={_pgid}", flush=True)

        # Re-own the directory AND anything already in it (e.g. a db file
        # left over from a previous PUID/PGID, or from before this uid/gid
        # drop existed at all) — chowning just the directory entry leaves
        # existing files owned by whoever created them, and the dropped-
        # privilege process then can't write to them ("attempt to write a
        # readonly database" from sqlite is the classic symptom of that).
        os.chown(data_dir, _puid, _pgid)
        children = list(data_dir.rglob("*"))
        for child in children:
            os.chown(child, _puid, _pgid)

        after = data_dir.stat()
        print(f"[startup] {data_dir} and {len(children)} existing file(s) now "
              f"owned by uid={after.st_uid} gid={after.st_gid}", flush=True)

        os.setgid(_pgid)
        os.setuid(_puid)
        print(f"[startup] Dropped privileges to uid={_puid} gid={_pgid}", flush=True)
    except (OSError, AttributeError) as e:
        print(f"[startup] WARNING: could not drop privileges to "
              f"{_puid}:{_pgid}: {e} — continuing as current user", flush=True)

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
            file_hash       TEXT,               -- md5 of first 64KB (fast)
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
                      ("shutter", "TEXT"), ("iso", "TEXT"), ("focal_length", "TEXT")]:
        if col not in existing:
            conn.execute(f"ALTER TABLE photos ADD COLUMN {col} {ddl}")
            print(f"[db] Migrated: added photos.{col}", flush=True)
    conn.commit()
    conn.close()
    print(f"[db] Initialised at {DB_PATH}", flush=True)

init_db()

# ─── DB helpers ───────────────────────────────────────────────────────────────

def db_upsert_photo(conn, photo: dict):
    conn.execute("""
        INSERT INTO photos (
            id, path, filename, folder, size_kb, file_mtime,
            date_taken, lat, lon, location_name, has_gps, status,
            phash, dhash, file_hash, inferred_lat, inferred_lon,
            inferred_from, inferred_delta_min, scan_root, last_scanned, date_source,
            camera, lens, aperture, shutter, iso, focal_length
        ) VALUES (
            :id,:path,:filename,:folder,:size_kb,:file_mtime,
            :date_taken,:lat,:lon,:location_name,:has_gps,:status,
            :phash,:dhash,:file_hash,:inferred_lat,:inferred_lon,
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
            phash=excluded.phash, dhash=excluded.dhash, file_hash=excluded.file_hash,
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
        "phash":None,"dhash":None,"file_hash":None,"date_source":None,
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
    rolls over on the next _ai_increment()."""
    today = datetime.now().date().isoformat()
    stored_date = get_setting("ai_usage_date")
    if stored_date != today:
        return today, 0
    return today, int(get_setting("ai_usage_count", "0") or 0)

def _ai_allowed():
    with _ai_lock:
        _, count = _ai_load_usage()
        if count >= AI_DAILY_LIMIT:
            return False, f"Daily AI limit of {AI_DAILY_LIMIT} reached."
        return True, ""

def _ai_increment():
    with _ai_lock:
        today, count = _ai_load_usage()
        set_setting("ai_usage_date", today)
        set_setting("ai_usage_count", str(count + 1))

def _ai_usage_info():
    with _ai_lock:
        _, count = _ai_load_usage()
        return {"used":count,"limit":AI_DAILY_LIMIT,"remaining":max(0,AI_DAILY_LIMIT-count)}

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

def compute_hashes(filepath):
    """
    Return (file_hash, phash_str, dhash_str).
    Two perceptual hashes are computed because they fail in different ways:
    phash (DCT) is strong on general perceptual similarity but weak on
    high-frequency/noisy images; dhash (gradient) is strong on structure and
    robust to brightness and resize. Matching on either catches far more
    real-world duplicates than one alone.
    """
    file_hash = phash_str = dhash_str = None
    try:
        with open(filepath,"rb") as f:
            file_hash = hashlib.md5(f.read(65536)).hexdigest()
    except Exception: pass
    try:
        img = Image.open(filepath)
        phash_str = str(imagehash.phash(img))
        dhash_str = str(imagehash.dhash(img))
    except Exception: pass
    return file_hash, phash_str, dhash_str

def _geocode_throttle():
    """Nominatim's usage policy caps anonymous use at ~1 req/sec — every
    call that hits it (reverse or forward) goes through this one gate
    so the limit holds regardless of which endpoint is calling."""
    global _last_geocode
    with _geocode_lock:
        wait = GEOCODE_DELAY - (time.time() - _last_geocode)
        if wait > 0: time.sleep(wait)
        _last_geocode = time.time()

def reverse_geocode(lat, lon):
    _geocode_throttle()
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
            params={"lat":lat,"lon":lon,"format":"json","zoom":14},
            headers={"User-Agent":"PhotoTagger/1.0"}, timeout=10)
        addr = r.json().get("address",{})
        parts = []
        for key in ("city","town","village","municipality","county"):
            if key in addr: parts.append(addr[key]); break
        if "country" in addr: parts.append(addr["country"])
        return ", ".join(parts) if parts else r.json().get("display_name","")
    except Exception: return None

def forward_geocode_search(query, limit=5):
    """Address/place-name -> candidate list of {name,lat,lon}, for the map
    picker's search box. Nominatim's free-text /search endpoint, not the
    /reverse one reverse_geocode() uses."""
    _geocode_throttle()
    try:
        r = requests.get("https://nominatim.openstreetmap.org/search",
            params={"q":query,"format":"json","limit":limit},
            headers={"User-Agent":"PhotoTagger/1.0"}, timeout=10)
        return [{"name":x.get("display_name",""),
                  "lat":float(x["lat"]),"lon":float(x["lon"])}
                for x in r.json()]
    except Exception:
        return None

def write_location_to_exif(filepath, location_name, lat=None, lon=None, date_str=None):
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
    try:
        exif_dict = piexif.load(filepath)
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
    piexif.insert(piexif.dump(exif_dict), filepath)

def _write_xmp_sidecar(filepath, location_name, lat=None, lon=None, date_str=None):
    sidecar = Path(filepath).with_suffix(".xmp")
    lat_s = f"{abs(lat):.6f}" if lat is not None else ""
    lon_s = f"{abs(lon):.6f}" if lon is not None else ""
    lat_r = ("N" if lat>=0 else "S") if lat is not None else ""
    lon_r = ("E" if lon>=0 else "W") if lon is not None else ""
    # location_name/date_str are free text (user-typed or AI-suggested) —
    # unescaped, a name containing & < or > (e.g. "Smith & Sons Farm")
    # produces invalid XML that Lightroom/Capture One silently fail to read.
    location_esc = xml_escape(location_name) if location_name else ""
    date_esc = xml_escape(date_str) if date_str else ""
    sidecar.write_text(f"""<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/'>
  <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
    <rdf:Description rdf:about=''
      xmlns:dc='http://purl.org/dc/elements/1.1/'
      xmlns:exif='http://ns.adobe.com/exif/1.0/'
      xmlns:xmp='http://ns.adobe.com/xap/1.0/'>
      <dc:description><rdf:Alt><rdf:li xml:lang='x-default'>{location_esc}</rdf:li></rdf:Alt></dc:description>
      <exif:GPSLatitude>{lat_s}{lat_r}</exif:GPSLatitude>
      <exif:GPSLongitude>{lon_s}{lon_r}</exif:GPSLongitude>
      <xmp:CreateDate>{date_esc}</xmp:CreateDate>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>""", encoding="utf-8")

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
    try:
        exif_dict = piexif.load(filepath)
    except Exception as e:
        _log(f"[exif] Refusing to rotate {filepath}: existing EXIF could not be "
             f"parsed ({e}) — rotating anyway would discard it")
        raise
    img = Image.open(filepath)
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
    img.convert("RGB").save(filepath, "jpeg", **save_kwargs)

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
    old_path = Path(row["path"])
    if not old_path.is_file():
        raise FileNotFoundError(f"{old_path} no longer exists")
    new_filename = (new_filename or "").strip()
    if not new_filename or "/" in new_filename or "\\" in new_filename:
        raise ValueError(f"Invalid filename: {new_filename!r}")
    new_path = old_path.parent / new_filename
    if new_path.exists():
        raise FileExistsError(f"{new_filename} already exists in {old_path.parent}")
    os.rename(old_path, new_path)
    old_sidecar = old_path.with_suffix(".xmp")
    if old_sidecar.exists():
        os.rename(old_sidecar, new_path.with_suffix(".xmp"))
    new_id = str(new_path.relative_to(Path(row["scan_root"])))
    db.execute("""UPDATE photos SET id=?, path=?, filename=?,
                  original_filename=COALESCE(original_filename,?) WHERE id=?""",
               (new_id, str(new_path), new_path.name, row["filename"], row["id"]))
    db.execute("INSERT INTO rename_log (photo_id, old_path, new_path) VALUES (?,?,?)",
               (new_id, str(old_path), str(new_path)))
    return new_id

@app.route("/api/rename_preview", methods=["POST"])
def api_rename_preview():
    data = request.json or {}
    ids = data.get("ids", [])
    pattern = (data.get("pattern") or "").strip() or "{date}_{location}_{seq}{ext}"
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
    data = request.json or {}
    items = data.get("items", [])
    dry_run = effective_dry_run(data.get("dry_run", False))
    db = _get_db()
    results = []
    for item in items:
        pid = item.get("id")
        new_filename = (item.get("new_filename") or "").strip()
        row = db.execute("SELECT * FROM photos WHERE id=?", (pid,)).fetchone()
        if not row:
            results.append({"id": pid, "ok": False, "error": "not found"}); continue
        if not new_filename or new_filename == row["filename"]:
            results.append({"id": pid, "ok": True, "skipped": True}); continue
        if dry_run:
            db_save_pending(db, pid, "rename", row["filename"], new_filename)
            results.append({"id": pid, "ok": True, "dry_run": True})
            continue
        try:
            new_id = _apply_rename(db, row, new_filename)
            results.append({"id": pid, "ok": True, "new_id": new_id})
        except Exception as e:
            results.append({"id": pid, "ok": False, "error": str(e)})
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

    # Pre-parse + sort every GPS photo's timestamp once, then bisect per
    # candidate. This used to re-parse every GPS photo's datetime string
    # inside the inner loop for every non-GPS candidate — an O(N×M) scan
    # with repeated parsing, the exact bug class already fixed once for
    # duplicate detection (11 min → 3 sec there). On a library with a
    # few thousand of each this was easily minutes; sorted + bisect
    # finds the same true nearest-in-time match in a couple of seconds.
    gps_ts, gps_sorted = [], []
    for p in all_db:
        if not (p["has_gps"] and p["date_taken"]):
            continue
        try:
            gps_ts.append((datetime.fromisoformat(p["date_taken"]) - _EPOCH).total_seconds())
            gps_sorted.append(p)
        except ValueError:
            continue
    order = sorted(range(len(gps_ts)), key=lambda i: gps_ts[i])
    gps_ts     = [gps_ts[i] for i in order]
    gps_sorted = [gps_sorted[i] for i in order]

    inferred = 0
    for photo in all_db:
        # 'history' (matched against imported location history, if any)
        # is a stronger signal than a same-folder GPS-cluster guess —
        # don't let this pass clobber it back down to 'inferred'.
        if photo["has_gps"] or photo["status"] in ("named","inferred","history") or not photo["date_taken"] or not gps_ts:
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

def _run_scan(folder, rescan=False):
    base = Path(folder)
    now_iso = datetime.now().isoformat()

    try:
        # ── Count ──────────────────────────────────────────────────
        with _scan_lock:
            _scan_state.update(phase="counting",message="Counting photo files…",
                               current=0,total=0,scan_root=folder)
        # _duplicates/ is where duplicate-resolution moves files (see
        # _move_to_duplicates_folder) — it lives inside the scan root for
        # simplicity, so it must be excluded here or a rescan would just
        # re-import everything just moved out of the library as "new" photos.
        all_paths = sorted([p for p in base.rglob("*")
                            if p.suffix.lower() in PHOTO_EXTENSIONS
                            and "_duplicates" not in p.relative_to(base).parts])
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
        conn = _connect_db()
        photos_batch = []

        for i, p in enumerate(all_paths):
            exif = read_exif(str(p))
            file_hash, phash_str, dhash_str = compute_hashes(str(p))
            mtime = p.stat().st_mtime

            photo = {
                "id":           str(p.relative_to(base)),
                "path":         str(p),
                "filename":     p.name,
                "folder":       str(p.parent.relative_to(base)),
                "size_kb":      round(p.stat().st_size/1024),
                "file_mtime":   mtime,
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
                "file_hash":    file_hash,
                "inferred_lat": None,"inferred_lon":None,
                "inferred_from":None,"inferred_delta_min":None,
                "scan_root":    folder,
                "last_scanned": now_iso,
                "date_source":  exif.get("date_source"),
            }
            photos_batch.append(photo)
            db_upsert_photo(conn, photo)

            if i % 50 == 0 or i == len(all_paths)-1:
                conn.commit()
                _log(f"[scan] EXIF {i+1}/{len(all_paths)}  {p.name}")
                with _scan_lock:
                    _scan_state.update(phase="reading", current=i+1,
                        message=f"Reading EXIF: {i+1} / {len(all_paths)}  ({p.name})")

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
        # rate limit (GEOCODE_DELAY, ~1.1s/request per Nominatim's usage
        # policy) is the real, already-documented pace ("Geocoding 500
        # photos takes ~10 min" — README); this just lets a scan finish the
        # whole backlog instead of stopping partway through it.
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

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return render_template("index.html", version=APP_VERSION)

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
    })

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """User-configurable settings that aren't safety-critical enough to need
    their own endpoint (c.f. /api/dry_run, which is deliberately separate
    and more defensive). Currently just the AI model; add keys here as
    the settings surface grows."""
    if request.method == "POST":
        data = request.json or {}
        if "ai_model" in data:
            model = (data.get("ai_model") or "").strip()
            set_setting("ai_model", model or AI_MODEL)
            _log(f"[settings] AI model set to {model or AI_MODEL}")
    return jsonify({"ai_model": get_ai_model()})

@app.route("/api/logs")
def api_logs():
    """
    Tail server stdout/stderr for the in-app Logs view.
    Pass `since` (last `id` you've already seen) to long-poll-style fetch
    only new lines; omit it (or pass 0) for an initial backfill of the last
    `limit` lines. Cheap: it's just filtering an in-memory deque.
    """
    since = request.args.get("since", 0, type=int)
    limit = request.args.get("limit", 500, type=int)
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
        data = request.json or {}
        val = bool(data.get("dry_run", True))
        set_setting("dry_run", "true" if val else "false")
        _log(f"[safety] Dry run set to {'ON' if val else 'OFF'}")
    return jsonify({"dry_run": get_dry_run()})

# ── Folder browser ────────────────────────────────────────────────
@app.route("/api/browse")
def api_browse():
    path = request.args.get("path", DEFAULT_PHOTO_ROOT)
    try:
        p = Path(path)
        if not p.exists() or not p.is_dir():
            return jsonify({"error": f"Not a directory: {path}"}), 400
        dirs = sorted([str(d.name) for d in p.iterdir()
                       if d.is_dir() and not d.name.startswith(".")])
        parent = str(p.parent) if str(p.parent) != str(p) else None
        return jsonify({"path": str(p), "parent": parent, "dirs": dirs})
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
    data = request.json or {}
    name = data.get("name","").strip()
    root = data.get("scan_root","").strip()
    if not name or not root:
        return jsonify({"error":"name and scan_root required"}), 400
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

# ── Scan ──────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    folder  = data.get("folder","").strip()
    rescan  = data.get("rescan", False)
    if not folder or not os.path.isdir(folder):
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
    # Self-heal: db_save_pending() now supersedes an existing uncommitted
    # row for the same photo+field instead of stacking another one, but
    # this cleans up anything left over from before that fix — a photo
    # edited/re-staged repeatedly (while testing a feature, adjusting a
    # pin, etc.) could otherwise show the same field pending several times
    # over. Keeps only the most recent uncommitted row per (photo_id,
    # field); committed rows (history) are untouched.
    db.execute("""
        DELETE FROM pending_changes
        WHERE committed=0 AND id NOT IN (
            SELECT MAX(id) FROM pending_changes WHERE committed=0
            GROUP BY photo_id, field
        )
    """)
    db.commit()
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
    data = request.json or {}
    ids  = data.get("ids")   # optional list of specific pending IDs
    db   = _get_db()
    q = "SELECT pc.*,p.path FROM pending_changes pc JOIN photos p ON p.id=pc.photo_id WHERE pc.committed=0"
    rows = db.execute(q + (" AND pc.id IN ({})".format(",".join("?"*len(ids))) if ids else ""),
                      ids or []).fetchall()
    results = []
    by_photo = {}
    for r in rows:
        by_photo.setdefault(r["photo_id"], {"path":r["path"],"fields":{}})
        by_photo[r["photo_id"]]["fields"][r["field"]] = r["new_value"]

    for photo_id, info in by_photo.items():
        try:
            fields = info["fields"]
            # A photo marked for duplicate cleanup is leaving the library —
            # any other pending field for it (a location edit made before it
            # was flagged as a dup, say) is moot, so skip straight to the
            # move and mark everything for this photo committed together.
            if fields.get("move_to_duplicates"):
                row = db.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
                if row:
                    _move_to_duplicates_folder(db, row)
                db.execute("UPDATE pending_changes SET committed=1 WHERE photo_id=? AND committed=0",
                           (photo_id,))
                results.append({"photo_id":photo_id,"ok":True})
                continue
            # write_location_to_exif unconditionally reloads+resaves the EXIF
            # segment even when nothing changed — fine for a real edit, but
            # a rename-only or rotate-only pending change would otherwise
            # re-encode the file for no reason.
            if any(fields.get(k) for k in ("location_name","lat","lon","date_taken")):
                write_location_to_exif(
                    info["path"],
                    fields.get("location_name"),
                    float(fields["lat"]) if fields.get("lat") else None,
                    float(fields["lon"]) if fields.get("lon") else None,
                    fields.get("date_taken"),
                )
            if fields.get("rotate_degrees"):
                rotate_image_file(info["path"], int(fields["rotate_degrees"]))
            # Renamed last: every write above already targeted the
            # pre-rename path captured in info["path"], so doing this last
            # means order here doesn't matter for any of them.
            if fields.get("rename"):
                row = db.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
                if row:
                    _apply_rename(db, row, fields["rename"])
            db.execute("UPDATE pending_changes SET committed=1 WHERE photo_id=? AND committed=0",
                       (photo_id,))
            results.append({"photo_id":photo_id,"ok":True})
        except Exception as e:
            results.append({"photo_id":photo_id,"ok":False,"error":str(e)})
    db.commit()
    return jsonify({"results":results,"committed":sum(1 for r in results if r["ok"])})

@app.route("/api/pending/discard", methods=["POST"])
def api_discard_pending():
    data = request.json or {}
    ids  = data.get("ids")
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
    data = request.json or {}
    lat,lon = data.get("lat"), data.get("lon")
    if lat is None or lon is None:
        return jsonify({"error":"lat/lon required"}), 400
    return jsonify({"location_name": reverse_geocode(lat,lon)})

@app.route("/api/geocode_search")
def api_geocode_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"results":[]})
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
    data = request.json or {}
    name, lat, lon = data.get("name"), data.get("lat"), data.get("lon")
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
    data = request.json or {}
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
    data          = request.json or {}
    filepath      = data.get("path")
    location_name = data.get("location_name")
    lat           = data.get("lat")
    lon           = data.get("lon")
    date_str      = data.get("date_taken")
    rotate_deg    = data.get("rotate_degrees") or 0
    dry_run       = effective_dry_run(data.get("dry_run", False))
    photo_id      = data.get("id")

    if not filepath or not os.path.isfile(filepath):
        return jsonify({"error":"File not found"}), 400

    db = _get_db()

    if dry_run:
        _log(f"[dry-run] Would write: {filepath}")
        if photo_id:
            # Get old values for undo
            row = db.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
            if row:
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
        # Update DB
        if photo_id:
            db.execute("""UPDATE photos SET location_name=?,lat=?,lon=?,date_taken=?,
                          has_gps=?,status=? WHERE id=?""",
                       (location_name, lat, lon, date_str,
                        1 if (lat and lon) else 0,
                        "gps" if (lat and lon) else ("named" if location_name else "unknown"),
                        photo_id))
            db.commit()
        return jsonify({"ok":True})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/save_batch", methods=["POST"])
def api_save_batch():
    data    = request.json or {}
    photos  = data.get("photos",[])
    dry_run = effective_dry_run(data.get("dry_run", False))
    db      = _get_db()
    results = []
    for p in photos:
        if dry_run:
            _log(f"[dry-run] Would write: {p.get('path')}")
            if p.get("id"):
                row = db.execute("SELECT * FROM photos WHERE id=?", (p["id"],)).fetchone()
                if row:
                    for field, new_val in [("location_name",p.get("location_name")),
                                            ("lat",p.get("lat")),("lon",p.get("lon")),
                                            ("date_taken",p.get("date_taken"))]:
                        if new_val is not None:
                            db_save_pending(db, p["id"], field, row[field], new_val)
            results.append({"id":p.get("id"),"ok":True,"dry_run":True})
        else:
            try:
                write_location_to_exif(p["path"],p.get("location_name"),
                                        p.get("lat"),p.get("lon"),p.get("date_taken"))
                if p.get("id"):
                    db.execute("""UPDATE photos SET location_name=?,lat=?,lon=?,
                                  has_gps=?,status=? WHERE id=?""",
                               (p.get("location_name"),p.get("lat"),p.get("lon"),
                                1 if (p.get("lat") and p.get("lon")) else 0,
                                "gps" if (p.get("lat") and p.get("lon"))
                                else ("named" if p.get("location_name") else "unknown"),
                                p["id"]))
                results.append({"id":p.get("id"),"ok":True})
            except Exception as e:
                results.append({"id":p.get("id"),"ok":False,"error":str(e)})
    db.commit()
    return jsonify({"results":results,"dry_run":dry_run})

# ── Thumbnail ─────────────────────────────────────────────────────
@app.route("/api/thumbnail")
def api_thumbnail():
    filepath = request.args.get("path","")
    if not filepath or not os.path.isfile(filepath):
        return "",404
    size = int(request.args.get("size",280))
    try:
        from io import BytesIO
        img = Image.open(filepath)
        img.thumbnail((size,size), Image.LANCZOS)
        buf = BytesIO()
        img.convert("RGB").save(buf,"JPEG",quality=75)
        buf.seek(0)
        return send_file(buf, mimetype="image/jpeg")
    except Exception as e:
        return str(e),500

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

def _run_dup_scan(folder):
    from collections import defaultdict
    try:
        with _dup_lock:
            _dup_state.update(phase="loading", message="Loading hashes from database…",
                              current=0, total=0)

        conn = _connect_db()
        rows = rows_to_dicts(conn.execute(
            "SELECT id,path,filename,folder,size_kb,date_taken,phash,dhash,file_hash,"
            "status,location_name FROM photos WHERE scan_root=?", (folder,)).fetchall())
        conn.close()

        n = len(rows)
        _log(f"[dup] Loaded {n} photos for duplicate analysis")

        # ── 1. Exact byte-level duplicates (instant, dict-based) ──────
        with _dup_lock:
            _dup_state.update(phase="exact", message="Finding exact duplicates…", total=n)
        exact = defaultdict(list)
        for r in rows:
            if r.get("file_hash"):
                exact[r["file_hash"]].append(r)
        exact_groups = [v for v in exact.values() if len(v) > 1]
        _log(f"[dup] {len(exact_groups)} exact-duplicate groups")

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
    data = request.json or {}
    folder = data.get("folder", "").strip()
    force  = data.get("force", False)
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
    src = Path(row["path"])
    if not src.is_file():
        raise FileNotFoundError(f"{src} no longer exists")
    dest_dir = Path(row["scan_root"]) / "_duplicates" / (row["folder"] or "")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    n = 1
    while dest.exists():
        dest = dest_dir / f"{src.stem} ({n}){src.suffix}"
        n += 1
    shutil.move(str(src), str(dest))
    sidecar = src.with_suffix(".xmp")
    if sidecar.exists():
        shutil.move(str(sidecar), str(dest.with_suffix(".xmp")))
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
    data = request.json or {}
    move_ids = data.get("move_ids", [])
    dry_run = effective_dry_run(data.get("dry_run", False))
    if not move_ids:
        return jsonify({"error": "move_ids required"}), 400
    db = _get_db()
    results = []
    for pid in move_ids:
        row = db.execute("SELECT * FROM photos WHERE id=?", (pid,)).fetchone()
        if not row:
            results.append({"id": pid, "ok": False, "error": "not found"}); continue
        if dry_run:
            db_save_pending(db, pid, "move_to_duplicates", None, "1")
            results.append({"id": pid, "ok": True, "dry_run": True})
            continue
        try:
            _move_to_duplicates_folder(db, row)
            results.append({"id": pid, "ok": True})
        except Exception as e:
            results.append({"id": pid, "ok": False, "error": str(e)})
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
        conn.execute("UPDATE location_imports SET status='error', error=? WHERE id=?",
                     (str(e), import_id))
        conn.commit()
        _log(f"[history] Import #{import_id} FAILED: {e}")
        with _hist_import_lock:
            _hist_import_state.update(running=False, phase="error", error=str(e), message=f"Error: {e}")
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

@app.route("/api/history/import", methods=["POST"])
def api_history_import():
    with _hist_import_lock:
        if _hist_import_state["running"]:
            return jsonify({"error": "An import is already running"}), 409

    upload = request.files.get("file")
    cleanup_path = None
    if upload and upload.filename:
        ext = Path(upload.filename).suffix.lower()
        if ext not in LOCATION_PARSERS:
            return jsonify({"error": f"Unsupported file type: {ext or '(none)'}"}), 400
        tmp_dir = Path(DB_PATH).parent / "tmp_imports"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        source_name = upload.filename
        filepath = str(tmp_dir / f"upload_{int(time.time())}{ext}")
        upload.save(filepath)  # Werkzeug streams this to disk in chunks, not buffered in memory
        cleanup_path = filepath
    else:
        data = request.form or request.get_json(silent=True) or {}
        path = (data.get("path") or "").strip()
        if not path:
            return jsonify({"error": "Provide a file upload or a server-side path"}), 400
        ext = Path(path).suffix.lower()
        if ext not in LOCATION_PARSERS:
            return jsonify({"error": f"Unsupported file type: {ext or '(none)'}"}), 400
        if not os.path.isfile(path):
            return jsonify({"error": f"File not found: {path}"}), 400
        filepath = path
        source_name = Path(path).name

    db = _get_db()
    cur = db.execute("INSERT INTO location_imports (source_name, source_type, status) VALUES (?,?,'importing')",
                      (source_name, LOCATION_SOURCE_LABEL[ext]))
    db.commit()
    import_id = cur.lastrowid

    with _hist_import_lock:
        _hist_import_state.update(running=True, phase="starting", current=0, total=0,
                                   message="Starting import…", error=None, import_id=import_id)
    threading.Thread(target=_run_history_import,
                      args=(import_id, filepath, ext, cleanup_path), daemon=True).start()
    return jsonify({"started": True, "import_id": import_id})

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
    data = request.json or {}
    folder = data.get("folder", "").strip()
    try:
        tolerance = max(1, int(data.get("tolerance_minutes", 60)))
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
    data   = request.json or {}
    folder = data.get("scan_root")
    if not folder:
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
    from io import BytesIO
    try:
        img = Image.open(path)
        img = ImageOps.exif_transpose(img)  # a sideways-looking photo is a bad look-at-the-image clue
        img.thumbnail((max_dim, max_dim), Image.LANCZOS)
        buf = BytesIO()
        img.convert("RGB").save(buf, "JPEG", quality=85)
        return base64.standard_b64encode(buf.getvalue()).decode("ascii")
    except Exception as e:
        _log(f"[ai] Could not decode {path} for vision, falling back to text-only: {e}")
        return None

def _ai_image_block(b64):
    return {"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":b64}}

@app.route("/api/ai_infer", methods=["POST"])
def api_ai_infer():
    import anthropic
    allowed, reason = _ai_allowed()
    if not allowed:
        return jsonify({"error":reason,"limit_reached":True}), 429
    data      = request.json or {}
    photo     = data.get("photo",{})
    neighbors = data.get("neighbors",[])
    lines = []
    if photo.get("date_taken"): lines.append(f"Photo taken: {photo['date_taken']}")
    if photo.get("folder"):     lines.append(f"Folder: {photo['folder']}")
    if photo.get("filename"):   lines.append(f"Filename: {photo['filename']}")
    if neighbors:
        lines.append("\nNearby photos with known locations:")
        for n in neighbors[:6]:
            lines.append(f"  - {n.get('filename')}: {n.get('location_name')} ({n.get('date_taken')})")
    b64 = _encode_photo_for_ai(photo.get("path")) if photo.get("path") else None
    if b64:
        prompt = (
            "Look at this photo and suggest where it was most likely taken. Use whatever's "
            "visible — landmarks, architecture, signage or text, vegetation, terrain, road "
            "signs, license plates, flags — together with the filename/folder/date/nearby-photo "
            "metadata below, which may add useful context (or may just be an uninformative "
            "camera-assigned name — don't let it override strong visual evidence). "
            "Reply with ONLY the location name (city, country format), or 'Unknown' if you "
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
            "(city, country format), or 'Unknown' if you genuinely cannot guess. "
            "No explanation, no hedging, no mention of photos or images.\n\n"
            + "\n".join(lines)
        )
        content = prompt
    try:
        msg = anthropic.Anthropic().messages.create(
            model=get_ai_model(), max_tokens=30,
            messages=[{"role":"user","content":content}])
        _ai_increment()
        suggestion = msg.content[0].text.strip()
        usage = _ai_usage_info()
        _log(f"[ai] {photo.get('filename')} → {suggestion} ({usage['used']}/{usage['limit']})")
        return jsonify({"suggestion":suggestion,"ai_usage":usage})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/ai_infer_with_coords", methods=["POST"])
def api_ai_infer_with_coords():
    import anthropic
    allowed, reason = _ai_allowed()
    if not allowed:
        return jsonify({"error":reason,"limit_reached":True}), 429
    data          = request.json or {}
    photo         = data.get("photo",{})
    seed_lat      = data.get("seed_lat")
    seed_lon      = data.get("seed_lon")
    seed_location = data.get("seed_location","")
    lines = [
        f"Seed location (manually pinned by user): {seed_location} (GPS: {seed_lat}, {seed_lon})",
        f"Photo filename: {photo.get('filename','unknown')}",
        f"Folder: {photo.get('folder','unknown')}",
    ]
    if photo.get("date_taken"):
        lines.append(f"Date taken: {photo['date_taken']}")
    b64 = _encode_photo_for_ai(photo.get("path")) if photo.get("path") else None
    if b64:
        prompt = (
            "A user manually pinned a location on a map for one photo in a folder, and wants "
            "it applied to this photo too. Look at the image: does it plausibly belong at that "
            "seed location, or does what you actually see (indoors vs. outdoors, landscape vs. "
            "cityscape, climate/vegetation, any visible landmarks or signage) suggest otherwise? "
            "Combine that with the filename/folder/date metadata below. If the seed location "
            "looks right, return it as-is; if the photo clearly doesn't match it (and you can "
            "tell where it actually is instead), return your own answer instead. "
            "Reply with ONLY the location name (e.g. 'Paris, France'). "
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
        msg = anthropic.Anthropic().messages.create(
            model=get_ai_model(), max_tokens=30,
            messages=[{"role":"user","content":content}])
        _ai_increment()
        location_name = msg.content[0].text.strip()
        # Reject any response that sounds like an apology/explanation
        if len(location_name) > 60 or any(w in location_name.lower() for w in
                ("i don't","i cannot","i'm unable","no access","image file","photo file")):
            location_name = seed_location  # fall back to seed
        usage = _ai_usage_info()
        _log(f"[ai-seed] {photo.get('filename')} → {location_name}")
        return jsonify({"location_name":location_name,"ai_usage":usage})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/ai_usage")
def api_ai_usage():
    return jsonify(_ai_usage_info())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
