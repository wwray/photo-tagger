import os
import re
import sys
import time
import json
import bisect
import calendar
import hashlib
import sqlite3
import threading
import contextlib
import xml.etree.ElementTree as ET
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

    def write(self, data):
        self._real.write(data)
        global _log_seq
        self._partial += data
        while "\n" in self._partial:
            line, self._partial = self._partial.split("\n", 1)
            if line.strip():
                with _log_buffer_lock:
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
DEFAULT_PHOTO_ROOT = os.environ.get("PHOTO_ROOT", "/photos")
AI_DAILY_LIMIT     = int(os.environ.get("AI_DAILY_LIMIT", "50"))
AI_MODEL           = os.environ.get("AI_MODEL", "claude-haiku-4-5")
DB_PATH            = os.environ.get("DB_PATH", "/app/data/phototagger.db")

_geocode_lock = threading.Lock()
_last_geocode = 0.0
_ai_usage     = {"date": None, "count": 0}
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

def _get_db():
    if "db" not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
                      ("history_delta_min", "INTEGER"), ("history_import_id", "INTEGER")]:
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
            inferred_from, inferred_delta_min, scan_root, last_scanned, date_source
        ) VALUES (
            :id,:path,:filename,:folder,:size_kb,:file_mtime,
            :date_taken,:lat,:lon,:location_name,:has_gps,:status,
            :phash,:dhash,:file_hash,:inferred_lat,:inferred_lon,
            :inferred_from,:inferred_delta_min,:scan_root,:last_scanned,:date_source
        )
        ON CONFLICT(id) DO UPDATE SET
            path=excluded.path, filename=excluded.filename,
            folder=excluded.folder, size_kb=excluded.size_kb,
            file_mtime=excluded.file_mtime, date_taken=excluded.date_taken,
            lat=excluded.lat, lon=excluded.lon,
            location_name=COALESCE(excluded.location_name, photos.location_name),
            has_gps=excluded.has_gps,
            -- 'history' is a suggestion (from imported location history), not
            -- read straight from the file, so it's just as fragile to a
            -- rescan re-deriving 'unknown' as 'named'/'gps' would be — treat
            -- it the same way rather than silently discarding the match.
            status=CASE WHEN photos.status IN ('named','gps','history') AND excluded.status='unknown'
                        THEN photos.status ELSE excluded.status END,
            phash=excluded.phash, dhash=excluded.dhash, file_hash=excluded.file_hash,
            date_source=excluded.date_source,
            inferred_lat=excluded.inferred_lat, inferred_lon=excluded.inferred_lon,
            inferred_from=excluded.inferred_from,
            inferred_delta_min=excluded.inferred_delta_min,
            scan_root=excluded.scan_root, last_scanned=excluded.last_scanned
    """, {**{
        "id":None,"path":None,"filename":None,"folder":None,"size_kb":None,
        "file_mtime":None,"date_taken":None,"lat":None,"lon":None,
        "location_name":None,"has_gps":0,"status":"unknown",
        "phash":None,"dhash":None,"file_hash":None,"date_source":None,
        "inferred_lat":None,"inferred_lon":None,
        "inferred_from":None,"inferred_delta_min":None,
        "scan_root":None,"last_scanned":None
    }, **photo})

def db_save_pending(conn, photo_id, field, old_value, new_value):
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
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    finally:
        conn.close()

def set_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
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

def _ai_allowed():
    with _ai_lock:
        today = datetime.now().date().isoformat()
        if _ai_usage["date"] != today:
            _ai_usage["date"] = today; _ai_usage["count"] = 0
        if _ai_usage["count"] >= AI_DAILY_LIMIT:
            return False, f"Daily AI limit of {AI_DAILY_LIMIT} reached."
        return True, ""

def _ai_increment():
    with _ai_lock: _ai_usage["count"] += 1

def _ai_usage_info():
    with _ai_lock:
        today = datetime.now().date().isoformat()
        if _ai_usage["date"] != today:
            return {"used":0,"limit":AI_DAILY_LIMIT,"remaining":AI_DAILY_LIMIT}
        used = _ai_usage["count"]
        return {"used":used,"limit":AI_DAILY_LIMIT,"remaining":max(0,AI_DAILY_LIMIT-used)}

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

def read_exif(filepath):
    result = {"date_taken":None,"lat":None,"lon":None,
              "location_name":None,"has_gps":False,"error":None,
              "date_source":None}
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
            if lat is not None and lon is not None:
                result["lat"] = lat; result["lon"] = lon; result["has_gps"] = True
        if "Image ImageDescription" in tags:
            result["location_name"] = str(tags["Image ImageDescription"])
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

def reverse_geocode(lat, lon):
    global _last_geocode
    with _geocode_lock:
        wait = GEOCODE_DELAY - (time.time() - _last_geocode)
        if wait > 0: time.sleep(wait)
        _last_geocode = time.time()
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

def write_location_to_exif(filepath, location_name, lat=None, lon=None, date_str=None):
    ext = Path(filepath).suffix.lower()
    if ext in (".jpg",".jpeg"):
        _write_jpeg_exif(filepath, location_name, lat, lon, date_str)
    else:
        _write_xmp_sidecar(filepath, location_name, lat, lon, date_str)

def _write_jpeg_exif(filepath, location_name, lat=None, lon=None, date_str=None):
    try:    exif_dict = piexif.load(filepath)
    except: exif_dict = {"0th":{},"Exif":{},"GPS":{},"1st":{}}
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
    sidecar.write_text(f"""<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/'>
  <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
    <rdf:Description rdf:about=''
      xmlns:dc='http://purl.org/dc/elements/1.1/'
      xmlns:exif='http://ns.adobe.com/exif/1.0/'
      xmlns:xmp='http://ns.adobe.com/xap/1.0/'>
      <dc:description><rdf:Alt><rdf:li xml:lang='x-default'>{location_name or ''}</rdf:li></rdf:Alt></dc:description>
      <exif:GPSLatitude>{lat_s}{lat_r}</exif:GPSLatitude>
      <exif:GPSLongitude>{lon_s}{lon_r}</exif:GPSLongitude>
      <xmp:CreateDate>{date_str or ''}</xmp:CreateDate>
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
    try:
        exif_dict = piexif.load(filepath)
    except Exception:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}}
    img = ImageOps.exif_transpose(Image.open(filepath))
    # PIL's rotate() is counter-clockwise; the UI's ⟳ is clockwise, so negate.
    img = img.rotate(-degrees, expand=True)
    exif_dict["0th"][piexif.ImageIFD.Orientation] = 1
    img.convert("RGB").save(filepath, "jpeg", quality=92, exif=piexif.dump(exif_dict))

# ─── Scan (background thread) ─────────────────────────────────────────────────

_scan_state = {"running":False,"phase":"","current":0,"total":0,
               "message":"","error":None,"scan_root":None}
_scan_lock  = threading.Lock()

def _log(msg): print(msg, flush=True)

def _run_scan(folder, rescan=False):
    base = Path(folder)
    now_iso = datetime.now().isoformat()

    try:
        # ── Count ──────────────────────────────────────────────────
        with _scan_lock:
            _scan_state.update(phase="counting",message="Counting photo files…",
                               current=0,total=0,scan_root=folder)
        all_paths = sorted([p for p in base.rglob("*")
                            if p.suffix.lower() in PHOTO_EXTENSIONS])
        total = len(all_paths)
        _log(f"[scan] Found {total} photos in {folder}")

        # ── Diff against DB (rescan) ───────────────────────────────
        if rescan:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
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
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
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

        all_db = rows_to_dicts(conn.execute(
            "SELECT * FROM photos WHERE scan_root=?", (folder,)).fetchall())
        gps_photos = [p for p in all_db if p["has_gps"] and p["date_taken"]]

        inferred = 0
        for photo in all_db:
            # 'history' (matched against imported location history, if any)
            # is a stronger signal than a same-folder GPS-cluster guess —
            # don't let this pass clobber it back down to 'inferred'.
            if photo["has_gps"] or photo["status"] in ("named","inferred","history") or not photo["date_taken"]:
                continue
            try: dt = datetime.fromisoformat(photo["date_taken"])
            except ValueError: continue
            best, best_delta = None, float("inf")
            for gp in gps_photos:
                try:
                    delta = abs((dt-datetime.fromisoformat(gp["date_taken"])).total_seconds())
                    if delta < best_delta: best_delta, best = delta, gp
                except ValueError: continue
            if best and best_delta <= 4*3600:
                conn.execute("""UPDATE photos SET inferred_lat=?,inferred_lon=?,
                    inferred_from=?,inferred_delta_min=?,status='inferred'
                    WHERE id=?""",
                    (best["lat"],best["lon"],best["filename"],
                     round(best_delta/60),photo["id"]))
                inferred += 1
        conn.commit()
        _log(f"[scan] Inferred {inferred} locations")

        # ── Geocode ────────────────────────────────────────────────
        needs_geo = [p for p in all_db if p["has_gps"] and not p["location_name"]][:200]
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
        conn.close()

        counts = {}
        for p in all_db: counts[p["status"]] = counts.get(p["status"],0)+1
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
def index(): return render_template("index.html")

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
    return jsonify({"photos": rows_to_dicts(rows), "total": len(rows)})

# ── Pending changes (dry run persistence) ────────────────────────
@app.route("/api/pending")
def api_pending():
    folder = request.args.get("folder","")
    db = _get_db()
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
            write_location_to_exif(
                info["path"],
                fields.get("location_name"),
                float(fields["lat"]) if fields.get("lat") else None,
                float(fields["lon"]) if fields.get("lon") else None,
                fields.get("date_taken"),
            )
            if fields.get("rotate_degrees"):
                rotate_image_file(info["path"], int(fields["rotate_degrees"]))
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

        conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
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

# ── AI infer ──────────────────────────────────────────────────────
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
    prompt = (
        "You are a metadata assistant. You have NO access to any image files or photos. "
        "Work only from the text metadata provided below.\n\n"
        "Based only on the filename, folder name, date, and nearby photos listed, "
        "suggest the most likely location. Reply with ONLY the location name "
        "(city, country format), or 'Unknown' if you genuinely cannot guess. "
        "No explanation, no hedging, no mention of photos or images.\n\n"
        + "\n".join(lines)
    )
    try:
        msg = anthropic.Anthropic().messages.create(
            model=get_ai_model(), max_tokens=30,
            messages=[{"role":"user","content":prompt}])
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
    prompt = (
        "You are a metadata assistant. You have NO access to any image files or photos. "
        "Work only from the text metadata provided below.\n\n"
        "A user manually pinned a location on a map for one photo in a folder. "
        "Based only on the seed location and the filename/folder/date metadata below, "
        "return the most likely location name for this photo. "
        "If the seed location is reasonable, just return it as-is. "
        "Reply with ONLY the location name (e.g. 'Paris, France'). "
        "No explanation, no hedging, no mention of photos or images.\n\n"
        + "\n".join(lines)
    )
    try:
        msg = anthropic.Anthropic().messages.create(
            model=get_ai_model(), max_tokens=30,
            messages=[{"role":"user","content":prompt}])
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
