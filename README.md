# PhotoTagger 📷

A self-hosted Docker web app to browse your photo library, read and write EXIF location/date metadata, detect duplicates, and intelligently infer locations for untagged photos. Built for Unraid, works anywhere Docker runs.

## Quick start (from GitHub)

```bash
git clone https://github.com/YOUR_USERNAME/phototagger.git
cd phototagger
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY if you want AI suggestions
docker build -t phototagger:latest .
docker run -d \
  --name phototagger \
  --restart unless-stopped \
  -p 5000:5000 \
  -v /path/to/your/photos:/photos:rw \
  -v $(pwd)/data:/app/data \
  --env-file .env \
  phototagger:latest
```

PowerShell equivalent for the `docker run` line:

```powershell
docker run -d `
  --name phototagger `
  --restart unless-stopped `
  -p 5000:5000 `
  -v C:\path\to\your\photos:/photos:rw `
  -v ${PWD}/data:/app/data `
  --env-file .env `
  phototagger:latest
```

Open `http://localhost:5000` (or your server IP).

A prebuilt image is also published to GHCR on every push to `master` — see
[`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml) —
so you can skip the `docker build` step and pull instead:

```bash
docker pull ghcr.io/YOUR_USERNAME/phototagger:latest
```

> ⚠️ **This app has no authentication and no path restriction on the
> filesystem browser/scanner.** Anyone who can reach port 5000 can browse and
> read directories anywhere the container's user can see, not just your
> photo share. It's meant to run on a trusted LAN — don't expose it directly
> to the internet without putting it behind a reverse proxy with auth (or a
> VPN).

## Features

- **Scans** any folder recursively for JPEG and RAW photos (CR2, NEF, ARW, ORF, RW2, DNG)
- **Reads EXIF**: date taken, GPS coordinates, existing location tags
- **Reverse geocodes** GPS coordinates to human-readable city/country names (OpenStreetMap, free, no API key)
- **Infers locations** for un-GPS-tagged photos based on nearby timestamped photos (±4 hour window)
- **Location history import**: match un-GPS-tagged photos against an imported Google Takeout `Records.json` or GPX track by timestamp — offline, no API key, and more reliable than inferring from other photos since it's where *you* actually were (see below)
- **AI suggestions** via Claude API for photos that can't be auto-inferred (optional)
- **Writes metadata back** directly into JPEG EXIF, or XMP sidecar files for RAW formats
- **Rotate**: 90°/180°/270° rotation from the detail view, previewed live before saving, applied through the same dry-run flow as everything else (JPEG only — see below)
- **Batch operations**: geocode all, tag a selection, save all at once
- **Dry run by default**: every write is staged as a pending change and reviewed before anything touches disk (see below)
- **Sessions**: save named scan roots so you can jump back into a library without re-typing the path
- **Duplicate detection**: exact-byte, filename-pattern, and perceptual (pHash + dHash) matches, run as a background job with progress

---

## Unraid — Community Applications (easiest)

1. Copy `phototagger-unraid.xml` to `/boot/config/plugins/dockerMan/templates-user/` on your Unraid server
2. In Unraid, go to **Docker → Add Container → Select a Template** and choose **PhotoTagger**
3. Set your **Photos Share** path (e.g. `/mnt/user/Photos`)
4. Optionally paste your Anthropic API key for AI suggestions
5. Click **Apply**

---

## Unraid — Manual Docker setup

### 1. Build the image on your Unraid server

```bash
# Copy the project folder to your Unraid server, then:
cd /path/to/photo-tagger
docker build -t phototagger:latest .
```

### 2. Run the container

```bash
docker run -d \
  --name phototagger \
  --restart unless-stopped \
  -p 5000:5000 \
  -v /mnt/user/Photos:/photos:rw \
  -v /mnt/user/appdata/phototagger:/app/data \
  -e PUID=99 \
  -e PGID=100 \
  -e ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE \
  phototagger:latest
```

Replace `/mnt/user/Photos` with the path to your Unraid photos share.

> ⚠️ The `/app/data` mount is not optional. It's where the database lives —
> sessions, scan cache, pending dry-run changes. Skip it and that data
> lives only in the container's disposable layer, silently gone the next
> time the container is recreated (an update, a rebuild, anything short of
> `docker start` on the exact same container).

### 3. Open the UI

```
http://YOUR-UNRAID-IP:5000
```

The folder input will auto-fill with `/photos`. Click **Scan Folder**.

---

## Docker Compose (alternative)

```bash
# Edit docker-compose.yml to set your photos path, then:
ANTHROPIC_API_KEY=sk-ant-... docker compose up -d
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PUID` | `99` | User ID for file writes (99 = Unraid nobody) |
| `PGID` | `100` | Group ID for file writes (100 = Unraid users) |
| `ANTHROPIC_API_KEY` | *(empty)* | Enables AI location suggestions (optional) |
| `PHOTO_ROOT` | `/photos` | Container path pre-filled in the scan box |
| `AI_DAILY_LIMIT` | `50` | Max AI suggestion calls per day (cost control) |
| `AI_MODEL` | `claude-haiku-4-5-20251001` | Anthropic model used for AI suggestions |

---

## Dry run mode (default ON)

PhotoTagger never writes to a file unless you explicitly turn dry run off.
This flag is **server-side**, not client-side — the browser can only ever make
a request *more* conservative, never less, and every fresh page load re-arms
it to ON. Concretely:

1. With dry run on, saves are recorded as **pending changes** in the database
   instead of touching any file.
2. Review them (per-photo or in bulk) before anything happens on disk.
3. **Commit** writes the reviewed changes to the actual files/sidecars, or
   **discard** drops them with no effect.

Turning dry run off is a deliberate, logged action — do it once you trust
the suggestions you're about to write.

---

## Location history import

If you have an exported location history — a Google Takeout `Records.json`,
or a GPX track from a phone/GPS device — PhotoTagger can use it to fill in
photos that have no embedded GPS, by matching each photo's timestamp against
the nearest recorded point. This is ground truth about where *you* were, so
it's generally more trustworthy than guessing from nearby photos, and it's
entirely offline (no Nominatim, no API key).

Click **🛰️ History** in the header to:

1. **Import** a `Records.json` or `.gpx` file, either by server-side path
   (recommended for large exports — Takeout files can be 1GB+ with millions
   of points, and this avoids uploading that over the network) or by
   uploading it directly. Import runs as a background job and streams the
   file rather than loading it all into memory.
2. **Match** the current library against everything imported so far, with an
   adjustable time tolerance (default 60 minutes). Only photos with no GPS
   and no location name yet are considered — it never overwrites an existing
   GPS tag or a confirmed name, and it can supersede a weaker "inferred from
   sibling photos" guess.
3. Matched photos show up with a **History** badge and, in the detail panel,
   the time gap to the point that matched (e.g. "3 min from a recorded
   location point"). Coordinates are pre-filled — click **🌍 Geocode** to
   turn them into a name, then **Save** like any other photo. Nothing is
   written to a file by the match itself; it only produces a suggestion that
   goes through the same dry-run review as everything else.

A bad import can be removed from the History panel — this also clears any
suggestions it produced. Note: matching compares timestamps directly, so it
assumes your camera clock and the imported history are in the same
timezone (UTC is the safe case); there's no per-import offset setting.

---

## How metadata is written

| Format | Method |
|--------|--------|
| `.jpg` / `.jpeg` | EXIF `ImageDescription` (location) + GPS IFD + DateTimeOriginal |
| `.cr2`, `.nef`, `.arw`, `.orf`, `.rw2`, `.dng` | XMP sidecar `.xmp` file (picked up by Lightroom, Capture One, etc.) |

Rotation is JPEG-only: it physically re-encodes the pixels (any existing EXIF
orientation flag is normalized first, so it isn't applied twice), which PIL
can do for a JPEG but not for a RAW format — there's no RAW codec here to
decode/re-encode one. The rotate buttons are disabled for RAW files rather
than pretending to support them via a sidecar hint most RAW viewers won't
honor anyway.

---

## Notes

- Nominatim geocoding is rate-limited to ~1 req/sec (OSM policy). Geocoding 500 photos takes ~10 min.
- AI suggestions are optional — the app works fully without an API key, just without that one button.
- Thumbnails are generated on-the-fly; first grid load on a large library may take a moment.
- **Always keep backups before writing metadata in bulk.**
- Back up `data/phototagger.db` too — it holds your sessions, hash cache, and any pending (not-yet-committed) changes. Losing it doesn't touch your photos, but you'd lose that state and have to rescan.

---

## License

[MIT](LICENSE)

---

## Changelog

### Unreleased

**Fixed: switching sessions re-scanned the whole folder from disk every
time, and could silently break the scan you switched away from.**
Clicking a saved session always called a full scan, even switching back
to one already fully loaded a moment ago — for a large library that
meant every switch cost minutes. Worse: if a scan was still running when
you clicked a different session, the new attempt got rejected by the
server (only one scan runs at a time) — but the client had already
overwritten which folder it was tracking progress for, so the original
scan's results never made it into the grid when it actually finished; it
just looked stuck on "Scanning…" forever. Fixed: clicking a session now
loads its already-scanned data straight from the database instantly, no
re-scan, unless that folder has genuinely never been scanned before —
and a rejected scan attempt no longer touches the tracking for whichever
scan is actually running. Reproduced both symptoms first (confirmed the
rejected attempt used to corrupt state, and that instant-switch was
actually triggering a scan), then verified the fix on both.

**Fixed: "database is locked" errors while a scan was running** (e.g.
using a saved session, or anything else that writes to the database).
No connection anywhere ever set `PRAGMA busy_timeout` — SQLite's default
is 0, so any write that found the database locked failed immediately
instead of waiting. It was easy to hit in practice because a scan's
connection holds SQLite's single writer lock for its *entire* commit
batch (Python's `sqlite3` module opens an implicit transaction on the
first write and doesn't release the lock until `.commit()`), which is
several seconds of EXIF/hash-reading time for every 50 photos. All
connections now go through one shared helper that sets a 30-second
`busy_timeout`, so a concurrent write waits briefly instead of failing.
Reproduced the original error and confirmed the fix with a real
two-thread lock-contention test, not just by reasoning about it.

**Fixed: photos already tagged only with a camera's firmware-default
description (e.g. "OLYMPUS DIGITAL CAMERA") showed up as Named/Tagged.**
That text was never a caption anyone entered; treating it as one made
those photos look already-confirmed and blocked Propagate-to-folder and
similar "don't overwrite confirmed data" logic. New scans now recognize
the `"<anything> DIGITAL CAMERA"` pattern and treat it as empty; a full
**Scan** (not **↻ Rescan**, which skips unchanged files) also self-heals
photos already mis-tagged this way from before the fix, without
disturbing genuinely-named photos.

**Fixed: database didn't survive a container rebuild on Unraid.** Neither
the Community Applications template nor the README's manual Unraid
`docker run` command mounted `/app/data` to a persistent path — only the
photos share was mounted. That meant the SQLite database (sessions, scan
cache, pending dry-run changes) lived in the container's disposable
writable layer and was silently wiped on every recreate (Force Update, a
rebuild, anything short of starting the *exact same* container). The
`docker-compose.yml` path was never affected — it already mounted
`/app/data` correctly. Fixed in both the XML template (new `/app/data` →
`/mnt/user/appdata/phototagger` volume) and the README's manual command.
**If you deployed before this fix**, copy your current database out
before redeploying with the new volume, or it's lost like everything
else that was in the old layer:
`docker cp phototagger:/app/data/phototagger.db /mnt/user/appdata/phototagger/`
(create that host folder first) — then update the container definition
and recreate it.

**Added: drag-to-select in the grid.** Click and drag to select every
card the rectangle touches (Ctrl/Cmd-drag extends the existing selection
instead of replacing it). Along the way, fixed a real gotcha: dragging
over an `<img>` triggers the browser's native image-drag after the first
pixel of movement, which silently stops further `mousemove` events from
firing at all — thumbnails now have `draggable="false"`.

**Improved: "Propagate to folder" can now (deliberately) overwrite an
already-tagged photo.** It used to just exclude any photo with GPS or a
name, with no way to override — confusing if that's exactly what you
meant to do. Those photos are now included with a status badge and
"will overwrite" note, but start unchecked, so overwriting one is always
an explicit choice, never an accident.

**Added: status filter tabs in "Propagate to folder."** The checklist can
mix untagged, inferred, and history-matched siblings; tabs (dynamically
generated from what's actually in the list) let you narrow to one status
at a time. Checked state is tracked per-photo, not per-tab, so switching
tabs never silently drops a selection made elsewhere.

**Added: map picker and Geocode to the batch "Set location for selected"
prompt.** Previously it only took typed-in coordinates; it now has the
same 🌍 Geocode and 🗺️ Map buttons as the single-photo detail view.

**Improved: the grid's selection checkbox was hard to hit.** Its actual
click target is now a 44×44px corner zone — the visible box stays small,
but a near-miss no longer opens the photo instead of selecting it.
Ctrl/Cmd-click and Shift-click (range-select) on a card now also toggle
selection from anywhere on it, no precision required.

**Added: rotate controls.** ⟲/⟳ buttons in the detail view, previewed live
with a CSS transform before saving, applied via the same dry-run-gated
`/api/save` path as every other field (JPEG only — see "How metadata is
written").

**Added: configurable AI model.** A ⚙️ Settings modal lets you change the
model used for AI Suggest without restarting the container. Also fixed the
shipped default, which had an incorrect date suffix (`claude-haiku-4-5-20251001`
→ `claude-haiku-4-5`) — current Anthropic model IDs don't take one.

**Improved: detail view and "Propagate to folder" modal are no longer
cramped.** The photo detail panel was capped at 860px wide with the image
further limited to 68vh (and fetched at only 600px regardless of screen
size); it now scales up to `min(94vw, 1400px)` and fetches images at
1400px. The propagate-to-folder checklist had 44×33px thumbnails that made
it hard to tell whether a photo actually belonged at the target location;
thumbnails are now full-size grid cards (~200px+, fetched at 420px).

**Improved: the location-history modal explains itself.** It previously
jumped straight to "Import from a server path" with no framing; it now
opens with what the feature is, why it's more trustworthy than the
automatic "Inferred" guess, and a 3-step outline of the actual workflow.

**Fixed: scan progress could stretch a status bar to fill most of the
screen.** `body` used a 2-row CSS grid (`auto 1fr`) that only accounts for
exactly two always-visible children — header and `.main`. Any optional
in-flow sibling that becomes visible between them (the pending-changes
bar, and the new scan-status bar) got auto-placed into the `1fr` row and
stretched to fill it, squashing `.main` into an auto-sized row instead.
This was a latent bug affecting the pending-changes bar too, whenever it
was visible — the new status bar just triggered it far more often. Fixed
by switching `body` to a flex column with `.main{flex:1}`, which doesn't
care how many optional bars come and go.

**Added: location history import.** Import a Google Takeout `Records.json`
or GPX track and match un-GPS-tagged photos against it by timestamp
(configurable tolerance, default 60 min). Streamed/batched throughout so a
1GB+, multi-million-point export doesn't need to fit in memory at once —
import and matching both run as background jobs with progress, matches are
persisted (not just held in memory), and a bad import can be removed
cleanly. Produces suggestions only, through the existing dry-run review
flow — see the new "Location history import" section above. Adds a new
`ijson` dependency for streaming JSON parsing.

**Fixed: `PUID`/`PGID` had no effect.**
The Dockerfile ran the process as a fixed `appuser` (uid 1000) before
`CMD`, so app.py's `os.setuid()` call — meant to drop root down to the
requested `PUID`/`PGID` — was unreachable: a non-root process can't
`setuid` to an arbitrary other user, and the failure was swallowed by a
bare `except`. Files ended up owned by uid 1000 regardless of what
`PUID`/`PGID` were set to. The container now starts as root so the
existing privilege-drop code actually runs, the data directory is chowned
to the target uid/gid before the drop, and a failed drop now logs a
warning instead of failing silently.

### v1.1 — P0 stability pass

**Fixed: AI Suggest hung forever with no network request.**
`detailIndex` was a positional index into `sortedFiltered()`, which is
recomputed on every call. Any re-render between opening the photo and clicking
the button invalidated it, so the lookup returned `undefined` and threw on
`p.id` — *after* the button label had been set to "Thinking…" and *before* the
`fetch`. The function was `async` with no `try/catch`, so the rejection was
swallowed. The detail panel now tracks the photo by ID, every handler guards
against a missing photo, and a global `unhandledrejection` listener surfaces
any future silent failure as a toast.

**Fixed: dry-run reset to OFF and was client-controlled.**
The flag was sent from the browser in the request body, so stale JS state could
cause a real write. The server now owns it: it is stored in the database,
defaults to ON, is re-armed to ON on every page load, and a client can only
make a request *more* conservative, never less. Turning it off is now a
deliberate, logged action.

**Fixed: duplicate scan appeared to hang.**
It wasn't broken, it was O(n²) with `imagehash.hex_to_hash()` re-parsing inside
the inner loop — benchmarked at ~11 minutes for 5,900 photos with no feedback.
Hashes are now compared as integers via XOR + `bit_count()`: **3.1 seconds** for
the same set. It runs as a background job with live progress, a 5-minute
timeout, an explicit error state, and result caching.

**Improved: duplicate accuracy.**
Both pHash (DCT) and dHash (gradient) are now stored and a pair matches if
either agrees, because they fail on different inputs. Results are split into
identical files, visually similar, and filename-pattern groups.

**Hardened:** double-click guard on scan, poll timers cleared before awaiting,
idempotent header injection.
