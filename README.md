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
- **AI suggestions** via Claude API for photos that can't be auto-inferred (optional)
- **Writes metadata back** directly into JPEG EXIF, or XMP sidecar files for RAW formats
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
  -e PUID=99 \
  -e PGID=100 \
  -e ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE \
  phototagger:latest
```

Replace `/mnt/user/Photos` with the path to your Unraid photos share.

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

## How metadata is written

| Format | Method |
|--------|--------|
| `.jpg` / `.jpeg` | EXIF `ImageDescription` (location) + GPS IFD + DateTimeOriginal |
| `.cr2`, `.nef`, `.arw`, `.orf`, `.rw2`, `.dng` | XMP sidecar `.xmp` file (picked up by Lightroom, Capture One, etc.) |

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
