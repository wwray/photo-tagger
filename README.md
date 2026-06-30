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

Open `http://localhost:5000` (or your server IP).

## Features

- **Scans** any folder recursively for JPEG and RAW photos (CR2, NEF, ARW, ORF, RW2, DNG)
- **Reads EXIF**: date taken, GPS coordinates, existing location tags
- **Reverse geocodes** GPS coordinates to human-readable city/country names (OpenStreetMap, free, no API key)
- **Infers locations** for un-GPS-tagged photos based on nearby timestamped photos (±4 hour window)
- **AI suggestions** via Claude API for photos that can't be auto-inferred (optional)
- **Writes metadata back** directly into JPEG EXIF, or XMP sidecar files for RAW formats
- **Batch operations**: geocode all, tag a selection, save all at once

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
