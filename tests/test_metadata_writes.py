"""Preserving existing metadata: XMP sidecars, JPEG EXIF, rename/move targets."""
import os
import xml.dom.minidom as minidom

import piexif
import pytest

from conftest import app_module, make_jpeg

LIGHTROOM_SIDECAR = """<?xpacket begin='﻿' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 7.0">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:crs="http://ns.adobe.com/camera-raw-settings/1.0/"
    xmlns:lr="http://ns.adobe.com/lightroom/1.0/"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:exif="http://ns.adobe.com/exif/1.0/"
    xmp:Rating="4"
    xmp:CreateDate="2001-01-01T00:00:00"
    crs:Exposure2012="+0.35"
    exif:GPSLatitude="10,0.000000N">
   <dc:subject><rdf:Bag><rdf:li>family</rdf:li><rdf:li>beach</rdf:li></rdf:Bag></dc:subject>
   <dc:description><rdf:Alt>
     <rdf:li xml:lang="x-default">Old caption</rdf:li>
     <rdf:li xml:lang="fr-FR">Ancienne légende</rdf:li>
   </rdf:Alt></dc:description>
   <lr:hierarchicalSubject><rdf:Bag><rdf:li>People|Family</rdf:li></rdf:Bag></lr:hierarchicalSubject>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""

NS = {"rdf": app_module.NS_RDF, "dc": app_module.NS_DC, "exif": app_module.NS_EXIF,
      "xmp": app_module.NS_XMP, "crs": "http://ns.adobe.com/camera-raw-settings/1.0/",
      "lr": "http://ns.adobe.com/lightroom/1.0/"}


def _desc(xml_bytes):
    doc = minidom.parseString(xml_bytes)
    return doc, doc.getElementsByTagNameNS(NS["rdf"], "Description")[0]


def test_xmp_update_preserves_unrelated_fields_and_prefixes(env):
    raw = env.root / "IMG_1.cr2"; raw.write_bytes(b"fake raw")
    side = env.root / "IMG_1.xmp"; side.write_text(LIGHTROOM_SIDECAR, encoding="utf-8")
    app_module._write_xmp_sidecar(str(raw), "Smith & Sons <Farm>", 45.5, -73.25, "2024-06-12T10:00:00")
    out = side.read_bytes()
    text = out.decode("utf-8")
    doc, d = _desc(out)
    # Unrelated metadata untouched.
    assert d.getAttributeNS(NS["xmp"], "Rating") == "4"
    assert d.getAttributeNS(NS["crs"], "Exposure2012") == "+0.35"
    assert "<rdf:li>family</rdf:li>" in text and "People|Family" in text
    assert "Ancienne légende" in text
    # Original prefixes kept (no ns0:/ns1: rewriting) and xpacket wrapper kept.
    for prefix in ("xmp:", "crs:", "lr:", "dc:", "exif:", "rdf:"):
        assert prefix in text
    assert "ns0:" not in text
    assert text.startswith("<?xpacket begin=") and text.rstrip().endswith("?>")
    # Intended fields updated, in the form they already had (attributes).
    assert d.getAttributeNS(NS["xmp"], "CreateDate") == "2024-06-12T10:00:00"
    assert d.getAttributeNS(NS["exif"], "GPSLatitude") == "45,30.000000N"
    assert d.getElementsByTagNameNS(NS["exif"], "GPSLongitude")[0].firstChild.data == "73,15.000000W"
    lis = d.getElementsByTagNameNS(NS["rdf"], "li")
    defaults = [li for li in lis if li.getAttributeNS(app_module.NS_XML, "lang") == "x-default"]
    assert len(defaults) == 1 and defaults[0].firstChild.data == "Smith & Sons <Farm>"


def test_xmp_only_requested_fields_change(env):
    raw = env.root / "IMG_2.nef"; raw.write_bytes(b"raw")
    side = env.root / "IMG_2.xmp"; side.write_text(LIGHTROOM_SIDECAR, encoding="utf-8")
    app_module._write_xmp_sidecar(str(raw), "New caption", None, None, None)
    _, d = _desc(side.read_bytes())
    assert d.getAttributeNS(NS["xmp"], "CreateDate") == "2001-01-01T00:00:00"
    assert d.getAttributeNS(NS["exif"], "GPSLatitude") == "10,0.000000N"


def test_new_sidecar_is_valid_xmp(env):
    raw = env.root / "new.dng"; raw.write_bytes(b"raw")
    app_module._write_xmp_sidecar(str(raw), "Paris", 48.8584, 2.2945, None)
    doc, d = _desc((env.root / "new.xmp").read_bytes())
    assert d.getElementsByTagNameNS(NS["exif"], "GPSLatitude")[0].firstChild.data.endswith("N")
    assert not d.getElementsByTagNameNS(NS["xmp"], "CreateDate")  # nothing written for absent fields


@pytest.mark.parametrize("bad", [
    b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><unclosed></x:xmpmeta>",
    b"not xml at all",
    b"<!DOCTYPE x [<!ENTITY e 'boom'>]><x:xmpmeta xmlns:x='adobe:ns:meta/'>&e;</x:xmpmeta>",
    b"<x:xmpmeta xmlns:x='adobe:ns:meta/'/>",  # no rdf:RDF
])
def test_malformed_sidecar_is_refused_and_left_untouched(env, bad):
    raw = env.root / "IMG_3.cr2"; raw.write_bytes(b"raw")
    side = env.root / "IMG_3.xmp"; side.write_bytes(bad)
    with pytest.raises(app_module.SidecarError):
        app_module._write_xmp_sidecar(str(raw), "X", 1.0, 2.0, None)
    assert side.read_bytes() == bad
    assert [p.name for p in env.root.iterdir() if p.name.endswith(".tmp")] == []


def test_jpeg_write_preserves_other_exif_and_is_atomic(env):
    p = make_jpeg(env.root / "a.jpg")
    app_module._write_jpeg_exif(str(p), "Lisbon", 38.7, -9.1, "2024-01-02T03:04:05")
    ex = piexif.load(str(p))
    assert ex["0th"][piexif.ImageIFD.Make] == b"TestCam"
    assert ex["0th"][piexif.ImageIFD.Software] == b"KeepMe 1.0"
    assert ex["Exif"][piexif.ExifIFD.LensModel] == b"KeepLens 50mm"
    assert ex["0th"][piexif.ImageIFD.ImageDescription] == b"Lisbon"
    assert [x.name for x in env.root.iterdir()] == ["a.jpg"]  # no temp files left


def test_failed_jpeg_write_leaves_original_intact(env, monkeypatch):
    p = make_jpeg(env.root / "b.jpg")
    before = p.read_bytes()
    def boom(*a, **k):
        raise OSError("disk full")
    with monkeypatch.context() as m:
        m.setattr(app_module.os, "replace", boom)
        with pytest.raises(OSError):
            app_module._write_jpeg_exif(str(p), "X", None, None, None)
    assert p.read_bytes() == before
    assert [x.name for x in env.root.iterdir()] == ["b.jpg"]


def test_rename_refuses_to_overwrite_unrelated_destination_sidecar(env):
    raw = env.root / "IMG_9.cr2"; raw.write_bytes(b"raw-9")
    (env.root / "IMG_9.xmp").write_text(LIGHTROOM_SIDECAR, encoding="utf-8")
    unrelated = env.root / "Trip.xmp"; unrelated.write_text("<keep-me/>", encoding="utf-8")
    env.add_photo(raw)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/rename_batch", json={"items": [{"id": "IMG_9.cr2", "new_filename": "Trip.cr2"}],
                                             "dry_run": False})
    res = r.json["results"][0]
    assert not res["ok"] and "already exists" in res["error"]
    assert raw.exists() and (env.root / "IMG_9.xmp").exists()      # nothing moved
    assert unrelated.read_text(encoding="utf-8") == "<keep-me/>"     # nothing overwritten
    assert not (env.root / "Trip.cr2").exists()


def test_rename_refuses_existing_destination_photo(env):
    a = make_jpeg(env.root / "a.jpg"); b = make_jpeg(env.root / "b.jpg", color=(1, 2, 3))
    before = b.read_bytes()
    env.add_photo(a)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/rename_batch", json={"items": [{"id": "a.jpg", "new_filename": "b.jpg"}]})
    assert not r.json["results"][0]["ok"]
    assert b.read_bytes() == before and a.exists()


@pytest.mark.parametrize("name", ["../escape.jpg", "sub/x.jpg", "..", ".hidden.jpg", "x.png", "CON.jpg",
                                  "a\x00b.jpg"])
def test_rename_rejects_unsafe_names(env, name):
    a = make_jpeg(env.root / "a.jpg")
    env.add_photo(a)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/rename_batch", json={"items": [{"id": "a.jpg", "new_filename": name}]})
    assert not r.json["results"][0]["ok"]
    assert a.exists()
    # Also refused when staging in dry-run.
    env.app.set_setting("dry_run", "true")
    r = env.post("/api/rename_batch", json={"items": [{"id": "a.jpg", "new_filename": name}]})
    assert not r.json["results"][0]["ok"]


def test_rename_moves_own_sidecar_with_photo(env):
    raw = env.root / "IMG_5.cr2"; raw.write_bytes(b"raw")
    (env.root / "IMG_5.xmp").write_text(LIGHTROOM_SIDECAR, encoding="utf-8")
    env.add_photo(raw)
    env.app.set_setting("dry_run", "false")
    r = env.post("/api/rename_batch", json={"items": [{"id": "IMG_5.cr2", "new_filename": "Beach.cr2"}]})
    assert r.json["results"][0]["ok"], r.json
    assert (env.root / "Beach.cr2").exists() and (env.root / "Beach.xmp").exists()
    assert not (env.root / "IMG_5.xmp").exists()


def test_move_to_duplicates_never_overwrites_existing_sidecar(env):
    raw = env.root / "sub" / "D.cr2"; raw.parent.mkdir(); raw.write_bytes(b"dup")
    (env.root / "sub" / "D.xmp").write_text("<mine/>", encoding="utf-8")
    dd = env.root / "_duplicates" / "sub"; dd.mkdir(parents=True)
    (dd / "D.xmp").write_text("<someone-elses/>", encoding="utf-8")  # sidecar name taken, photo name free
    env.add_photo(raw)
    row = env.row(os.path.join("sub", "D.cr2"))
    conn = app_module._connect_db()
    app_module._move_to_duplicates_folder(conn, row)
    conn.commit(); conn.close()
    assert (dd / "D.xmp").read_text(encoding="utf-8") == "<someone-elses/>"
    assert (dd / "D (1).cr2").read_bytes() == b"dup"
    assert (dd / "D (1).xmp").read_text(encoding="utf-8") == "<mine/>"


def test_move_no_clobber(env):
    a = env.root / "a.bin"; a.write_bytes(b"a")
    b = env.root / "b.bin"; b.write_bytes(b"b")
    with pytest.raises(FileExistsError):
        app_module.move_no_clobber(a, b)
    assert a.read_bytes() == b"a" and b.read_bytes() == b"b"
    app_module.move_no_clobber(a, env.root / "c.bin")
    assert not a.exists() and (env.root / "c.bin").read_bytes() == b"a"


def test_commit_pending_uses_library_path_and_preserves_sidecar(env):
    raw = env.root / "IMG_7.arw"; raw.write_bytes(b"raw")
    side = env.root / "IMG_7.xmp"; side.write_text(LIGHTROOM_SIDECAR, encoding="utf-8")
    env.add_photo(raw)
    r = env.post("/api/save", json={"id": "IMG_7.arw", "location_name": "Oslo", "lat": 59.9, "lon": 10.7})
    assert r.json.get("dry_run") is True
    r = env.post("/api/pending/commit", json={})
    assert r.json["committed"] == 1, r.json
    text = side.read_text(encoding="utf-8")
    assert "Oslo" in text and "family" in text and 'Rating="4"' in text
