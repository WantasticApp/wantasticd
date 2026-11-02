#!/usr/bin/env python3
"""Builds the direct build's update feed for one release.

For each previous release APK it writes a bsdiff patch to the new APK,
checks the patch with bspatch (the result must be byte-identical), and
writes update.json, which the app reads from
https://get.wantastic.app/android/latest/update.json.

    release_update.py --version 0.3.0 --code 130 --apk dist/versioned/wantastic-android-0.3.0.apk \
        --previous prev/ --versioned dist/versioned --latest dist/latest
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

BASE = "https://get.wantastic.app/android"


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--code", type=int, required=True)
    ap.add_argument("--apk", type=pathlib.Path, required=True)
    ap.add_argument("--previous", type=pathlib.Path, required=True, help="directory of earlier release APKs")
    ap.add_argument("--versioned", type=pathlib.Path, required=True)
    ap.add_argument("--latest", type=pathlib.Path, required=True)
    a = ap.parse_args()

    new_sha = sha256(a.apk)
    patches_dir = a.versioned / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patches = []
    for old in sorted(a.previous.glob("*.apk")):
        old_sha = sha256(old)
        if old_sha == new_sha:
            continue
        patch = patches_dir / f"{old_sha}.bsdiff"
        subprocess.run(["bsdiff", str(old), str(a.apk), str(patch)], check=True)
        with tempfile.TemporaryDirectory() as tmp:
            rebuilt = pathlib.Path(tmp) / "rebuilt.apk"
            subprocess.run(["bspatch", str(old), str(rebuilt), str(patch)], check=True)
            if sha256(rebuilt) != new_sha:
                raise SystemExit(f"patch from {old.name} does not rebuild the new APK")
        # A patch nearly as big as the APK saves nothing; the app downloads the APK then.
        if patch.stat().st_size > a.apk.stat().st_size * 0.8:
            patch.unlink()
            print(f"{old.name}: patch not worth it, skipped")
            continue
        patches.append({
            "from": old_sha,
            "url": f"{BASE}/{a.version}/patches/{patch.name}",
            "sha256": sha256(patch),
            "size": patch.stat().st_size,
        })
        print(f"{old.name}: patch {patch.stat().st_size} bytes (APK {a.apk.stat().st_size})")

    feed = {
        "version": a.version,
        "versionCode": a.code,
        "apk": {
            "url": f"{BASE}/{a.version}/{a.apk.name}",
            "sha256": new_sha,
            "size": a.apk.stat().st_size,
        },
        "patches": patches,
    }
    a.latest.mkdir(parents=True, exist_ok=True)
    (a.latest / "update.json").write_text(json.dumps(feed, indent=1) + "\n")
    print(json.dumps(feed, indent=1))


if __name__ == "__main__":
    main()
