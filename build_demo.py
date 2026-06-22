#!/usr/bin/env python3
"""build_demo.py — generate nmap.org demo data for the gobuster-recon web UI."""

import json
import subprocess
import sys
import datetime
from pathlib import Path

TARGET       = "https://nmap.org"
DOMAIN       = "nmap.org"
TARGET_FILE  = Path("web/data/targets") / f"{DOMAIN}.json"
INDEX_FILE   = Path("web/data/index.json")
DISPLAY_NAME = "fmfalgun"
DISPLAY_LOC  = "Chennai, India"


def run_tool():
    print(f"[*] Running gobuster-recon.py on {TARGET}...")
    result = subprocess.run(
        ["python3", "gobuster-recon.py", "-u", TARGET, "-o", str(TARGET_FILE), "--no-cache"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[WARN] gobuster-recon.py exited {result.returncode}:\n{result.stderr[:300]}")
    if not TARGET_FILE.exists():
        print(f"[ERROR] {TARGET_FILE} not created — aborting")
        sys.exit(1)
    print(f"[OK] wrote {TARGET_FILE}")


def update_target_file():
    with open(TARGET_FILE) as f:
        data = json.load(f)
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    data["display_name"]   = DISPLAY_NAME
    data["display_loc"]    = DISPLAY_LOC
    data["last_refreshed"] = now
    with open(TARGET_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return data


def update_index(data):
    now = data.get("last_refreshed", "")
    entry = {
        "d":             DOMAIN,
        "url":           TARGET,
        "display_name":  DISPLAY_NAME,
        "display_loc":   DISPLAY_LOC,
        "scanned_at":    data.get("scanned_at", now),
        "last_refreshed": now,
        "finding_count": data.get("finding_count", 0),
        "status_2xx":    data.get("status_2xx", 0),
        "status_3xx":    data.get("status_3xx", 0),
        "has_admin":     bool(data.get("has_admin")),
        "has_login":     bool(data.get("has_login")),
        "has_phpmyadmin": bool(data.get("has_phpmyadmin")),
        "has_git":       bool(data.get("has_git")),
        "has_env":       bool(data.get("has_env")),
        "has_backup":    bool(data.get("has_backup")),
        "mode":          data.get("mode", "dir"),
        "method":        data.get("method", "gobuster"),
        "wordlist":      data.get("wordlist", ""),
    }

    try:
        with open(INDEX_FILE) as f:
            index = json.load(f)
    except Exception:
        index = {"total_targets": 0, "targets": []}

    existing = [t for t in index.get("targets", []) if t["d"] != DOMAIN]
    existing.append(entry)
    existing.sort(key=lambda t: -(t.get("finding_count", 0)))
    index["targets"]       = existing
    index["total_targets"] = len(existing)

    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)
    print(f"[OK] updated {INDEX_FILE}")


if __name__ == "__main__":
    TARGET_FILE.parent.mkdir(parents=True, exist_ok=True)
    run_tool()
    data = update_target_file()
    update_index(data)
    print("[DONE]")
