#!/usr/bin/env python3
"""Wipe this machine's local data (the SQLite database and any uploaded
files) so you can start over with a completely empty app -- no accounts, no
profiles, no postings.

This only ever touches your own local data/ and uploads/ folders. It never
touches git, and it never affects anyone else's copy of this app -- there's
no shared or remote data anywhere in this project.

Usage:
    python scripts/reset_local_data.py          # asks for confirmation
    python scripts/reset_local_data.py --yes    # skips the confirmation
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    args = parser.parse_args()

    data_dir = Path(__import__("os").environ.get("JOB_AGENT_DATA_DIR", ROOT / "data"))
    uploads_dir = ROOT / "uploads"

    db_path = data_dir / "job_agent.db"
    targets = [p for p in [db_path] if p.exists()]
    upload_files = [p for p in uploads_dir.glob("*") if p.name != ".gitkeep"] if uploads_dir.exists() else []

    if not targets and not upload_files:
        print("Nothing to reset -- there's no local database or uploaded files yet.")
        return

    print("This will permanently delete:")
    for p in targets:
        print(f"  - {p}")
    for p in upload_files:
        print(f"  - {p}")

    if not args.yes:
        answer = input("\nType 'yes' to delete this local data: ").strip().lower()
        if answer != "yes":
            print("Cancelled -- nothing was deleted.")
            sys.exit(1)

    for p in targets:
        p.unlink()
    for p in upload_files:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()

    print("Done. Run the app again and it'll create a fresh, empty database.")


if __name__ == "__main__":
    main()
