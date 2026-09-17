#!/usr/bin/env python3
"""Run a single search pass for one profile (or all profiles) from the
command line, without going through the web UI.

Useful for triggering a run from an external cron job, a CI schedule, or
just testing, instead of relying on the app's built-in scheduler.

Usage:
    python scripts/run_once.py --slug jane-smith
    python scripts/run_once.py --all
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from core import db
from core.scheduler import run_search_for_profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--slug", help="Run the search for a single profile by its slug.")
    group.add_argument("--all", action="store_true", help="Run the search for every profile.")
    args = parser.parse_args()

    db.init_db()

    if args.all:
        profiles = db.list_profiles()
    else:
        profile = db.get_profile_by_slug(args.slug)
        if profile is None:
            print(f"No profile found with slug '{args.slug}'.", file=sys.stderr)
            sys.exit(1)
        profiles = [profile]

    for profile in profiles:
        print(f"Searching for {profile['name']} ({profile['slug']})...")
        try:
            n = run_search_for_profile(profile["id"])
            print(f"  -> {n} new posting(s).")
        except Exception as e:  # noqa: BLE001
            print(f"  -> failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
