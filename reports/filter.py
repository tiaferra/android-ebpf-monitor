#!/usr/bin/env python3
"""
reports/filter.py

Reads <session_dir>/events.jsonl, presents all UIDs found in the session,
lets you select one or more, then writes a filtered copy of the session
into a new sibling directory that summary.py can consume directly.

Output directory name:
  <original_name>_uid<X>            (single UID)
  <original_name>_uid<X>_<Y>_<Z>   (multiple UIDs)

Usage:
  python3 reports/filter.py sessions/<session_dir>
"""

import argparse
import json
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── UID range label ────────────────────────────────────────────────────────────

_KNOWN_UIDS: Dict[int, str] = {
    0:    "root",
    1000: "system",
    1001: "radio",
    1002: "bluetooth",
    1003: "graphics",
    1004: "input",
    1005: "audio",
    1006: "camera",
    1007: "log",
    1009: "mount",
    1010: "wifi",
    1011: "adb",
    1013: "media",
    1014: "dhcp",
    1016: "vpn",
    1017: "keystore",
    1019: "drm",
    1021: "gps",
    1027: "nfc",
    1036: "logd",
    1041: "audioserver",
    1046: "cameraserver",
    1050: "dns",
    1052: "webview_zygote",
    1065: "statsd",
    1068: "lmkd",
    1072: "network_stack",
    2000: "shell",
    2001: "cache",
}


def uid_label(uid: int) -> str:
    if uid in _KNOWN_UIDS:
        return f"system  ({_KNOWN_UIDS[uid]})"
    if uid < 10000:
        return "system"
    if uid < 99999:
        return "app"
    return "isolated"


# ── Event loading (mirrors summary.py) ────────────────────────────────────────

def load_events(events_path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with events_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue
    return events


# ── UID table ─────────────────────────────────────────────────────────────────

def build_uid_table(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    uid_events: Counter = Counter()
    uid_comms: Dict[int, Set[str]] = defaultdict(set)

    for ev in events:
        uid = ev.get("uid")
        comm = ev.get("comm", "?")
        if not isinstance(uid, int):
            continue
        uid_events[uid] += 1
        if isinstance(comm, str) and comm:
            uid_comms[uid].add(comm)

    table = []
    for uid, count in uid_events.most_common():
        procs = sorted(uid_comms[uid])
        table.append({
            "uid":         uid,
            "label":       uid_label(uid),
            "event_count": count,
            "processes":   procs,
        })

    # App UIDs first (most interesting), then by event count descending
    table.sort(key=lambda r: (0 if r["uid"] >= 10000 else 1, -r["event_count"]))
    return table


def print_uid_table(table: List[Dict[str, Any]], total: int) -> None:
    print()
    print(f"  Found {len(table)} UIDs across {total} total events")
    print()
    print(f"  {'#':<4} {'UID':<8} {'Range':<22} {'Events':>7}   Processes")
    print("  " + "─" * 78)
    for i, row in enumerate(table, start=1):
        procs = row["processes"]
        if len(procs) <= 4:
            procs_str = ", ".join(procs)
        else:
            procs_str = ", ".join(procs[:4]) + f"  ... (+{len(procs) - 4} more)"
        print(f"  {i:<4} {row['uid']:<8} {row['label']:<22} {row['event_count']:>7}   {procs_str}")
    print("  " + "─" * 78)


# ── Selection prompt ──────────────────────────────────────────────────────────

def prompt_selection(table: List[Dict[str, Any]]) -> Optional[List[int]]:
    n = len(table)
    print()
    print("  Selection options:")
    print("  Single UID        1")
    print("  Multiple UIDs     1 3")
    print("  All app UIDs      A     (keeps everything >= 10000)")
    print("  All UIDs          ALL   (no filter — re-emit everything)")
    print("  Quit              Q")
    print()

    while True:
        try:
            raw = input("  Your selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if not raw:
            print("  Please enter a selection.")
            continue

        upper = raw.upper()

        if upper == "Q":
            return None

        if upper == "ALL":
            return [row["uid"] for row in table]

        if upper == "A":
            app_uids = [row["uid"] for row in table if row["uid"] >= 10000]
            if not app_uids:
                print("  [!] No app UIDs (>= 10000) found in this session.")
                continue
            return app_uids

        # Parse space-separated numbers
        tokens = raw.split()
        selected_uids: List[int] = []
        valid = True
        seen: Set[int] = set()

        for token in tokens:
            if not token.isdigit():
                print(f"  [!] Invalid token '{token}' — use numbers, A, ALL or Q.")
                valid = False
                break
            idx = int(token) - 1
            if idx < 0 or idx >= n:
                print(f"  [!] Number {token} is out of range (1–{n}).")
                valid = False
                break
            uid = table[idx]["uid"]
            if uid not in seen:
                selected_uids.append(uid)
                seen.add(uid)

        if valid and selected_uids:
            return selected_uids


# ── Output directory name ─────────────────────────────────────────────────────

def make_output_name(original_name: str, uids: List[int]) -> str:
    suffix = "_".join(str(u) for u in sorted(uids))
    return f"{original_name}_uid{suffix}"


# ── Write filtered session ────────────────────────────────────────────────────

def write_filtered_session(
    source_dir: Path,
    output_dir: Path,
    uids: Set[int],
    events: List[Dict[str, Any]],
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)

    filtered = [ev for ev in events if ev.get("uid") in uids]

    out_events = output_dir / "events.jsonl"
    with out_events.open("w", encoding="utf-8") as f:
        for ev in filtered:
            f.write(json.dumps(ev) + "\n")

    # Copy session.json so summary.py can read probe metadata
    src_session = source_dir / "session.json"
    if src_session.exists():
        shutil.copy2(src_session, output_dir / "session.json")

    return len(filtered)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Interactively filter events.jsonl by UID and write a new session directory."
    )
    ap.add_argument(
        "session_path",
        help="Path to a session directory (must contain events.jsonl)",
    )
    args = ap.parse_args()

    session_path = Path(args.session_path).expanduser().resolve()
    events_path  = session_path / "events.jsonl"

    if not session_path.is_dir():
        print(f"ERROR: '{session_path}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    if not events_path.exists():
        print(f"ERROR: events.jsonl not found in '{session_path}'.", file=sys.stderr)
        sys.exit(1)

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"\n  Loading events from: {session_path.name} ...", end="", flush=True)
    events = load_events(events_path)
    print(f"  ({len(events)} events)")

    if not events:
        print("ERROR: events.jsonl is empty.", file=sys.stderr)
        sys.exit(1)

    # ── Build and display UID table ───────────────────────────────────────────
    table = build_uid_table(events)

    if not table:
        print("ERROR: no events with a valid UID field found.", file=sys.stderr)
        sys.exit(1)

    print_uid_table(table, len(events))

    # ── Interactive selection ─────────────────────────────────────────────────
    selected_uids = prompt_selection(table)

    if selected_uids is None:
        print("\n  Aborted.\n")
        sys.exit(0)

    # ── Write output ──────────────────────────────────────────────────────────
    output_name = make_output_name(session_path.name, selected_uids)
    output_dir  = session_path.parent / output_name

    if output_dir.exists():
        print(f"\n  [!] Output directory already exists: {output_dir.name}")
        try:
            confirm = input("  Overwrite? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.\n")
            sys.exit(0)
        if confirm != "y":
            print("  Aborted.\n")
            sys.exit(0)
        shutil.rmtree(output_dir)

    uid_set = set(selected_uids)
    written = write_filtered_session(session_path, output_dir, uid_set, events)
    pct = (written / len(events) * 100) if events else 0

    print()
    print(f"  Filtered:  {written} / {len(events)} events  ({pct:.1f}%)")
    print(f"  UIDs kept: {', '.join(str(u) for u in sorted(selected_uids))}")
    print(f"  Output:    {output_dir.name}")
    print()
    print("  To generate the report run:")
    print(f"    python3 reports/summary.py {output_dir}")
    print()


if __name__ == "__main__":
    main()
