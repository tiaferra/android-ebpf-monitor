#!/usr/bin/env python3
"""
reports/trace_ipc.py

Loads a session's events.jsonl, lets you pick a starting process
interactively, then follows Binder IPC transactions transitively up to
a configurable depth and prints the discovered call chain.

Usage:
  python3 reports/trace_ipc.py sessions/<session_dir>
  python3 reports/trace_ipc.py sessions/<session_dir> --depth 5
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Package name → UID map (from pm list packages -U) ─────────────────────────
# Embedded from uid.txt so the tool works offline inside the miniDebian.
# Keys are short readable names derived from the package name.
_PACKAGE_UIDS: Dict[int, List[str]] = {
    1000:  ["settings", "android", "keychain", "providers.settings",
            "server.telecom", "location.fused", "inputdevices",
            "DeviceAsWebcam", "localtransport", "dynsystem"],
    1001:  ["stk", "mms.service", "ons", "phone", "providers.telephony"],
    1002:  ["bluetooth"],
    1027:  ["nfc"],
    1068:  ["se"],
    1073:  ["networkstack", "networkstack.tethering", "cellbroadcastservice"],
    2000:  ["shell"],
    10060: ["settings.intelligence"],
    10066: ["gallery3d"],
    10064: ["webview_shell"],
    10067: ["camera2"],
    10071: ["inputmethod.latin"],
    10075: ["messaging"],
    10080: ["launcher3"],
    10086: ["systemui"],
    10107: ["wifi.dialog"],
}

# Invert: uid → comma-separated short package names
def _uid_to_packages(uid: int) -> str:
    pkgs = _PACKAGE_UIDS.get(uid)
    if pkgs:
        return ", ".join(pkgs[:3]) + ("  ..." if len(pkgs) > 3 else "")
    return ""


# ── UID range label ────────────────────────────────────────────────────────────
_KNOWN_UIDS: Dict[int, str] = {
    0:    "root",
    1000: "system",
    1001: "radio",
    1002: "bluetooth",
    1010: "wifi",
    1027: "nfc",
    1068: "se",
    1072: "network_stack",
    1073: "networkstack",
    2000: "shell",
}

def uid_label(uid: int) -> str:
    if uid in _KNOWN_UIDS:
        return _KNOWN_UIDS[uid]
    if uid < 10000:
        return f"system({uid})"
    return f"app({uid})"


# ── Event loading ──────────────────────────────────────────────────────────────
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


# ── Build lookup structures from events ───────────────────────────────────────
def build_indexes(events: List[Dict[str, Any]]):
    """
    Returns:
      pid_info   : pid → { comm, uid }
      binder_tx  : pid → list of { to_proc, debug_id, oneway, code }
    Only binder_transaction events are indexed (not received/alloc_buf).
    """
    pid_info: Dict[int, Dict[str, Any]] = {}
    binder_tx: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    for ev in events:
        pid  = ev.get("pid")
        comm = ev.get("comm", "?")
        uid  = ev.get("uid")

        # Build pid → comm/uid from any event
        if isinstance(pid, int):
            if pid not in pid_info:
                pid_info[pid] = {"comm": comm, "uid": uid}
            else:
                # Keep the most informative comm (not "?")
                if pid_info[pid]["comm"] == "?" and comm != "?":
                    pid_info[pid]["comm"] = comm
                if pid_info[pid]["uid"] is None and uid is not None:
                    pid_info[pid]["uid"] = uid

        # Index binder transactions only
        if ev.get("event") != "binder_transaction":
            continue

        data = ev.get("data", {})
        if not isinstance(data, dict):
            continue

        to_pid = data.get("to_pid")
        if not isinstance(to_pid, int) or to_pid == 0:
            continue

        if isinstance(pid, int):
            binder_tx[pid].append({
                "to_proc":  to_pid,
                "debug_id": data.get("debug_id"),
                "oneway":   data.get("oneway", 0),
                "code":     data.get("code"),
            })

    return pid_info, binder_tx


# ── Process table for interactive selection ───────────────────────────────────
def build_process_table(pid_info: Dict[int, Dict[str, Any]],
                        binder_tx: Dict[int, List[Dict[str, Any]]],
                        events: List[Dict[str, Any]]) -> List[Dict]:

    # Build pid → index of first appearance in events.jsonl
    first_seen: Dict[int, int] = {}
    for i, ev in enumerate(events):
        pid = ev.get("pid")
        if isinstance(pid, int) and pid not in first_seen:
            first_seen[pid] = i

    rows = []
    for pid, info in pid_info.items():
        uid      = info.get("uid")
        comm     = info.get("comm", "?")
        tx_count = len(binder_tx.get(pid, []))
        rows.append({
            "pid":        pid,
            "comm":       comm,
            "uid":        uid,
            "tx_count":   tx_count,
            "packages":   _uid_to_packages(uid) if isinstance(uid, int) else "",
            "first_seen": first_seen.get(pid, 999999999),
        })

    # Chronological order — first appearance in the event stream
    rows.sort(key=lambda r: r["first_seen"])
    return rows

def print_process_table(rows: List[Dict]) -> None:
    # Only show processes that have at least one outgoing binder transaction —
    # the others can't be useful starting points.
    active = [r for r in rows if r["tx_count"] > 0]
    inactive_count = len(rows) - len(active)

    print()
    print(f"  Processes with outgoing Binder transactions  "
          f"({inactive_count} processes with no Binder activity hidden)")
    print()
    print(f"  {'#':<4} {'PID':<7} {'UID':<7} {'Label':<16} {'TX':>4}   "
          f"{'comm':<20} Packages")
    print("  " + "─" * 85)

    for i, r in enumerate(active, start=1):
        uid     = r["uid"] if r["uid"] is not None else "?"
        label   = uid_label(r["uid"]) if isinstance(r["uid"], int) else "?"
        pkgs    = r["packages"]
        print(f"  {i:<4} {r['pid']:<7} {uid:<7} {label:<16} {r['tx_count']:>4}   "
              f"{r['comm']:<20} {pkgs}")

    print("  " + "─" * 85)
    return active   # return filtered list so selection indexes match


# ── Interactive process selection ─────────────────────────────────────────────
def prompt_process(active: List[Dict]) -> Optional[Dict]:
    n = len(active)
    print()
    print("  Enter the number of the process to start tracing from.")
    print("  Quit   Q")
    print()

    while True:
        try:
            raw = input("  Your selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if raw.upper() == "Q":
            return None

        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < n:
                return active[idx]

        print(f"  [!] Enter a number between 1 and {n}, or Q.")


# ── Binder chain traversal ────────────────────────────────────────────────────
class ChainNode:
    def __init__(self, pid: int, comm: str, uid: Any, tx_count: int):
        self.pid      = pid
        self.comm     = comm
        self.uid      = uid
        self.tx_count = tx_count
        self.children: List["ChainNode"] = []


def traverse(
    start_pid: int,
    pid_info:  Dict[int, Dict[str, Any]],
    binder_tx: Dict[int, List[Dict[str, Any]]],
    max_depth: int,
) -> Tuple[ChainNode, Set[int], Set[int]]:
    """
    BFS traversal of the Binder call graph starting from start_pid.
    Returns (root_node, all_pids_found, all_uids_found).
    """
    info     = pid_info.get(start_pid, {})
    root     = ChainNode(
        pid      = start_pid,
        comm     = info.get("comm", "?"),
        uid      = info.get("uid"),
        tx_count = len(binder_tx.get(start_pid, [])),
    )

    all_pids: Set[int] = {start_pid}
    all_uids: Set[int] = set()
    if isinstance(info.get("uid"), int):
        all_uids.add(info["uid"])

    # BFS queue: (node, current_depth)
    queue: List[Tuple[ChainNode, int]] = [(root, 0)]

    while queue:
        node, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        txs = binder_tx.get(node.pid, [])
        # Collect unique to_proc pids this node talks to
        seen_children: Set[int] = set()
        for tx in txs:
            to_pid = tx["to_proc"]
            if to_pid in all_pids or to_pid in seen_children:
                continue
            seen_children.add(to_pid)

        for to_pid in sorted(seen_children):
            child_info = pid_info.get(to_pid, {})
            child_uid  = child_info.get("uid")
            tx_to_child = sum(
                1 for tx in txs if tx["to_proc"] == to_pid
            )
            child_node = ChainNode(
                pid      = to_pid,
                comm     = child_info.get("comm", "?"),
                uid      = child_uid,
                tx_count = tx_to_child,
            )
            node.children.append(child_node)
            all_pids.add(to_pid)
            if isinstance(child_uid, int):
                all_uids.add(child_uid)
            queue.append((child_node, depth + 1))

    return root, all_pids, all_uids


# ── Tree rendering ─────────────────────────────────────────────────────────────
def render_tree(node: ChainNode, prefix: str = "", is_last: bool = True) -> List[str]:
    connector = "└── " if is_last else "├── "
    uid_str   = str(node.uid) if node.uid is not None else "?"
    label     = uid_label(node.uid) if isinstance(node.uid, int) else "?"
    pkgs      = _uid_to_packages(node.uid) if isinstance(node.uid, int) else ""
    pkg_str   = f"  [{pkgs}]" if pkgs else ""

    line = (
        f"{prefix}{connector}{node.comm}"
        f"  (pid {node.pid}, uid {uid_str} / {label})"
        f"  {node.tx_count} tx"
        f"{pkg_str}"
    )

    lines = [line]
    child_prefix = prefix + ("    " if is_last else "│   ")

    for i, child in enumerate(node.children):
        last = (i == len(node.children) - 1)
        lines.extend(render_tree(child, child_prefix, last))

    return lines


def print_chain(root: ChainNode, all_pids: Set[int], all_uids: Set[int]) -> None:
    uid_str  = str(root.uid) if root.uid is not None else "?"
    label    = uid_label(root.uid) if isinstance(root.uid, int) else "?"
    pkgs     = _uid_to_packages(root.uid) if isinstance(root.uid, int) else ""
    pkg_str  = f"  [{pkgs}]" if pkgs else ""

    print()
    print("  IPC chain")
    print("  " + "─" * 78)

    # Print root manually, then children
    root_line = (
        f"  {root.comm}"
        f"  (pid {root.pid}, uid {uid_str} / {label})"
        f"  {root.tx_count} tx"
        f"{pkg_str}"
    )
    print(root_line)

    for i, child in enumerate(root.children):
        last  = (i == len(root.children) - 1)
        lines = render_tree(child, prefix="  ", is_last=last)
        for line in lines:
            print(line)

    print("  " + "─" * 78)
    print()

    uid_list = ", ".join(str(u) for u in sorted(all_uids))
    pid_list = ", ".join(str(p) for p in sorted(all_pids))

    print(f"  PIDs discovered: {len(all_pids)}  →  {pid_list}")
    print(f"  UIDs discovered: {len(all_uids)}  →  {uid_list}")
    print()
    print("  To filter your session with these UIDs:")
    print(f"    python3 reports/filter.py <session_dir>")
    print(f"    then select: {uid_list}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Trace Binder IPC chains from a starting process in a session."
    )
    ap.add_argument(
        "session_path",
        help="Path to a session directory (must contain events.jsonl)",
    )
    ap.add_argument(
        "--depth", type=int, default=3,
        help="Maximum traversal depth (default: 3)",
    )
    ap.add_argument(
        "--out", default="reports/ipc_chains",
        help="Output directory for saved chain reports (default: reports/ipc_chains)",
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

    # ── Build indexes ─────────────────────────────────────────────────────────
    pid_info, binder_tx = build_indexes(events)

    if not binder_tx:
        print()
        print("  [!] No binder_transaction events found in this session.")
        print("      Make sure you ran the binder.bt probe.")
        print()
        sys.exit(1)

    # ── Show process table and prompt ─────────────────────────────────────────
    rows   = build_process_table(pid_info, binder_tx, events)
    active = print_process_table(rows)
    chosen = prompt_process(active)

    if chosen is None:
        print("\n  Aborted.\n")
        sys.exit(0)

    # ── Traverse ──────────────────────────────────────────────────────────────
    print(f"\n  Tracing from: {chosen['comm']} "
          f"(pid {chosen['pid']}, uid {chosen['uid']})  "
          f"depth={args.depth} ...")

    root, all_pids, all_uids = traverse(
        start_pid = chosen["pid"],
        pid_info  = pid_info,
        binder_tx = binder_tx,
        max_depth = args.depth,
    )

    # ── Print result ──────────────────────────────────────────────────────────
    print_chain(root, all_pids, all_uids)

    # ── Save to file ──────────────────────────────────────────────────────────
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    out_filename = f"{session_path.name}_pid{chosen['pid']}.txt"
    out_path = out_dir / out_filename

    lines = []
    lines.append(f"Session:   {session_path.name}")
    lines.append(f"Start:     {chosen['comm']}  (pid {chosen['pid']}, uid {chosen['uid']})")
    lines.append(f"Depth:     {args.depth}")
    lines.append("")

    # Render tree into lines
    lines.append("IPC chain")
    lines.append("─" * 78)
    root_line = (
        f"{root.comm}"
        f"  (pid {root.pid}, uid {root.uid} / {uid_label(root.uid) if isinstance(root.uid, int) else '?'})"
        f"  {root.tx_count} tx"
    )
    pkgs = _uid_to_packages(root.uid) if isinstance(root.uid, int) else ""
    if pkgs:
        root_line += f"  [{pkgs}]"
    lines.append(root_line)
    for i, child in enumerate(root.children):
        last = (i == len(root.children) - 1)
        for l in render_tree(child, prefix="", is_last=last):
            lines.append(l)
    lines.append("─" * 78)
    lines.append("")
    lines.append(f"PIDs discovered: {len(all_pids)}  →  {', '.join(str(p) for p in sorted(all_pids))}")
    lines.append(f"UIDs discovered: {len(all_uids)}  →  {', '.join(str(u) for u in sorted(all_uids))}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  [saved] {out_path}")
"""

The output file will be named after the session and the starting pid, for example:
reports/ipc_chains/P00011_2026-03-04_10-18-52_pid3421.txt

"""
if __name__ == "__main__":
    main()
