#!/usr/bin/env python3
"""
reports/summary.py

Reads:
  - <session>/events.jsonl
  - <session>/session.json (optional)

Writes:
  - <session>/index.json
  - reports/summaries/<session_id>.md  (plus prints to stdout)

Usage:
  python3 reports/summary.py sessions/<timestamp>
  python3 reports/summary.py sessions/<timestamp> --out reports/summaries
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _parse_iso_datetime(s: str) -> Optional[datetime]:
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


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


def load_session_metadata(session_path: Path) -> Optional[Dict[str, Any]]:
    session_file = session_path / "session.json"
    if not session_file.exists():
        return None
    try:
        with session_file.open("r", encoding="utf-8") as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    n = len(sorted_vals)
    k = int(p * (n - 1))
    return float(sorted_vals[max(0, min(k, n - 1))])


def compute_event_rate(session_meta: Optional[Dict[str, Any]], total_events: int) -> Optional[Dict[str, float]]:
    if not session_meta:
        return None
    start_s = session_meta.get("started_at")
    stop_s = session_meta.get("stopped_at")
    start = _parse_iso_datetime(start_s) if isinstance(start_s, str) else None
    stop = _parse_iso_datetime(stop_s) if isinstance(stop_s, str) else None
    if not start or not stop:
        return None
    duration = (stop - start).total_seconds()
    if duration <= 0:
        return None
    return {
        "duration_s": float(duration),
        "event_rate_eps": float(total_events) / float(duration),
    }


def compute_analytics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    type_counter = Counter()
    event_counter = Counter()

    proc_total = Counter()                 # comm -> total
    proc_by_type = defaultdict(Counter)    # comm -> Counter(type)
    proc_by_event = defaultdict(Counter)   # comm -> Counter(event)

    syscall_counts = Counter()
    syscall_errors = Counter()
    syscall_lat_by_name = defaultdict(list)
    all_lat_us: List[float] = []

    timeline_by_pid = defaultdict(list)    # pid -> list of (ts, type, event)
    pid_to_comm: Dict[int, str] = {}

    for ev in events:
        t = ev.get("type")
        e = ev.get("event")
        comm = ev.get("comm")
        pid = ev.get("pid")
        ts = ev.get("ts")

        if isinstance(t, str) and t:
            type_counter[t] += 1
        if isinstance(e, str) and e:
            event_counter[e] += 1

        if isinstance(comm, str) and comm:
            proc_total[comm] += 1
            if isinstance(t, str) and t:
                proc_by_type[comm][t] += 1
            if isinstance(e, str) and e:
                proc_by_event[comm][e] += 1

        if isinstance(pid, int):
            if isinstance(comm, str) and comm:
                pid_to_comm[pid] = comm
            if isinstance(e, str) and e:
                timeline_by_pid[pid].append((ts, t, e))

        if t == "syscall":
            if isinstance(e, str) and e:
                syscall_counts[e] += 1

            data = ev.get("data", {})
            if isinstance(data, dict):
                ret = data.get("ret")
                lat = data.get("lat_us")

                if isinstance(ret, int) and isinstance(e, str) and e and ret < 0:
                    syscall_errors[e] += 1

                if isinstance(lat, (int, float)):
                    lat_f = float(lat)
                    all_lat_us.append(lat_f)
                    if isinstance(e, str) and e:
                        syscall_lat_by_name[e].append(lat_f)

    syscall_error_rates = {}
    for name, cnt in syscall_counts.items():
        err = syscall_errors.get(name, 0)
        syscall_error_rates[name] = (err / cnt) if cnt else 0.0

    latency_summary = {}
    if all_lat_us:
        all_lat_us.sort()
        latency_summary = {
            "min_us": float(all_lat_us[0]),
            "p50_us": percentile(all_lat_us, 0.50),
            "p95_us": percentile(all_lat_us, 0.95),
            "p99_us": percentile(all_lat_us, 0.99),
            "max_us": float(all_lat_us[-1]),
            "n": int(len(all_lat_us)),
        }

    latency_by_syscall = {}
    for name, vals in syscall_lat_by_name.items():
        if not vals:
            continue
        vals.sort()
        latency_by_syscall[name] = {
            "p50_us": percentile(vals, 0.50),
            "p95_us": percentile(vals, 0.95),
            "p99_us": percentile(vals, 0.99),
            "max_us": float(vals[-1]),
            "n": int(len(vals)),
        }

    return {
        "total_events": int(len(events)),
        "events_by_type": dict(type_counter),
        "events_by_name": dict(event_counter),

        "top_processes": proc_total.most_common(10),

        "process_profiles": {
            comm: {
                "total": int(proc_total[comm]),
                "by_type": dict(proc_by_type[comm]),
                "by_event": dict(proc_by_event[comm]),
            }
            for comm in proc_total
        },

        "syscalls": {
            "counts": dict(syscall_counts),
            "errors": dict(syscall_errors),
            "error_rates": syscall_error_rates,
            "latency_overall": latency_summary,
            "latency_by_syscall": latency_by_syscall,
        },

        "timeline_by_pid": {str(pid): timeline_by_pid[pid] for pid in timeline_by_pid},
        "pid_to_comm": {str(pid): pid_to_comm[pid] for pid in pid_to_comm},
    }


def build_report_text(session_path: Path, summary: Dict[str, Any], timeline_max_events: int = 25) -> str:
    lines: List[str] = []

    lines.append("========== SESSION SUMMARY ==========")
    lines.append("")
    lines.append(f"Session: {session_path}")

    total = summary.get("total_events", 0)
    lines.append(f"Total events: {total}")

    er = summary.get("event_rate")
    if isinstance(er, dict):
        lines.append(f"Duration: {er.get('duration_s', 0):.3f} s")
        lines.append(f"Event rate: {er.get('event_rate_eps', 0):.3f} events/s")

    lines.append("")
    lines.append("Events by type:")
    for k, v in (summary.get("events_by_type") or {}).items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("Top processes (by total events):")
    for comm, count in summary.get("top_processes", []):
        lines.append(f"  {comm}: {count}")

    syscalls = summary.get("syscalls", {})
    counts = syscalls.get("counts", {})
    if counts:
        lines.append("")
        lines.append("Syscalls (count + error rate):")
        error_rates = syscalls.get("error_rates", {})
        errors = syscalls.get("errors", {})
        for name, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            rate = float(error_rates.get(name, 0.0)) * 100.0
            err = int(errors.get(name, 0))
            lines.append(f"  {name}: {cnt}  (errors: {err}, {rate:.2f}%)")

    lat = syscalls.get("latency_overall")
    if isinstance(lat, dict) and lat:
        lines.append("")
        lines.append("Overall syscall latency (microseconds):")
        lines.append(f"  n: {lat.get('n', 0)}")
        lines.append(f"  min: {lat.get('min_us', 0):.0f}")
        lines.append(f"  p50: {lat.get('p50_us', 0):.0f}")
        lines.append(f"  p95: {lat.get('p95_us', 0):.0f}")
        lines.append(f"  p99: {lat.get('p99_us', 0):.0f}")
        lines.append(f"  max: {lat.get('max_us', 0):.0f}")

    # Process timelines (top 5 comm; pick pid with most events)
    lines.append("")
    lines.append("Process timelines (top 5 processes):")

    top5 = [comm for comm, _ in summary.get("top_processes", [])[:5]]
    pid_to_comm = summary.get("pid_to_comm", {})
    timeline_by_pid = summary.get("timeline_by_pid", {})

    comm_pids = defaultdict(list)
    for pid_s, comm in pid_to_comm.items():
        comm_pids[comm].append(pid_s)

    for comm in top5:
        pids = comm_pids.get(comm, [])
        if not pids:
            continue
        best_pid = max(pids, key=lambda ps: len(timeline_by_pid.get(ps, [])))
        tl = timeline_by_pid.get(best_pid, [])

        lines.append("")
        lines.append(f"  {comm} (pid {best_pid})")
        for (ts, t, e) in tl[:timeline_max_events]:
            ts_s = ts if isinstance(ts, str) else ""
            t_s = t if isinstance(t, str) else ""
            e_s = e if isinstance(e, str) else ""
            lines.append(f"    {ts_s:>8}  {t_s:<8}  {e_s}")
        if len(tl) > timeline_max_events:
            lines.append(f"    ... ({len(tl)} events total for this pid)")

    lines.append("")
    lines.append("====================================")
    lines.append("")
    return "\n".join(lines)


def to_markdown(text: str) -> str:
    # Put the whole report in a markdown code block for easy copy/paste and readability.
    return "```text\n" + text.rstrip() + "\n```\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate analytics summary for a session directory.")
    ap.add_argument("session_path", help="Path to a session directory (contains events.jsonl)")
    ap.add_argument("--out", default="reports/summaries", help="Output directory for saved summaries (default: reports/summaries)")
    ap.add_argument("--format", choices=["md", "txt"], default="md", help="Output format for saved summary (md or txt)")
    ap.add_argument("--timeline-max", type=int, default=25, help="Max events printed per timeline (default: 25)")
    args = ap.parse_args()

    session_path = Path(args.session_path).expanduser().resolve()
    events_path = session_path / "events.jsonl"
    if not events_path.exists():
        print("ERROR: events.jsonl not found in the provided session directory.", file=sys.stderr)
        sys.exit(1)

    # Determine session_id from folder name (e.g., 2026-02-14_11-14-48)
    session_id = session_path.name

    events = load_events(events_path)
    base = compute_analytics(events)

    session_meta = load_session_metadata(session_path)
    base["event_rate"] = compute_event_rate(session_meta, base["total_events"])

    # Save index.json in the session directory
    index_path = session_path / "index.json"
    with index_path.open("w", encoding="utf-8") as f:
        json.dump(base, f, indent=2)

    # Build report
    report_text = build_report_text(session_path, base, timeline_max_events=args.timeline_max)

    # Print to terminal
    print(report_text)

    # Save report under reports/
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.format == "md":
        out_path = out_dir / f"{session_id}.md"
        out_content = to_markdown(report_text)
    else:
        out_path = out_dir / f"{session_id}.txt"
        out_content = report_text

    out_path.write_text(out_content, encoding="utf-8")
    # Small confirmation on stderr so it doesn't mess with piping stdout
    print(f"[saved] {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()

