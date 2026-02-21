#!/usr/bin/env python3
"""
reports/summary.py

Reads:
- <session_dir>/events.jsonl
- <session_dir>/session.json (optional)

Writes:
- <session_dir>/index.json
- <out_dir>/<session_id>.md or .txt
- prints report to stdout

Usage:
  python3 reports/summary.py sessions/<session_dir>
  python3 reports/summary.py sessions/<session_dir> --out reports/summaries
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# -------------------------
# Parsing helpers
# -------------------------
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


# -------------------------
# Time helpers (ts_ns)
# -------------------------
def get_ts_ns(ev: Dict[str, Any]) -> Optional[int]:
    v = ev.get("ts_ns")
    if v is None:
        return None
    try:
        return int(v)  # you store it as string -> ok
    except (ValueError, TypeError):
        return None


def sort_events_by_time(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not events:
        return events
    has_ts = any(get_ts_ns(e) is not None for e in events)
    if not has_ts:
        return events  # keep original order
    # Put events without ts_ns at the end
    return sorted(events, key=lambda e: (get_ts_ns(e) is None, get_ts_ns(e) or 0))


def window_rate(events: List[Dict[str, Any]], window_s: float = 1.0) -> Dict[str, Any]:
    ts_list = [get_ts_ns(e) for e in events]
    ts_list = [t for t in ts_list if t is not None]
    if len(ts_list) < 2:
        return {"available": False, "reason": "ts_ns missing or too few events"}

    ts0 = min(ts_list)
    win_ns = int(window_s * 1e9)

    buckets = Counter()
    for t in ts_list:
        b = (t - ts0) // win_ns
        buckets[b] += 1

    peak_bucket, peak_count = max(buckets.items(), key=lambda kv: kv[1])
    peak_rate = float(peak_count) / float(window_s)
    avg_rate = (sum(buckets.values()) / max(len(buckets), 1)) / float(window_s)

    return {
        "available": True,
        "window_s": float(window_s),
        "peak_rate": float(peak_rate),
        "peak_window": {
            "start_s": float(peak_bucket * window_s),
            "end_s": float((peak_bucket + 1) * window_s),
            "count": int(peak_count),
        },
        "avg_rate": float(avg_rate),
        "total_windows": int(len(buckets)),
    }


def errno_from_ret(ret: Any) -> Optional[int]:
    try:
        r = int(ret)
    except (ValueError, TypeError):
        return None
    if r < 0:
        return abs(r)
    return None


# -------------------------
# Stats helpers
# -------------------------
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


# -------------------------
# Binder analytics
# -------------------------
def compute_binder_analytics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlates binder_transaction, binder_transaction_alloc_buf, and
    binder_transaction_received by debug_id to build a full IPC picture.
    """
    # Index alloc_buf and received by debug_id for O(1) join
    alloc_by_id: Dict[int, Dict] = {}
    received_by_id: Dict[int, Dict] = {}

    for ev in events:
        event = ev.get("event", "")
        data = ev.get("data", {})
        debug_id = data.get("debug_id")
        if debug_id is None:
            continue
        if event == "binder_transaction_alloc_buf":
            alloc_by_id[debug_id] = ev
        elif event == "binder_transaction_received":
            received_by_id[debug_id] = ev

    # Build transaction records
    transactions = []
    ipc_graph: Dict[Tuple[str, str], Dict] = {}  # (sender_comm, receiver_comm) -> stats
    code_usage: Counter = Counter()
    oneway_count = 0
    sync_count = 0
    total_bytes = 0

    for ev in events:
        if ev.get("event") != "binder_transaction":
            continue
        if ev.get("data", {}).get("reply") == 1:
            continue  # skip reply transactions for the graph, count separately

        data = ev.get("data", {})
        debug_id = data.get("debug_id")
        sender_comm = ev.get("comm", "unknown")
        sender_pid = ev.get("pid")
        to_pid = data.get("to_pid")
        code = data.get("code")
        oneway = data.get("oneway", 0)

        # Join with alloc_buf for payload size
        alloc = alloc_by_id.get(debug_id, {})
        data_size = alloc.get("data", {}).get("data_size", 0)
        total_bytes += data_size or 0

        # Join with received to get receiver comm
        recv = received_by_id.get(debug_id, {})
        receiver_comm = recv.get("comm", f"pid:{to_pid}" if to_pid else "unknown")

        if oneway:
            oneway_count += 1
        else:
            sync_count += 1

        if code is not None:
            code_usage[code] += 1

        # IPC graph edge
        edge = (sender_comm, receiver_comm)
        if edge not in ipc_graph:
            ipc_graph[edge] = {"count": 0, "total_bytes": 0, "codes": Counter()}
        ipc_graph[edge]["count"] += 1
        ipc_graph[edge]["total_bytes"] += data_size or 0
        if code is not None:
            ipc_graph[edge]["codes"][code] += 1

        transactions.append({
            "debug_id": debug_id,
            "sender_comm": sender_comm,
            "sender_pid": sender_pid,
            "receiver_comm": receiver_comm,
            "to_pid": to_pid,
            "code": code,
            "oneway": bool(oneway),
            "data_size": data_size,
        })

    # Serialize ipc_graph (Counter not JSON-serializable)
    ipc_graph_out = {}
    for (src, dst), stats in sorted(ipc_graph.items(), key=lambda x: x[1]["count"], reverse=True):
        ipc_graph_out[f"{src} → {dst}"] = {
            "count": stats["count"],
            "total_bytes": stats["total_bytes"],
            "top_codes": [{"code": k, "count": v} for k, v in stats["codes"].most_common(5)],
        }

    return {
        "total_transactions": len(transactions),
        "oneway": oneway_count,
        "sync": sync_count,
        "total_bytes_transferred": total_bytes,
        "top_codes": [{"code": k, "count": v} for k, v in code_usage.most_common(10)],
        "ipc_graph": ipc_graph_out,
    }


# -------------------------
# Process tree
# -------------------------
def compute_process_tree(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Builds parent->children map from ppid field.
    Returns both the tree structure and a flat list of known processes.
    """
    pid_to_comm: Dict[int, str] = {}
    pid_to_ppid: Dict[int, int] = {}

    for ev in events:
        pid = ev.get("pid")
        ppid = ev.get("ppid")
        comm = ev.get("comm")
        if isinstance(pid, int) and isinstance(comm, str) and comm:
            pid_to_comm[pid] = comm
        if isinstance(pid, int) and isinstance(ppid, int):
            pid_to_ppid[pid] = ppid

    # Build children map
    children: Dict[int, List[int]] = defaultdict(list)
    for pid, ppid in pid_to_ppid.items():
        if ppid != pid:  # avoid self-reference
            children[ppid].append(pid)

    # Find roots: pids whose ppid we haven't seen as a pid
    all_pids = set(pid_to_ppid.keys())
    roots = [pid for pid, ppid in pid_to_ppid.items() if ppid not in all_pids]

    def build_subtree(pid: int, depth: int = 0) -> Dict:
        return {
            "pid": pid,
            "comm": pid_to_comm.get(pid, "?"),
            "children": [build_subtree(c, depth + 1) for c in sorted(children.get(pid, []))],
        }

    tree = [build_subtree(r) for r in sorted(roots)]

    # Also flat list for quick lookup
    flat = [
        {"pid": pid, "comm": pid_to_comm.get(pid, "?"), "ppid": pid_to_ppid.get(pid)}
        for pid in sorted(all_pids)
    ]

    return {"roots": tree, "flat": flat}


# -------------------------
# Resource map
# -------------------------
def compute_resource_map(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregates the 'decoded' field by process and syscall type.
    Gives you: which files each process opened, which IPs it connected to,
    which binaries it executed.
    """
    # comm -> { "openat": set of paths, "connect": set of IPs, "execve": set of binaries }
    by_comm: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for ev in events:
        if ev.get("type") != "syscall":
            continue
        event = ev.get("event", "")
        comm = ev.get("comm", "")
        decoded = ev.get("decoded", "").strip()
        if not decoded or not comm:
            continue
        if event in ("openat", "connect", "execve"):
            by_comm[comm][event].add(decoded)

    # Serialize sets to sorted lists
    result = {}
    for comm, resources in sorted(by_comm.items()):
        result[comm] = {
            k: sorted(v) for k, v in resources.items() if v
        }

    return result


# -------------------------
# Main analytics
# -------------------------
def compute_analytics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    # sort for any time-based analysis and for timeline output
    events_sorted = sort_events_by_time(events)

    type_counter = Counter()
    event_counter = Counter()

    proc_total = Counter()  # comm -> total
    proc_by_type = defaultdict(Counter)  # comm -> Counter(type)
    proc_by_event = defaultdict(Counter)  # comm -> Counter(event)

    syscall_counts = Counter()
    syscall_errors = Counter()
    syscall_lat_by_name = defaultdict(list)
    all_lat_us: List[float] = []

    # For timelines
    timeline_by_pid = defaultdict(list)  # pid -> list of (ts_ns, ts, type, event)
    pid_to_comm: Dict[int, str] = {}

    # Collect syscall latency events separately for deeper analytics
    syscall_lat_events: List[Dict[str, Any]] = []

    for ev in events_sorted:
        t = ev.get("type")
        e = ev.get("event")
        comm = ev.get("comm")
        pid = ev.get("pid")
        ts = ev.get("ts")
        ts_ns = get_ts_ns(ev)

        if isinstance(t, str) and t:
            type_counter[t] += 1
        if isinstance(e, str) and e:
            event_counter[e] += 1

        # process aggregations (only if comm is usable)
        if isinstance(comm, str) and comm:
            proc_total[comm] += 1
            if isinstance(t, str) and t:
                proc_by_type[comm][t] += 1
            if isinstance(e, str) and e:
                proc_by_event[comm][e] += 1

        # timeline / pid mapping
        if isinstance(pid, int):
            if isinstance(comm, str) and comm:
                pid_to_comm[pid] = comm
            if isinstance(e, str) and e:
                timeline_by_pid[pid].append((ts_ns, ts, t, e))

        # syscall analytics
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
                    syscall_lat_events.append(ev)

    syscall_error_rates: Dict[str, float] = {}
    for name, cnt in syscall_counts.items():
        err = syscall_errors.get(name, 0)
        syscall_error_rates[name] = (err / cnt) if cnt else 0.0

    latency_summary: Dict[str, Any] = {}
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

    latency_by_syscall: Dict[str, Any] = {}
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

    # NEW: time/rate analytics based on ts_ns
    time_analytics = {
        "has_ts_ns": any(get_ts_ns(e) is not None for e in events_sorted),
        "rate_1s": window_rate(events_sorted, window_s=1.0),
    }

    # NEW: syscalls_latency deep analytics (outliers, p95 by comm, errno breakdown)
    syscalls_latency_deep: Dict[str, Any] = {}
    if syscall_lat_events:
        # Top slowest
        def _lat_us(ev: Dict[str, Any]) -> int:
            try:
                return int(ev.get("data", {}).get("lat_us"))
            except Exception:
                return -1

        topN = 20
        slowest = sorted(syscall_lat_events, key=_lat_us, reverse=True)[:topN]
        syscalls_latency_deep["top_slowest"] = [
            {
                "ts": ev.get("ts"),
                "ts_ns": get_ts_ns(ev),
                "comm": ev.get("comm"),
                "pid": ev.get("pid"),
                "tid": ev.get("tid"),
                "event": ev.get("event"),
                "ret": ev.get("data", {}).get("ret"),
                "lat_us": ev.get("data", {}).get("lat_us"),
            }
            for ev in slowest
        ]

        # Percentiles by comm
        by_comm = defaultdict(list)
        for ev in syscall_lat_events:
            comm = ev.get("comm") or ""
            if not isinstance(comm, str) or not comm:
                continue
            try:
                by_comm[comm].append(int(ev.get("data", {}).get("lat_us")))
            except Exception:
                continue

        def _p(vals: List[int], p: float) -> Optional[int]:
            if not vals:
                return None
            s = sorted(vals)
            idx = int(p * (len(s) - 1))
            return s[idx]

        p95_by_comm = []
        for comm, vals in by_comm.items():
            p95_by_comm.append(
                {
                    "comm": comm,
                    "n": len(vals),
                    "p50_us": _p(vals, 0.50),
                    "p95_us": _p(vals, 0.95),
                    "p99_us": _p(vals, 0.99),
                    "max_us": max(vals) if vals else None,
                }
            )
        p95_by_comm.sort(key=lambda x: (x["p95_us"] is None, x["p95_us"] or -1), reverse=True)
        syscalls_latency_deep["p95_by_comm_top"] = p95_by_comm[:15]

        # Errno breakdown
        errno_global = Counter()
        errno_by_syscall = defaultdict(Counter)

        for ev in syscall_lat_events:
            data = ev.get("data", {}) if isinstance(ev.get("data"), dict) else {}
            ret = data.get("ret")
            eno = errno_from_ret(ret)
            if eno is None:
                continue
            sc = ev.get("event") or "unknown"
            errno_global[eno] += 1
            errno_by_syscall[sc][eno] += 1

        syscalls_latency_deep["errno_global_top"] = [
            {"errno": k, "count": v} for k, v in errno_global.most_common(10)
        ]
        syscalls_latency_deep["errno_by_syscall_top"] = {
            sc: [{"errno": k, "count": v} for k, v in cnt.most_common(5)]
            for sc, cnt in errno_by_syscall.items()
        }

    # NEW: binder, process tree, resource map
    binder_analytics = compute_binder_analytics(events_sorted)
    process_tree = compute_process_tree(events_sorted)
    resource_map = compute_resource_map(events_sorted)

    # Build base result (keeps your existing keys for compatibility)
    result = {
        "total_events": int(len(events_sorted)),
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
        "timeline_by_pid": {
            str(pid): [
                # store just the readable triple in index.json like before,
                # but ordered by ts_ns already
                (ts if isinstance(ts, str) else "", t if isinstance(t, str) else "", e if isinstance(e, str) else "")
                for (_, ts, t, e) in timeline_by_pid[pid]
            ]
            for pid in timeline_by_pid
        },
        "pid_to_comm": {str(pid): pid_to_comm[pid] for pid in pid_to_comm},
        # NEW keys
        "time": time_analytics,
        "syscalls_latency": syscalls_latency_deep,
        "binder": binder_analytics,
        "process_tree": process_tree,
        "resource_map": resource_map,
    }
    return result


# -------------------------
# Report rendering
# -------------------------
def build_report_text(
    session_path: Path,
    summary: Dict[str, Any],
    session_meta: Optional[Dict[str, Any]],
    timeline_max_events: int = 25,
) -> str:
    lines: List[str] = []

    lines.append("========== SESSION SUMMARY ==========")
    lines.append("")
    lines.append(f"Session: {session_path}")

    # probe identifiers (if present)
    if isinstance(session_meta, dict):
        pc = session_meta.get("probe_code")
        pp = session_meta.get("probe_path")
        if pc:
            lines.append(f"Probe code: {pc}")
        if pp:
            lines.append(f"Probe path: {pp}")

    total = summary.get("total_events", 0)
    lines.append(f"Total events: {total}")

    er = summary.get("event_rate")
    if isinstance(er, dict):
        lines.append(f"Duration: {er.get('duration_s', 0):.3f} s")
        lines.append(f"Event rate: {er.get('event_rate_eps', 0):.3f} events/s")

    # Time / Rate (ts_ns based)
    lines.append("")
    lines.append("Time / Rate")
    time_info = summary.get("time", {}) if isinstance(summary.get("time"), dict) else {}
    rate_1s = time_info.get("rate_1s", {}) if isinstance(time_info.get("rate_1s"), dict) else {}
    if rate_1s.get("available"):
        pw = rate_1s.get("peak_window", {}) if isinstance(rate_1s.get("peak_window"), dict) else {}
        lines.append(f" Window: {rate_1s.get('window_s', 1.0)} s")
        lines.append(f" Peak rate: {rate_1s.get('peak_rate', 0.0):.2f} events/s")
        lines.append(
            f" Peak window: {pw.get('start_s', 0.0)}s–{pw.get('end_s', 0.0)}s "
            f"({pw.get('count', 0)} events)"
        )
        lines.append(f" Avg rate: {rate_1s.get('avg_rate', 0.0):.2f} events/s")
    else:
        lines.append(f" Rate unavailable: {rate_1s.get('reason', 'missing ts_ns')}")

    lines.append("")
    lines.append("Events by type:")
    for k, v in (summary.get("events_by_type") or {}).items():
        lines.append(f" {k}: {v}")

    lines.append("")
    lines.append("Top processes (by total events):")
    for comm, count in summary.get("top_processes", []):
        lines.append(f" {comm}: {count}")

    syscalls = summary.get("syscalls", {})
    counts = syscalls.get("counts", {}) if isinstance(syscalls, dict) else {}
    if counts:
        lines.append("")
        lines.append("Syscalls (count + error rate):")
        error_rates = syscalls.get("error_rates", {}) if isinstance(syscalls, dict) else {}
        errors = syscalls.get("errors", {}) if isinstance(syscalls, dict) else {}
        for name, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            rate = float(error_rates.get(name, 0.0)) * 100.0
            err = int(errors.get(name, 0))
            lines.append(f" {name}: {cnt} (errors: {err}, {rate:.2f}%)")

    lat = syscalls.get("latency_overall") if isinstance(syscalls, dict) else None
    if isinstance(lat, dict) and lat:
        lines.append("")
        lines.append("Overall syscall latency (microseconds):")
        lines.append(f" n: {lat.get('n', 0)}")
        lines.append(f" min: {lat.get('min_us', 0):.0f}")
        lines.append(f" p50: {lat.get('p50_us', 0):.0f}")
        lines.append(f" p95: {lat.get('p95_us', 0):.0f}")
        lines.append(f" p99: {lat.get('p99_us', 0):.0f}")
        lines.append(f" max: {lat.get('max_us', 0):.0f}")

    # NEW: syscalls latency deep dive
    scd = summary.get("syscalls_latency", {})
    if isinstance(scd, dict) and scd:
        lines.append("")
        lines.append("Syscalls latency (deep dive)")

        slowest = scd.get("top_slowest", [])
        if slowest:
            lines.append(" Top slowest events (lat_us):")
            for e in slowest[:10]:
                lines.append(
                    f"  - {e.get('ts','')} {e.get('comm','')} pid={e.get('pid')} "
                    f"{e.get('event')} ret={e.get('ret')} lat_us={e.get('lat_us')}"
                )

        p95c = scd.get("p95_by_comm_top", [])
        if p95c:
            lines.append("")
            lines.append(" Top processes by p95 latency:")
            for r in p95c:
                lines.append(
                    f"  - {r.get('comm')} (n={r.get('n')}): "
                    f"p50={r.get('p50_us')}us p95={r.get('p95_us')}us p99={r.get('p99_us')}us max={r.get('max_us')}us"
                )

        errno_top = scd.get("errno_global_top", [])
        if errno_top:
            lines.append("")
            lines.append(" Top errno (ret<0):")
            lines.append("  " + ", ".join([f"errno={x['errno']} ({x['count']})" for x in errno_top]))

    # Process timelines (top 5 comm; pick pid with most events)
    lines.append("")
    lines.append("Process timelines (top 5 processes):")
    top5 = [comm for comm, _ in summary.get("top_processes", [])[:5]]
    pid_to_comm = summary.get("pid_to_comm", {})
    timeline_by_pid = summary.get("timeline_by_pid", {})

    comm_pids = defaultdict(list)
    for pid_s, comm in (pid_to_comm or {}).items():
        comm_pids[comm].append(pid_s)

    for comm in top5:
        pids = comm_pids.get(comm, [])
        if not pids:
            continue

        best_pid = max(pids, key=lambda ps: len(timeline_by_pid.get(ps, [])))
        tl = timeline_by_pid.get(best_pid, [])

        lines.append("")
        lines.append(f" {comm} (pid {best_pid})")
        for (ts, t, e) in tl[:timeline_max_events]:
            ts_s = ts if isinstance(ts, str) else ""
            t_s = t if isinstance(t, str) else ""
            e_s = e if isinstance(e, str) else ""
            lines.append(f" {ts_s:>8} {t_s:<8} {e_s}")

        if len(tl) > timeline_max_events:
            lines.append(f" ... ({len(tl)} events total for this pid)")

    # Binder IPC analysis
    binder = summary.get("binder", {})
    if isinstance(binder, dict) and binder.get("total_transactions", 0) > 0:
        lines.append("")
        lines.append("Binder IPC:")
        lines.append(f" Total transactions: {binder.get('total_transactions', 0)}")
        lines.append(f" One-way: {binder.get('oneway', 0)}  Sync: {binder.get('sync', 0)}")
        lines.append(f" Total bytes transferred: {binder.get('total_bytes_transferred', 0)}")

        top_codes = binder.get("top_codes", [])
        if top_codes:
            codes_str = ", ".join([f"code={x['code']}({x['count']})" for x in top_codes[:5]])
            lines.append(f" Top codes: {codes_str}")

        ipc_graph = binder.get("ipc_graph", {})
        if ipc_graph:
            lines.append("")
            lines.append(" IPC communication graph (top 10 edges):")
            for edge, stats in list(ipc_graph.items())[:10]:
                lines.append(f"  {edge}: {stats['count']} calls, {stats['total_bytes']} bytes")

    # Process tree
    proc_tree = summary.get("process_tree", {})
    flat = proc_tree.get("flat", [])
    if flat:
        lines.append("")
        lines.append("Process tree:")

        def render_tree(node: dict, indent: int = 0) -> None:
            prefix = "  " * indent + ("└─ " if indent > 0 else "")
            lines.append(f" {prefix}{node['comm']} (pid {node['pid']})")
            for child in node.get("children", []):
                render_tree(child, indent + 1)

        for root in proc_tree.get("roots", []):
            render_tree(root)

    # Resource map
    resource_map = summary.get("resource_map", {})
    if resource_map:
        lines.append("")
        lines.append("Resource map (files / IPs / binaries per process):")
        for comm, resources in list(resource_map.items())[:10]:
            lines.append(f" {comm}:")
            for rtype, values in resources.items():
                label = {"openat": "files", "connect": "connections", "execve": "executed"}.get(rtype, rtype)
                for v in values[:5]:
                    lines.append(f"   [{label}] {v}")
                if len(values) > 5:
                    lines.append(f"   [{label}] ... ({len(values)} total)")

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
    report_text = build_report_text(session_path, base, session_meta, timeline_max_events=args.timeline_max)

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
