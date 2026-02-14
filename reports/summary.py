#!/usr/bin/env python3

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_events(events_path):
    events = []
    with open(events_path, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def compute_summary(events):

    type_counter = Counter()
    event_counter = Counter()
    process_counter = Counter()

    syscall_counter = Counter()
    syscall_errors = Counter()
    latency_values = []

    for ev in events:

        t = ev.get("type")
        e = ev.get("event")
        comm = ev.get("comm")

        if t:
            type_counter[t] += 1

        if e:
            event_counter[e] += 1

        if comm:
            process_counter[comm] += 1

        # syscall-specific analytics
        if t == "syscall":
            syscall_counter[e] += 1

            data = ev.get("data", {})
            ret = data.get("ret")
            lat = data.get("lat_us")

            if isinstance(ret, int) and ret < 0:
                syscall_errors[e] += 1

            if isinstance(lat, (int, float)):
                latency_values.append(lat)

    latency_stats = {}
    if latency_values:
        latency_values.sort()
        n = len(latency_values)

        def pct(p):
            return latency_values[int(n * p)]

        latency_stats = {
            "min_us": latency_values[0],
            "p50_us": pct(0.50),
            "p95_us": pct(0.95),
            "max_us": latency_values[-1],
        }

    summary = {
        "total_events": len(events),
        "events_by_type": dict(type_counter),
        "events_by_name": dict(event_counter),
        "top_processes": process_counter.most_common(10),
        "syscalls": {
            "counts": dict(syscall_counter),
            "errors": dict(syscall_errors),
            "latency": latency_stats,
        },
    }

    return summary


def print_summary(summary):

    print("\n========== SESSION SUMMARY ==========\n")

    print(f"Total events: {summary['total_events']}\n")

    print("Events by type:")
    for k, v in summary["events_by_type"].items():
        print(f"  {k}: {v}")

    print("\nTop processes:")
    for proc, count in summary["top_processes"]:
        print(f"  {proc}: {count}")

    if summary["syscalls"]["counts"]:
        print("\nSyscall counts:")
        for sc, count in summary["syscalls"]["counts"].items():
            errors = summary["syscalls"]["errors"].get(sc, 0)
            err_rate = (errors / count) * 100 if count else 0
            print(f"  {sc}: {count} (errors: {errors}, {err_rate:.1f}%)")

    if summary["syscalls"]["latency"]:
        lat = summary["syscalls"]["latency"]
        print("\nLatency (microseconds):")
        for k, v in lat.items():
            print(f"  {k}: {v}")

    print("\n====================================\n")


def save_index(summary, session_path):
    index_path = session_path / "index.json"
    with open(index_path, "w") as f:
        json.dump(summary, f, indent=2)


def main():

    if len(sys.argv) != 2:
        print("Usage: python3 summary.py <session_path>")
        sys.exit(1)

    session_path = Path(sys.argv[1])
    events_path = session_path / "events.jsonl"

    if not events_path.exists():
        print("events.jsonl not found in session directory.")
        sys.exit(1)

    events = load_events(events_path)
    summary = compute_summary(events)

    print_summary(summary)
    save_index(summary, session_path)


if __name__ == "__main__":
    main()

