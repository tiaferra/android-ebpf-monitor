#!/usr/bin/env python3

import subprocess
import os
import json
import datetime
import sys
import threading

# =========================
# Configurazione base
# =========================

DEFAULT_PROBE_PATH = "probes/test_exec.bt"
PROBES_MAP_PATH = "config/probes_map.json"
SESSIONS_DIR = "sessions"

# =========================
# Utility
# =========================

def create_session_dir():
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_path = os.path.join(SESSIONS_DIR, ts)
    os.makedirs(session_path, exist_ok=True)
    return session_path

def load_probes_map(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def start_bpftrace(probe_path: str) -> subprocess.Popen:
    cmd = ["bpftrace", probe_path]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # line-buffered
    )

def drain_stream_to_file(stream, out_file):
    """Legge continuamente uno stream (es. stderr) e lo scrive su file."""
    try:
        for line in stream:
            if not line:
                continue
            out_file.write(line)
            out_file.flush()
    except Exception:
        pass

def normalize_event(obj: dict, probe_meta: dict) -> dict:
    """Assicura che l'evento rispetti lo schema minimo e applica fallback da config."""
    if "schema_version" not in obj:
        obj["schema_version"] = probe_meta.get("schema_version", 1)

    # fallback type/event se mancanti
    if "type" not in obj and "type" in probe_meta:
        obj["type"] = probe_meta["type"]

    if "event" not in obj and "event" in probe_meta and probe_meta["event"] != "*":
        obj["event"] = probe_meta["event"]

    # assicura data object
    if "data" not in obj or not isinstance(obj["data"], dict):
        obj["data"] = {}

    return obj

def validate_event(obj: dict, probe_meta: dict) -> str | None:
    """Ritorna una stringa di warning se non matcha la config, altrimenti None."""
    expected_type = probe_meta.get("type")
    expected_event = probe_meta.get("event")

    if expected_type and obj.get("type") and obj["type"] != expected_type:
        return f"[WARN] type mismatch: got={obj.get('type')} expected={expected_type}"

    # event "*" = multi-evento, non validare
    if expected_event and expected_event != "*" and obj.get("event") and obj["event"] != expected_event:
        return f"[WARN] event mismatch: got={obj.get('event')} expected={expected_event}"

    return None

# =========================
# Main
# =========================

def main():
    # scegli probe da CLI oppure default
    probe_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROBE_PATH

    print("[*] Android eBPF Monitor - starting...")

    # carica mappa probe
    try:
        probes_map = load_probes_map(PROBES_MAP_PATH)
    except FileNotFoundError:
        print(f"[!] Missing {PROBES_MAP_PATH}. Create it first.")
        sys.exit(1)

    if probe_path not in probes_map:
        print(f"[!] Probe not found in {PROBES_MAP_PATH}: {probe_path}")
        print("[!] Add it to the map or pass a known probe.")
        sys.exit(1)

    probe_meta = probes_map[probe_path]

    # crea sessione
    session_dir = create_session_dir()
    print(f"[*] Session created: {session_dir}")

    events_file_path = os.path.join(session_dir, "events.jsonl")
    stderr_file_path = os.path.join(session_dir, "stderr.log")
    session_meta_path = os.path.join(session_dir, "session.json")

    # salva metadata sessione
    session_meta = {
        "started_at": datetime.datetime.now().isoformat(),
        "probe_path": probe_path,
        "probe_meta": probe_meta
    }
    with open(session_meta_path, "w", encoding="utf-8") as f:
        json.dump(session_meta, f, indent=2)

    # avvia bpftrace
    print(f"[*] Starting bpftrace: {probe_path}")
    proc = start_bpftrace(probe_path)

    with open(events_file_path, "w", encoding="utf-8") as events_file, \
         open(stderr_file_path, "w", encoding="utf-8") as stderr_file:

        # thread che drena stderr di bpftrace (errori/diagnostica)
        t = threading.Thread(target=drain_stream_to_file, args=(proc.stderr, stderr_file), daemon=True)
        t.start()

        print("[*] Monitoring started. Press Ctrl-C to stop.")

        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    stderr_file.write(line + "\n")
                    stderr_file.flush()
                    continue

                obj = normalize_event(obj, probe_meta)

                warn = validate_event(obj, probe_meta)
                if warn:
                    stderr_file.write(warn + "\n")
                    stderr_file.flush()

                events_file.write(json.dumps(obj) + "\n")
                events_file.flush()

        except KeyboardInterrupt:
            print("\n[*] Stopping monitor (Ctrl-C received)...")

        finally:
            print("[*] Cleaning up...")
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.kill()
            except Exception:
                pass

            # aggiorna meta
            session_meta["stopped_at"] = datetime.datetime.now().isoformat()
            with open(session_meta_path, "w", encoding="utf-8") as f:
                json.dump(session_meta, f, indent=2)

            print(f"[*] Session saved in: {session_dir}")
            print("[*] Monitor stopped.")

if __name__ == "__main__":
    main()

