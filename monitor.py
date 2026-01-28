#!/usr/bin/env python3

import subprocess
import os
import json
import datetime
import signal
import sys

# =========================
# Configurazione base
# =========================

PROBE_PATH = "probes/test_exec.bt"
SESSIONS_DIR = "sessions"

# =========================
# Creazione sessione
# =========================

def create_session_dir():
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_path = os.path.join(SESSIONS_DIR, ts)
    os.makedirs(session_path, exist_ok=True)
    return session_path

# =========================
# Avvio bpftrace
# =========================

def start_bpftrace(probe_path):
    cmd = ["bpftrace", probe_path]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1  # line-buffered
    )
    return process

# =========================
# Main
# =========================

def main():
    print("[*] Android eBPF Monitor - starting...")

    # 1) crea sessione
    session_dir = create_session_dir()
    print(f"[*] Session created: {session_dir}")

    events_file_path = os.path.join(session_dir, "events.jsonl")
    stderr_file_path = os.path.join(session_dir, "stderr.log")

    # 2) avvia bpftrace
    print("[*] Starting bpftrace...")
    proc = start_bpftrace(PROBE_PATH)

    # apertura file
    events_file = open(events_file_path, "w")
    stderr_file = open(stderr_file_path, "w")

    print("[*] Monitoring started. Press Ctrl-C to stop.")

    try:
        # 3) loop di lettura eventi
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            # validazione JSON
            try:
                obj = json.loads(line)
                events_file.write(json.dumps(obj) + "\n")
                events_file.flush()
            except json.JSONDecodeError:
                # se non è JSON valido, lo mettiamo nello stderr log
                stderr_file.write(line + "\n")
                stderr_file.flush()

    except KeyboardInterrupt:
        print("\n[*] Stopping monitor (Ctrl-C received)...")

    finally:
        # 4) cleanup
        print("[*] Cleaning up...")

        try:
            proc.terminate()
        except Exception:
            pass

        try:
            proc.kill()
        except Exception:
            pass

        events_file.close()
        stderr_file.close()

        print(f"[*] Session saved in: {session_dir}")
        print("[*] Monitor stopped.")

if __name__ == "__main__":
    main()
