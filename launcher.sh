#!/usr/bin/env bash
# =============================================================================
# run_probe.sh
# Interactive launcher for android-ebpf-monitor probes.
#
# Usage:
#   ./run_probe.sh                  # interactive menu
#   ./run_probe.sh -t 60            # preset timer (seconds)
#   ./run_probe.sh -p probes/syscalls.bt -t 30   # skip menu, run one probe
#
# Requirements: must be run from the project root (where monitor.py lives).
# =============================================================================

set -uo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBES_MAP="${SCRIPT_DIR}/config/probes_map.json"
MONITOR="${SCRIPT_DIR}/monitor.py"
SUMMARY="${SCRIPT_DIR}/reports/summary.py"
SESSIONS_DIR="${SCRIPT_DIR}/sessions"

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }

# ── Sanity checks ─────────────────────────────────────────────────────────────
[[ -f "$MONITOR" ]]    || die "monitor.py not found. Run this script from the project root."
[[ -f "$PROBES_MAP" ]] || die "config/probes_map.json not found."
command -v python3  &>/dev/null || die "python3 not found."
command -v bpftrace &>/dev/null || die "bpftrace not found."
command -v jq       &>/dev/null || die "jq not found (needed to parse probes_map.json). Install with: apt install jq"
command -v timeout  &>/dev/null || die "timeout not found (part of GNU coreutils). Install with: apt install coreutils"

# ── Parse CLI flags ───────────────────────────────────────────────────────────
CLI_PROBE=""
CLI_TIMER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--probe) CLI_PROBE="$2"; shift 2 ;;
        -t|--time)  CLI_TIMER="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [-p probe_path] [-t seconds]"
            echo "  -p  Path to a .bt probe (e.g. probes/syscalls.bt)"
            echo "  -t  Duration in seconds"
            exit 0
            ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ── Load probes from probes_map.json ──────────────────────────────────────────
# Build parallel arrays: paths, codes, descriptions
mapfile -t PROBE_PATHS < <(jq -r 'keys[]' "$PROBES_MAP" | sort)

if [[ ${#PROBE_PATHS[@]} -eq 0 ]]; then
    die "No probes found in $PROBES_MAP."
fi

# Filter to probes whose .bt file actually exists
AVAILABLE_PATHS=()
for p in "${PROBE_PATHS[@]}"; do
    if [[ -f "${SCRIPT_DIR}/${p}" ]]; then
        AVAILABLE_PATHS+=("$p")
    fi
done

[[ ${#AVAILABLE_PATHS[@]} -gt 0 ]] || die "None of the probes listed in probes_map.json exist on disk."

# ── Display probe table ───────────────────────────────────────────────────────
print_probe_table() {
    echo ""
    echo -e "${BOLD}Available probes:${RESET}"
    echo -e "${BOLD}  #   Code     Type        Event       Path${RESET}"
    echo    "  ─────────────────────────────────────────────────────────────────"
    local i=1
    for p in "${AVAILABLE_PATHS[@]}"; do
        local code type event desc
        code=$(jq -r --arg k "$p" '.[$k].code  // "?"' "$PROBES_MAP")
        type=$(jq -r --arg k "$p" '.[$k].type  // "?"' "$PROBES_MAP")
        event=$(jq -r --arg k "$p" '.[$k].event // "?"' "$PROBES_MAP")
        printf "  ${CYAN}%-3s${RESET} %-8s %-11s %-11s %s\n" "$i" "$code" "$type" "$event" "$p"
        ((i++))
    done
    echo    "  ─────────────────────────────────────────────────────────────────"
    echo -e "  ${CYAN}A${RESET}   Run ALL probes sequentially"
    echo ""
}

# ── Timer prompt ──────────────────────────────────────────────────────────────
ask_timer() {
    local default="${1:-60}"
    local input
    while true; do
        read -rp "$(echo -e "  ${YELLOW}Duration per probe in seconds${RESET} [default: ${default}]: ")" input
        input="${input:-$default}"
        if [[ "$input" =~ ^[1-9][0-9]*$ ]]; then
            echo "$input"
            return
        fi
        warn "Please enter a positive integer."
    done
}

# ── Progress bar shown while probe runs ──────────────────────────────────────
show_progress() {
    local duration="$1"
    local elapsed=0
    while [[ $elapsed -lt $duration ]]; do
        sleep 1
        ((elapsed++)) || true
        local filled=$(( elapsed * 40 / duration ))
        local empty=$(( 40 - filled ))
        local bar=""
        for ((j=0; j<filled; j++)); do bar+="█"; done
        for ((j=0; j<empty; j++)); do bar+="░"; done
        printf "\r  [%s] %3ds / %ds " "$bar" "$elapsed" "$duration"
    done
    echo ""
}

# ── Run a single probe with timeout ──────────────────────────────────────────
# Sets LAST_SESSION_DIR to the session directory created by monitor.py
LAST_SESSION_DIR=""

run_probe() {
    local probe_path="$1"
    local duration="$2"
    local code
    code=$(jq -r --arg k "$probe_path" '.[$k].code // "UNKNOWN"' "$PROBES_MAP")

    echo ""
    info "Starting probe: ${BOLD}${probe_path}${RESET} (code: ${code})"
    info "Duration: ${duration}s — session will be saved automatically."
    info "Press Ctrl-C to stop early."
    echo ""

    # Temp file for output capture
    local tmpout
    tmpout=$(mktemp)

    # PYTHONUNBUFFERED=1 forces Python to flush stdout immediately on every
    # write — without this, output may be buffered and lost when timeout kills
    # the process before the buffer flushes to disk.
    timeout --foreground "${duration}s" env PYTHONUNBUFFERED=1 \
        python3 "$MONITOR" "$probe_path" > "$tmpout" 2>&1 &
    local monitor_pid=$!

    # Show monitor output to terminal in real time
    tail -f "$tmpout" &
    local tail_pid=$!

    # Show progress bar in parallel
    show_progress "$duration" &
    local bar_pid=$!

    # Wait for monitor.py to finish (timeout or early exit)
    local exit_code=0
    wait "$monitor_pid" 2>/dev/null || exit_code=$?

    # Stop tail and progress bar
    kill "$tail_pid" 2>/dev/null || true
    kill "$bar_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    wait "$bar_pid" 2>/dev/null || true
    echo ""

    # tmpout is now fully written — extract session directory
    LAST_SESSION_DIR=$(grep -o 'sessions/[^ ]*' "$tmpout" | head -1 | tr -d '[:space:]')

    # Fallback: if grep failed, pick the most recently modified session directory
    if [[ -z "$LAST_SESSION_DIR" && -d "${SCRIPT_DIR}/sessions" ]]; then
        warn "Could not parse session path from output — using most recent session directory."
        LAST_SESSION_DIR=$(find "${SCRIPT_DIR}/sessions" -mindepth 1 -maxdepth 1 -type d \
            -newer "$tmpout" -o -mindepth 1 -maxdepth 1 -type d \
            | sort | tail -1)
        # Strip absolute prefix to keep consistent with resolution below
        LAST_SESSION_DIR="${LAST_SESSION_DIR#${SCRIPT_DIR}/}"
    fi

    rm -f "$tmpout"

    # Resolve to absolute path
    if [[ -n "$LAST_SESSION_DIR" && ! "$LAST_SESSION_DIR" = /* ]]; then
        LAST_SESSION_DIR="${SCRIPT_DIR}/${LAST_SESSION_DIR}"
    fi

    # timeout exits with 124 when it kills the process — that's normal
    if [[ $exit_code -eq 124 ]]; then
        ok "Timer elapsed — probe ${code} stopped and session saved."
    elif [[ $exit_code -eq 0 ]]; then
        ok "Probe ${code} finished."
    elif [[ $exit_code -eq 130 ]]; then
        warn "Probe ${code} interrupted by user."
    else
        warn "Probe ${code} exited with code ${exit_code} — check sessions/ for details."
    fi
}

# ── Full monitoring: run probe then immediately report ────────────────────────
full_monitoring() {
    local probe_path="$1"
    local duration="$2"
    local format="${3:-md}"

    run_probe "$probe_path" "$duration"

    if [[ -z "$LAST_SESSION_DIR" || ! -d "$LAST_SESSION_DIR" ]]; then
        warn "Could not locate the session directory — skipping report."
        return
    fi

    echo ""
    info "Probe finished. Generating report for: ${BOLD}$(basename "$LAST_SESSION_DIR")${RESET}"
    echo ""

    python3 "$SUMMARY" "$LAST_SESSION_DIR" --format "$format"
    local exit_code=$?

    echo ""
    if [[ $exit_code -eq 0 ]]; then
        ok "Report saved in reports/summaries/"
    else
        warn "summary.py exited with code ${exit_code} — check output above."
    fi
}

# ── List sessions and generate a report ───────────────────────────────────────
create_report() {
    [[ -f "$SUMMARY" ]] || die "reports/summary.py not found. Make sure it exists in the reports/ directory."

    # Collect session directories that contain events.jsonl
    local sessions=()
    if [[ -d "$SESSIONS_DIR" ]]; then
        while IFS= read -r -d '' s; do
            if [[ -f "${s}/events.jsonl" ]]; then
                sessions+=("$s")
            fi
        done < <(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
    fi

    if [[ ${#sessions[@]} -eq 0 ]]; then
        warn "No sessions found in sessions/. Run a probe first."
        return
    fi

    echo ""
    echo -e "${BOLD}Available sessions:${RESET}"
    echo -e "${BOLD}  #   Session directory                      Events   Started${RESET}"
    echo    "  ─────────────────────────────────────────────────────────────────"

    local i=1
    for s in "${sessions[@]}"; do
        local name events_count started
        name="$(basename "$s")"
        events_count=$(wc -l < "${s}/events.jsonl" 2>/dev/null || echo "?")
        if [[ -f "${s}/session.json" ]]; then
            started=$(python3 -c "
import json
try:
    d = json.load(open('${s}/session.json'))
    print(d.get('started_at','')[:19])
except:
    print('')
" 2>/dev/null)
        else
            started=""
        fi
        printf "  ${CYAN}%-3s${RESET} %-40s %6s   %s\n" \
            "$i" "$name" "$events_count" "$started"
        ((i++))
    done
    echo    "  ─────────────────────────────────────────────────────────────────"
    echo ""

    local choice idx selected_session
    while true; do
        read -rp "$(echo -e "  ${YELLOW}Select session number${RESET}: ")" choice
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            idx=$(( choice - 1 ))
            if [[ $idx -ge 0 && $idx -lt ${#sessions[@]} ]]; then
                selected_session="${sessions[$idx]}"
                break
            fi
        fi
        warn "Invalid selection. Enter a number between 1 and ${#sessions[@]}."
    done

    echo ""
    info "Generating report for: ${BOLD}$(basename "$selected_session")${RESET}"

    echo ""
    python3 "$SUMMARY" "$selected_session" --format md
    local exit_code=$?

    echo ""
    if [[ $exit_code -eq 0 ]]; then
        ok "Report saved in reports/summaries/"
    else
        warn "summary.py exited with code ${exit_code} — check output above for errors."
    fi
}

# ── Handle Ctrl-C cleanly ─────────────────────────────────────────────────────
trap 'echo ""; warn "Interrupted by user."; exit 130' INT

# ── Main flow ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   Android eBPF Monitor — Launcher    ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"

# ── Mode: CLI flags provided — skip menu ──────────────────────────────────────
if [[ -n "$CLI_PROBE" ]]; then
    [[ -f "${SCRIPT_DIR}/${CLI_PROBE}" ]] || die "Probe file not found: $CLI_PROBE"
    TIMER="${CLI_TIMER:-60}"
    run_probe "$CLI_PROBE" "$TIMER"
    exit 0
fi

# ── Interactive loop — B returns here, Q exits ────────────────────────────────
while true; do

    # ── Top-level mode selection ──────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}What do you want to do?${RESET}"
    echo ""
    echo -e "  ${CYAN}1${RESET}   Start a probe"
    echo -e "  ${CYAN}2${RESET}   Create a report from a session"
    echo -e "  ${CYAN}3${RESET}   Full monitoring  (run probe + auto-generate report)"
    echo -e "  ${CYAN}Q${RESET}   Quit"
    echo ""

    MODE=""
    while true; do
        read -rp "$(echo -e "  ${YELLOW}Select [1/2/3/Q]${RESET}: ")" MODE
        if [[ "$MODE" == "1" || "$MODE" == "2" || "$MODE" == "3" \
           || "${MODE^^}" == "Q" ]]; then
            break
        fi
        warn "Please enter 1, 2, 3 or Q."
    done

    # ── Quit ─────────────────────────────────────────────────────────────────
    if [[ "${MODE^^}" == "Q" ]]; then
        echo ""
        ok "Goodbye."
        echo ""
        exit 0
    fi

    # ── Mode 2: create report ─────────────────────────────────────────────────
    if [[ "$MODE" == "2" ]]; then
        create_report || true
        echo ""
        read -rp "$(echo -e "  ${YELLOW}Press Enter to return to the main menu or Q to quit${RESET}: ")" _back
        [[ "${_back^^}" == "Q" ]] && { echo ""; ok "Goodbye."; echo ""; exit 0; }
        continue
    fi

    # ── Mode 1 and 3: shared probe multi-selection ────────────────────────────
    [[ "$MODE" == "3" && ! -f "$SUMMARY" ]] && {
        warn "reports/summary.py not found — cannot run full monitoring."
        continue
    }

    SELECTED_PROBES=()
    print_probe_table

    while true; do
        echo -e "  ${BOLD}Selection options:${RESET}"
        echo -e "  Single probe       ${CYAN}3${RESET}"
        echo -e "  Multiple probes    ${CYAN}1 3 5${RESET}"
        echo -e "  All probes         ${CYAN}A${RESET}"
        echo -e "  Go back            ${CYAN}B${RESET}"
        echo ""
        read -rp "$(echo -e "  ${YELLOW}Your selection${RESET}: ")" choice
        echo ""

        [[ "${choice^^}" == "B" ]] && break

        if [[ "${choice^^}" == "A" ]]; then
            SELECTED_PROBES=("${AVAILABLE_PATHS[@]}")
            break
        fi

        valid=1
        temp_selection=()
        for token in $choice; do
            if [[ "$token" =~ ^[0-9]+$ ]]; then
                idx=$(( token - 1 ))
                if [[ $idx -ge 0 && $idx -lt ${#AVAILABLE_PATHS[@]} ]]; then
                    temp_selection+=("${AVAILABLE_PATHS[$idx]}")
                else
                    warn "Number $token is out of range (1–${#AVAILABLE_PATHS[@]})."
                    valid=0; break
                fi
            else
                warn "Invalid token: '$token'. Use numbers, A or B."
                valid=0; break
            fi
        done

        if [[ $valid -eq 1 && ${#temp_selection[@]} -gt 0 ]]; then
            # Deduplicate while preserving order
            declare -A _seen=()
            for p in "${temp_selection[@]}"; do
                if [[ -z "${_seen[$p]+x}" ]]; then
                    SELECTED_PROBES+=("$p")
                    _seen["$p"]=1
                fi
            done
            unset _seen
            break
        fi
    done

    # B was pressed — go back to main menu
    [[ ${#SELECTED_PROBES[@]} -eq 0 ]] && continue

    # Show summary of what will run
    n=${#SELECTED_PROBES[@]}
    if [[ $n -eq 1 ]]; then
        code=$(jq -r --arg k "${SELECTED_PROBES[0]}" '.[$k].code // "?"' "$PROBES_MAP")
        desc=$(jq -r --arg k "${SELECTED_PROBES[0]}" '.[$k].description // "No description."' "$PROBES_MAP")
        echo -e "  ${BOLD}Selected:${RESET} ${SELECTED_PROBES[0]} (${code})"
        echo -e "  ${BOLD}Info:${RESET}     $desc"
    else
        info "Selected ${n} probes:"
        for p in "${SELECTED_PROBES[@]}"; do
            code=$(jq -r --arg k "$p" '.[$k].code // "?"' "$PROBES_MAP")
            echo -e "    ${CYAN}${code}${RESET}  $p"
        done
    fi
    echo ""

    TIMER=$(ask_timer 60)

    if [[ $n -gt 1 ]]; then
        total_time=$(( n * TIMER ))
        info "Total estimated time: ${total_time}s (~$(( total_time / 60 ))m $(( total_time % 60 ))s)"
        echo ""
    fi

    # ── Mode 3: run probe + report for each ──────────────────────────────────
    if [[ "$MODE" == "3" ]]; then
        for i in "${!SELECTED_PROBES[@]}"; do
            p="${SELECTED_PROBES[$i]}"
            [[ $n -gt 1 ]] && echo -e "${BOLD}── Probe $(( i + 1 )) / ${n} ──${RESET}"
            full_monitoring "$p" "$TIMER" "md"
            if [[ $(( i + 1 )) -lt $n ]]; then
                info "Waiting 3s before next probe..."
                sleep 3
            fi
        done
        [[ $n -gt 1 ]] && ok "All full monitoring runs complete."
        echo ""
        read -rp "$(echo -e "  ${YELLOW}Press Enter to return to the main menu or Q to quit${RESET}: ")" _back
        [[ "${_back^^}" == "Q" ]] && { echo ""; ok "Goodbye."; echo ""; exit 0; }
        continue
    fi

    # ── Mode 1: run probes ────────────────────────────────────────────────────
    for i in "${!SELECTED_PROBES[@]}"; do
        p="${SELECTED_PROBES[$i]}"
        [[ $n -gt 1 ]] && echo -e "${BOLD}── Probe $(( i + 1 )) / ${n} ──${RESET}"
        run_probe "$p" "$TIMER"
        if [[ $(( i + 1 )) -lt $n ]]; then
            info "Waiting 3s before next probe..."
            sleep 3
        fi
    done
    [[ $n -gt 1 ]] && ok "All probes completed."

    echo ""
    read -rp "$(echo -e "  ${YELLOW}Press Enter to return to the main menu or Q to quit${RESET}: ")" _back
    [[ "${_back^^}" == "Q" ]] && { echo ""; ok "Goodbye."; echo ""; exit 0; }

done
