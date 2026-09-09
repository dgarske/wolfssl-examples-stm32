#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# bench_matrix.sh -- drive `make BOARD=<x> CONFIG=<y> TARGET=bench flash`
# across the STM32 BARE board matrix and capture UART output to logs.
#
# Logs land in bench_logs/<board>_<config>.log so parse_bench.py (companion
# script) can extract a structured table for the README.
#
# Requirements (one-time):
#   - uart-monitor daemon running with the PTY for each board you intend to
#     bench (the /tmp/uart-monitor/pty/<NAME>_UART path must exist).
#   - The Makefile's TARGET=bench, flash, and per-board STLINK_SERIAL plumbing
#     working (i.e. you can already run `make BOARD=h7 CONFIG=bare TARGET=bench
#     flash` interactively).
#
# Usage:
#   ./bench_matrix.sh                    # all boards x {bare,asm,c}
#   ./bench_matrix.sh -b h7              # one board, all configs
#   ./bench_matrix.sh -b h7,u585 -c bare # specific boards / configs
#   ./bench_matrix.sh -t 900             # custom per-run timeout (seconds)
#   ./bench_matrix.sh -b u585 -S         # add a STACK=1 mem-tracked companion
#                                        #   run per config (<stem>_stack.log)
#   ./bench_matrix.sh --dry-run          # show planned runs, don't flash
#
# Exit code is the count of failed runs (0 = all good).
# ---------------------------------------------------------------------------
set -euo pipefail

# ---- Board -> uart-monitor PTY map ---------------------------------------
declare -A PTY_NAME=(
    [c031]=NUCLEO_C031C6_UART
    [c562]=STM32_STLINK_V3_UART_35383531
    [c5a3]=STM32C5A3_UART
    [f207]=NUCLEO_F207ZG_UART
    [f303]=GENERIC_UART_ttyUSB0
    [f437]=GENERIC_UART_ttyUSB0
    [f439]=NUCLEO_F439ZI_UART
    [f767]=NUCLEO_F767ZI_UART
    [g071]=NUCLEO_G071RB_UART
    [g474]=NUCLEO_G474RE_UART
    [g491]=NUCLEO_G491RE_UART
    [h5]=NUCLEO_H563ZI_UART
    [h573]=NUCLEO_H573ZI_UART
    [h7]=NUCLEO_H753ZI_UART
    [h723]=NUCLEO_H723ZG_UART
    [h7a3]=NUCLEO_H7A3ZI_Q_UART
    [h7s3]=NUCLEO_H7S3L8_UART
    [l4a6]=NUCLEO_L4A6ZG_UART
    [l552]=NUCLEO_L552ZE_Q_UART
    [l562]=STM32_VIRTUAL_COM_PORT_UART
    [n657]=NUCLEO_N657X0_Q_UART
    [u083]=NUCLEO_U083RC_UART
    [u3]=NUCLEO_U385RG_Q_UART
    [u5]=NUCLEO_U575ZI_Q_UART
    [u545]=NUCLEO_U545RE_Q_UART
    [u585]=B_U585I_IOT02A_UART
    # v8 has no UART yet -- console is a .noinit RAM buffer read over SWD.
    # This name is aspirational; not a working capture source until UART lands.
    [v8]=STM32_STLINK_V3_UART_34313937
    [wb55]=NUCLEO_WB55RG_UART
    [wba52]=NUCLEO_WBA52CG_UART
    [wl55]=NUCLEO_WL55JC_UART
)

# Boards excluded from the bench sweep (and why).
# Format: "<board>:<reason>".
declare -A EXCLUDE=(
    [c031]="bench overflows 32 KB flash"
    [v8]="passes but runs uncached (~20min/config); enable caches before sweeping"
)

# Per (board,config) skip set: M0/M0+ cannot build the asm config.
declare -A SKIP_BOARD_CONFIG=(
    [g071,asm]="M0+ has no Thumb2 ASM"
    [u083,asm]="M0+ has no Thumb2 ASM"
)

# ---- Argument parsing ----------------------------------------------------
ALL_BOARDS=(c562 c5a3 f207 f303 f437 f439 f767 g071 g474 g491 h5 h573 h7 h723 \
            h7a3 h7s3 l4a6 l552 l562 n657 u083 u3 u5 u545 u585 v8 wb55 wba52 wl55)
ALL_CONFIGS=(bare asm c)

BOARDS_ARG=""
CONFIGS_ARG=""
BUILD_AXIS=bare   # bare (default) or cubemx -- per the Makefile BUILD axis
TIMEOUT_S=900     # 15 min default per run
DRY_RUN=0
KEEP_BUILD=0
RUN_STACK=0       # -S: also run each config with STACK=1 (mem-tracked) into
                  # a companion <stem>_stack.log for parse_bench.py

usage() {
    sed -n '/^# ---/,/^# ---/p' "$0" | head -40 | sed 's/^# \?//'
    exit "${1:-1}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--boards)   BOARDS_ARG="$2"; shift 2;;
        -c|--configs)  CONFIGS_ARG="$2"; shift 2;;
        -B|--build)    BUILD_AXIS="$2"; shift 2;;
        -t|--timeout)  TIMEOUT_S="$2"; shift 2;;
        -k|--keep)     KEEP_BUILD=1; shift;;
        -S|--stack)    RUN_STACK=1; shift;;
        -n|--dry-run)  DRY_RUN=1; shift;;
        -h|--help)     usage 0;;
        *) echo "unknown arg: $1" >&2; usage 1;;
    esac
done

if [ -n "$BOARDS_ARG" ]; then
    IFS=',' read -ra BOARDS <<< "$BOARDS_ARG"
else
    BOARDS=("${ALL_BOARDS[@]}")
fi
if [ -n "$CONFIGS_ARG" ]; then
    IFS=',' read -ra CONFIGS <<< "$CONFIGS_ARG"
else
    CONFIGS=("${ALL_CONFIGS[@]}")
fi

# ---- Paths ---------------------------------------------------------------
TOP="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$TOP/bench_logs"
PTY_DIR=/tmp/uart-monitor/pty            # legacy reference -- not used
MON_LOG_DIR=/tmp/uart-monitor/latest     # uart-monitor session logs
mkdir -p "$LOG_DIR"

# ---- Helpers -------------------------------------------------------------
ts() { date '+%F %T'; }
say() { printf '[%s] %s\n' "$(ts)" "$*"; }

flash_one() {
    local board="$1" config="$2" stack="${3:-0}"
    local pty_name="${PTY_NAME[$board]:-}"
    # File-name suffix encodes the BUILD axis so bare- and cubemx-built
    # runs land in distinct files; STACK=1 adds a trailing _stack token so
    # its mem metrics merge onto the same (board, config) in parse_bench.py.
    local stem="${board}_${config}"
    if [ "$BUILD_AXIS" != "bare" ]; then
        stem="${board}_${BUILD_AXIS}_${config}"
    fi
    if [ "$stack" = "1" ]; then
        stem="${stem}_stack"
    fi
    local log="$LOG_DIR/${stem}.log"
    local build_log="$LOG_DIR/${stem}.build.log"

    if [ -z "$pty_name" ]; then
        say "SKIP $board:$config -- no PTY mapping"
        echo "SKIP no PTY mapping" > "$log"
        return 2
    fi
    local monitor_log="$MON_LOG_DIR/${pty_name}.log"
    if [ ! -f "$monitor_log" ]; then
        say "SKIP $board:$config -- monitor log $monitor_log missing"
        echo "SKIP monitor log $monitor_log missing" > "$log"
        return 2
    fi

    say "RUN  $board:$config -> $log  (monitor $pty_name)"
    : > "$log"
    : > "$build_log"
    {
        echo "# bench_matrix.sh $board $config @ $(ts)"
        echo "# Monitor log: $monitor_log"
        echo "# Timeout: ${TIMEOUT_S}s"
    } >> "$build_log"

    set +e
    ( cd "$TOP" && make -s BOARD="$board" BUILD="$BUILD_AXIS" \
        CONFIG="$config" STACK="$stack" TARGET=bench clean ) >> "$build_log" 2>&1
    ( cd "$TOP" && make -s BOARD="$board" BUILD="$BUILD_AXIS" \
        CONFIG="$config" STACK="$stack" TARGET=bench flash ) >> "$build_log" 2>&1
    local flash_rc=$?
    set -e

    if [ $flash_rc -ne 0 ]; then
        say "FAIL $board:$config -- flash returned $flash_rc"
        echo "# FLASH_FAILED rc=$flash_rc" >> "$log"
        return 1
    fi

    # Mark current size of the uart-monitor log; we only consider bytes
    # written AFTER this offset to be from the new bench binary.
    local offset
    offset=$(stat -c %s "$monitor_log" 2>/dev/null || echo 0)

    local deadline=$(( $(date +%s) + TIMEOUT_S ))
    local done=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if tail -c +$((offset + 1)) "$monitor_log" 2>/dev/null \
                | grep -q -E '^(Benchmark complete|Benchmark result:)'; then
            done=1
            break
        fi
        sleep 5
    done

    # Capture the slice into our per-(board,config) log.
    tail -c +$((offset + 1)) "$monitor_log" >> "$log" 2>/dev/null || true

    if [ $done -eq 1 ]; then
        say "DONE $board:$config"
        echo "# COMPLETED @ $(ts)" >> "$log"
        return 0
    fi
    say "TIMEOUT $board:$config after ${TIMEOUT_S}s"
    echo "# TIMEOUT @ $(ts)" >> "$log"
    return 1
}

# ---- Main loop -----------------------------------------------------------
fail_count=0
total=0
skipped=0

for board in "${BOARDS[@]}"; do
    if [ -n "${EXCLUDE[$board]:-}" ]; then
        say "EXCLUDE $board -- ${EXCLUDE[$board]}"
        continue
    fi
    for config in "${CONFIGS[@]}"; do
        if [ -n "${SKIP_BOARD_CONFIG[$board,$config]:-}" ]; then
            say "SKIP $board:$config -- ${SKIP_BOARD_CONFIG[$board,$config]}"
            skipped=$((skipped+1))
            continue
        fi
        total=$((total+1))
        if [ $DRY_RUN -eq 1 ]; then
            printf '  DRY  %s %s\n' "$board" "$config"
            if [ $RUN_STACK -eq 1 ]; then
                printf '  DRY  %s %s (STACK=1)\n' "$board" "$config"
            fi
            continue
        fi
        if ! flash_one "$board" "$config" 0; then
            fail_count=$((fail_count+1))
        fi
        if [ $RUN_STACK -eq 1 ]; then
            if ! flash_one "$board" "$config" 1; then
                fail_count=$((fail_count+1))
            fi
        fi
        if [ $KEEP_BUILD -eq 0 ]; then
            ( cd "$TOP" && make -s BOARD="$board" BUILD="$BUILD_AXIS" \
                CONFIG="$config" TARGET=bench clean ) >/dev/null 2>&1 || true
        fi
    done
done

echo
say "summary: total=$total fail=$fail_count skip=$skipped log_dir=$LOG_DIR"
exit "$fail_count"
