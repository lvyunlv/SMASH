#!/bin/bash

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_DIR="$BASE_DIR/Input"
INPUT_FILE="$INPUT_DIR/Input-P.txt"
CONFIG_DIR="$BASE_DIR/config"
IP_FILE="$CONFIG_DIR/parties8.txt"
SUMMARY_FILE="$RESULTS_DIR/semi_online_10k_2server.txt"

NET="wan"
TOTAL_PARTIES=6
START_ID=4
END_ID=6

mkdir -p "$RESULTS_DIR/logs"
mkdir -p "$INPUT_DIR"

echo "=== Current machine launching parties $START_ID to $END_ID ==="
echo "[Current machine] Generating random input file: $INPUT_FILE"

: > "$INPUT_FILE"
for ((k=1;k<=10000;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done

read_online_line() {
    local file="$1"
    local line=""
    for attempt in {1..60}; do
        if [[ -f "$file" ]]; then
            line=$(grep "Online time" "$file")
            if [[ -n "$line" ]]; then
                echo "$line"
                return 0
            fi
        fi
        sleep 0.05
    done
    echo ""
    return 1
}

PIDS=()

for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"
    target_ip=$(awk "NR==$i {print \$1}" "$IP_FILE")

    echo "[Current machine] Launching Party $i -> $target_ip"

    ping -c 1 -W 1 "$target_ip" >/dev/null || \
        echo "[Current machine] WARNING: Party $i target unreachable!"

    timeout 100 "$BIN_DIR/test_lvt_semi" \
        "$i" 0 "$TOTAL_PARTIES" "$NET" "$IP_FILE" \
        > "$LOG_FILE" 2>&1 &

    PIDS+=($!)
done

echo "[Current machine] Waiting for all local parties..."
for pid in "${PIDS[@]}"; do
    wait "$pid"
done
echo "[Current machine] All parties finished."

echo "party online_time(s) comm(MB)" > "$SUMMARY_FILE"

sum_time=0
sum_comm=0
count=0

for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"

    line=$(read_online_line "$LOG_FILE")

    if [[ -n "$line" ]]; then
        t=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="time:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')
        c=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="comm:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')

        if [[ -n "$t" && -n "$c" ]]; then
            echo "$i $t $c" >> "$SUMMARY_FILE"
            sum_time=$(awk -v a="$sum_time" -v b="$t" 'BEGIN {printf "%.10f", a+b}')
            sum_comm=$(awk -v a="$sum_comm" -v b="$c" 'BEGIN {printf "%.10f", a+b}')
            count=$((count+1))
        else
            echo "$i ERROR ERROR" >> "$SUMMARY_FILE"
            echo "[WARN] Unable to parse Online time in $LOG_FILE"
        fi
    else
        echo "$i ERROR ERROR" >> "$SUMMARY_FILE"
        echo "[WARN] Missing Online time in $LOG_FILE"
    fi
done

if [[ $count -gt 0 ]]; then
    avg_time=$(awk -v s="$sum_time" -v c="$count" 'BEGIN {printf "%.10f", s/c}')
    avg_comm=$(awk -v s="$sum_comm" -v c="$count" 'BEGIN {printf "%.10f", s/c}')

    {
        echo ""
        echo "avg_time $avg_time"
        echo "avg_comm $avg_comm"
    } >> "$SUMMARY_FILE"

    echo "[Current machine] Summary written to: $SUMMARY_FILE"
    echo "[Current machine] avg_time = $avg_time s"
    echo "[Current machine] avg_comm = $avg_comm MB"
else
    echo "[Current machine] No valid logs found!"
fi
