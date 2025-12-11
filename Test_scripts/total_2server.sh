#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"  
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
IP_FILE="$BASE_DIR/config/parties8.txt"

NET="wan"
TOTAL_PARTIES=6
START_ID=4
END_ID=6

mkdir -p "$RESULTS_DIR/logs"
mkdir -p "$BASE_DIR/Input"

INPUT_FILE="$BASE_DIR/Input/Input-P.txt"

read_line_safely() {
    local file="$1"
    local key="$2"
    local line=""

    for attempt in {1..60}; do
        if [[ -f "$file" ]]; then
            line=$(grep "$key" "$file")
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

echo "[Current machine] Generating random input file: $INPUT_FILE"
: > "$INPUT_FILE"
for ((k=1;k<=1;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done

echo "=== Current machine launching parties $START_ID to $END_ID ==="
PIDS=()

for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"
    target_ip=$(awk -v line="$i" 'NR==line{print $1}' "$IP_FILE")

    echo "[Current machine] Launching Party $i -> $target_ip"
    ping -c 1 -W 1 "$target_ip" >/dev/null || \
        echo "[Current machine] WARNING: Party $i unreachable!"

    timeout 300 "$BIN_DIR/test_lvt_online" \
        "$i" 0 "$TOTAL_PARTIES" "$NET" "$IP_FILE" \
        > "$LOG_FILE" 2>&1 &

    PIDS+=($!)
done

echo "[Current machine] Waiting for all parties..."
for pid in "${PIDS[@]}"; do
    wait $pid
done
echo "[Current machine] All parties finished."

SUMMARY_FILE="$RESULTS_DIR/total_2server.txt"
echo "party offline_time(s) offline_comm(MB) online_time(s) online_comm(MB)" > "$SUMMARY_FILE"

sum_off_time=0
sum_off_comm=0
sum_on_time=0
sum_on_comm=0
count=0

for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"

    offline_line=$(read_line_safely "$LOG_FILE" "Offline time")
    online_line=$(read_line_safely "$LOG_FILE"  "Online time")

    # ======= OFFLINE =======
    offline_time=$(echo "$offline_line" | awk '/Offline[[:space:]]+time/ {for(i=1;i<=NF;i++){if($i=="time:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')
    offline_comm=$(echo "$offline_line" | awk '/Offline[[:space:]]+time/ {for(i=1;i<=NF;i++){if($i=="comm:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')

    if [[ -z "$offline_time" || -z "$offline_comm" ]]; then
        t_off="ERROR"
        c_off="ERROR"
    else
        t_off="$offline_time"
        c_off="$offline_comm"
    fi

    # ======= ONLINE =======
    online_time=$(echo "$online_line" | awk '/Online[[:space:]]+time/ {for(i=1;i<=NF;i++){if($i=="time:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')
    online_comm=$(echo "$online_line" | awk '/Online[[:space:]]+time/ {for(i=1;i<=NF;i++){if($i=="comm:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')

    if [[ -z "$online_time" || -z "$online_comm" ]]; then
        t_on="ERROR"
        c_on="ERROR"
    else
        t_on="$online_time"
        c_on="$online_comm"
    fi

    echo "$i $t_off $c_off $t_on $c_on" >> "$SUMMARY_FILE"

    if [[ $t_off != "ERROR" ]]; then
        sum_off_time=$(awk -v a="$sum_off_time" -v b="$t_off" 'BEGIN {print a+b}')
        sum_off_comm=$(awk -v a="$sum_off_comm" -v b="$c_off" 'BEGIN {print a+b}')
        sum_on_time=$(awk -v a="$sum_on_time" -v b="$t_on" 'BEGIN {print a+b}')
        sum_on_comm=$(awk -v a="$sum_on_comm" -v b="$c_on" 'BEGIN {print a+b}')
        count=$((count+1))
    fi
done

if [[ $count -gt 0 ]]; then
    avg_off_time=$(awk -v s="$sum_off_time" -v c="$count" 'BEGIN {print s/c}')
    avg_off_comm=$(awk -v s="$sum_off_comm" -v c="$count" 'BEGIN {print s/c}')
    avg_on_time=$(awk -v s="$sum_on_time" -v c="$count" 'BEGIN {print s/c}')
    avg_on_comm=$(awk -v s="$sum_on_comm" -v c="$count" 'BEGIN {print s/c}')

    {
        echo ""
        echo "avg_offline_time $avg_off_time"
        echo "avg_offline_comm $avg_off_comm"
        echo "avg_online_time $avg_on_time"
        echo "avg_online_comm $avg_on_comm"
    } >> "$SUMMARY_FILE"

    echo "[Current machine] Summary written to: $SUMMARY_FILE"
    echo "[Current machine] offline avg_time = $avg_off_time s, offline avg_comm = $avg_off_comm MB"
    echo "[Current machine] online  avg_time = $avg_on_time s, online  avg_comm = $avg_on_comm MB"
else
    echo "[Current machine] No valid logs found!"
fi
