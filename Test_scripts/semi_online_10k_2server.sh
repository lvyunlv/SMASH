#!/bin/bash
BASE_DIR="/workspace/lyl/SMASH"
BIN_DIR="$BASE_DIR/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_FILE="$BASE_DIR/Input/Input-P.txt"
IP_FILE="$BASE_DIR/config/parties8.txt"
SUMMARY_FILE="$RESULTS_DIR/semi_online_10k_2server.txt"

NET="wan"    # local/lan/wan
TOTAL_PARTIES=6
START_ID=4    
END_ID=6

mkdir -p "$RESULTS_DIR/logs"
echo "=== Current machine launching parties $START_ID to $END_ID ==="
mkdir -p "$BASE_DIR/Input"
echo "[Current machine] Generating random input file: $INPUT_FILE"

: > "$INPUT_FILE" 
for ((k=1;k<=10000;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done
PIDS=()
for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"
    target_ip=$(awk "NR==$i {print \$1}" "$IP_FILE")

    echo "[Current machine] Launching Party $i -> $target_ip"
    ping -c 1 -W 1 "$target_ip" >/dev/null || echo "[Current machine] WARNING: Party $i target unreachable!"

    timeout 100 "$BIN_DIR/test_lvt_semi" \
        "$i" 0 "$TOTAL_PARTIES" "$NET" "$IP_FILE" \
        > "$LOG_FILE" 2>&1 &

    PIDS+=($!)
done

echo "[Current machine] Waiting for all local parties..."
for pid in "${PIDS[@]}"; do
    wait $pid
done
echo "[Current machine] All parties finished."

echo "party online_time(s) comm(MB)" > "$SUMMARY_FILE"

sum_time=0
sum_comm=0
count=0

for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"

    line=$(grep "Online time:" "$LOG_FILE")

    if [[ $line =~ Online\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
        t=${BASH_REMATCH[1]}
        c=${BASH_REMATCH[2]}
        echo "$i $t $c" >> "$SUMMARY_FILE"

        sum_time=$(awk "BEGIN {print $sum_time + $t}")
        sum_comm=$(awk "BEGIN {print $sum_comm + $c}")
        count=$((count+1))
    else
        echo "$i ERROR ERROR" >> "$SUMMARY_FILE"
    fi
done

if [[ $count -gt 0 ]]; then
    avg_time=$(awk "BEGIN {print $sum_time / $count}")
    avg_comm=$(awk "BEGIN {print $sum_comm / $count}")

    echo "" >> "$SUMMARY_FILE"
    echo "avg_time $avg_time" >> "$SUMMARY_FILE"
    echo "avg_comm $avg_comm" >> "$SUMMARY_FILE"

    echo "[Current machine] Summary written to: $SUMMARY_FILE"
    echo "[Current machine] avg_time = $avg_time s"
    echo "[Current machine] avg_comm = $avg_comm MB"
else
    echo "[Current machine] No valid logs found!"
fi
