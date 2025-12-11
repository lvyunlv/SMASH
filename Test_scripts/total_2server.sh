#!/bin/bash
BASE_DIR="/workspace/lyl/SMASH"
BIN_DIR="$BASE_DIR/bin"
RESULTS_DIR="$BASE_DIR/Results"
IP_FILE="$BASE_DIR/config/parties8.txt"

NET="wan"    # local/lan/wan    
TOTAL_PARTIES=6
START_ID=4    
END_ID=6

mkdir -p "$RESULTS_DIR/logs"

echo "=== Current machine launching parties $START_ID to $END_ID ==="
INPUT_FILE="$BASE_DIR/Input/Input-P.txt"
mkdir -p "$BASE_DIR/Input"

echo "[Current machine] Generating random input file: $INPUT_FILE"

: > "$INPUT_FILE"  
for ((k=1;k<=1;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done
PIDS=()
for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"
    target_ip=$(awk "NR==$i {print \$1}" "$IP_FILE")

    echo "[Current machine] Launching Party $i -> $target_ip"
    ping -c 1 -W 1 "$target_ip" >/dev/null || echo "[Current machine] WARNING: Party $i target unreachable!"

    timeout 200 "$BIN_DIR/test_lvt_online" \
        "$i" 0 "$TOTAL_PARTIES" "$NET" "$IP_FILE" \
        > "$LOG_FILE" 2>&1 &

    PIDS+=($!)
done

echo "[Current machine] Waiting for all local parties..."
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

    offline_line=$(grep "Offline time:" "$LOG_FILE")
    online_line=$(grep  "Online time:" "$LOG_FILE")

    # ====== OFFLINE ======
    if [[ $offline_line =~ Offline\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
        t_off=${BASH_REMATCH[1]}
        c_off=${BASH_REMATCH[2]}
    else
        t_off="ERROR"
        c_off="ERROR"
    fi

    # ====== ONLINE ======
    if [[ $online_line =~ Online\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
        t_on=${BASH_REMATCH[1]}
        c_on=${BASH_REMATCH[2]}
    else
        t_on="ERROR"
        c_on="ERROR"
    fi

    echo "$i $t_off $c_off $t_on $c_on" >> "$SUMMARY_FILE"

    if [[ $t_off != "ERROR" ]]; then
        sum_off_time=$(awk "BEGIN {print $sum_off_time + $t_off}")
        sum_off_comm=$(awk "BEGIN {print $sum_off_comm + $c_off}")
        sum_on_time=$(awk "BEGIN {print $sum_on_time + $t_on}")
        sum_on_comm=$(awk "BEGIN {print $sum_on_comm + $c_on}")
        count=$((count+1))
    fi
done

if [[ $count -gt 0 ]]; then
    avg_off_time=$(awk "BEGIN {print $sum_off_time / $count}")
    avg_off_comm=$(awk "BEGIN {print $sum_off_comm / $count}")
    avg_on_time=$(awk "BEGIN {print $sum_on_time / $count}")
    avg_on_comm=$(awk "BEGIN {print $sum_on_comm / $count}")

    echo "" >> "$SUMMARY_FILE"
    echo "avg_offline_time $avg_off_time" >> "$SUMMARY_FILE"
    echo "avg_offline_comm $avg_off_comm" >> "$SUMMARY_FILE"
    echo "avg_online_time $avg_on_time" >> "$SUMMARY_FILE"
    echo "avg_online_comm $avg_on_comm" >> "$SUMMARY_FILE"

    echo "[Current machine] Summary written to: $SUMMARY_FILE"
    echo "[Current machine] offline avg_time = $avg_off_time s, offline avg_comm = $avg_off_comm MB"
    echo "[Current machine] online  avg_time = $avg_on_time s, online  avg_comm = $avg_on_comm MB"
else
    echo "[Current machine] No valid logs found!"
fi
