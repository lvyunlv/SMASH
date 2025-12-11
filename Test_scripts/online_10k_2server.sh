#!/bin/bash

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_DIR="$BASE_DIR/Input"
CONFIG_DIR="$BASE_DIR/config"

INPUT_FILE="$INPUT_DIR/Input-P.txt"
IP_FILE="$CONFIG_DIR/parties8.txt"
SUMMARY_FILE="$RESULTS_DIR/online_10k_2server.txt"

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

PIDS=()

for ((i=START_ID;i<=END_ID;i++)); do
    LOG_FILE="$RESULTS_DIR/logs/party_${i}.log"

    time_val=$(awk '
        /Online[[:space:]]+time/ {
            for(i=1;i<=NF;i++){
                if($i=="time:") print $(i+1);
            }
        }' "$LOG_FILE")

    comm_val=$(awk '
        /Online[[:space:]]+time/ {
            for(i=1;i<=NF;i++){
                if($i=="comm:") print $(i+1);
            }
        }' "$LOG_FILE")

    time_val=$(echo "$time_val" | sed -E 's/[^0-9eE+.-]//g')
    comm_val=$(echo "$comm_val" | sed -E 's/[^0-9eE+.-]//g')

    if [[ -n "$time_val" && -n "$comm_val" ]]; then
        echo "$i $time_val $comm_val" >> "$SUMMARY_FILE"

        sum_time=$(awk -v a="$sum_time" -v b="$time_val" 'BEGIN {printf "%.10f", a+b}')
        sum_comm=$(awk -v a="$sum_comm" -v b="$comm_val" 'BEGIN {printf "%.10f", a+b}')

        count=$((count+1))
    else
        echo "$i ERROR ERROR" >> "$SUMMARY_FILE"
    fi
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
    line=$(grep "Online time:" "$LOG_FILE")

    if [[ $line =~ Online\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
        t=${BASH_REMATCH[1]}
        c=${BASH_REMATCH[2]}

        echo "$i $t $c" >> "$SUMMARY_FILE"

        sum_time=$(awk -v a="$sum_time" -v b="$t" 'BEGIN {printf "%.10f", a+b}')
        sum_comm=$(awk -v a="$sum_comm" -v b="$c" 'BEGIN {printf "%.10f", a+b}')

        count=$((count+1))
    else
        echo "$i ERROR ERROR" >> "$SUMMARY_FILE"
    fi
done

if [[ $count -gt 0 ]]; then
    avg_time=$(awk -v s="$sum_time" -v c="$count" 'BEGIN {printf "%.10f", s/c}')
    avg_comm=$(awk -v s="$sum_comm" -v c="$count" 'BEGIN {printf "%.10f", s/c}')

    echo "" >> "$SUMMARY_FILE"
    echo "avg_time $avg_time" >> "$SUMMARY_FILE"
    echo "avg_comm $avg_comm" >> "$SUMMARY_FILE"

    echo "[Current machine] Summary written to: $SUMMARY_FILE"
    echo "[Current machine] avg_time = $avg_time s"
    echo "[Current machine] avg_comm = $avg_comm MB"
else
    echo "[Current machine] No valid logs found!"
fi
