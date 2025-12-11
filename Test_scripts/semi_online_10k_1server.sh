#!/bin/bash

BASE_DIR="/workspace/lyl/SMASH"
BIN_DIR="$BASE_DIR/bin"
RESULTS_DIR="$BASE_DIR/Results"
OUTPUT_FILE="$RESULTS_DIR/semi_online_10k_1server.txt"
INPUT_FILE="$BASE_DIR/Input/Input-P.txt"
mkdir -p "$BASE_DIR/Input"
mkdir -p "$RESULTS_DIR"
echo "n condition avg_time(s) avg_comm(MB)" > "$OUTPUT_FILE"
echo "[Current machine] Generating random input file: $INPUT_FILE"
NS=(2 4 8 16 32)
NETS=("local" "lan" "wan")

: > "$INPUT_FILE"  
for ((k=1;k<=10000;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done

for n in "${NS[@]}"; do
    for net in "${NETS[@]}"; do
        echo "Running n=$n, network=$net ..."
        
        TIMES=()
        COMMS=()

        PIDS=()
        TMP_FILES=()
        for ((i=1;i<=n;i++)); do
            TMP_FILE=$(mktemp)
            TMP_FILES+=("$TMP_FILE")
            "$BIN_DIR/test_lvt_semi" "$i" $((31947)) "$n" "$net" > "$TMP_FILE" 2>&1 &
            PIDS+=($!)
        done

        for pid in "${PIDS[@]}"; do
            wait $pid
        done

        for tmpf in "${TMP_FILES[@]}"; do
            line=$(grep "Online time" "$tmpf")
            if [[ $line =~ Online\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
                TIMES+=("${BASH_REMATCH[1]}")
                COMMS+=("${BASH_REMATCH[2]}")
            fi
            rm -f "$tmpf"
        done

        sum_time=0
        sum_comm=0
        for t in "${TIMES[@]}"; do
            sum_time=$(awk "BEGIN {print $sum_time + $t}")
        done
        for c in "${COMMS[@]}"; do
            sum_comm=$(awk "BEGIN {print $sum_comm + $c}")
        done

        avg_time=$(awk "BEGIN {print $sum_time / ${#TIMES[@]}}")
        avg_comm=$(awk "BEGIN {print $sum_comm / ${#COMMS[@]}}")

        echo "$n $net $avg_time $avg_comm" >> "$OUTPUT_FILE"
        echo "Done n=$n, network=$net -> avg_time=$avg_time s, avg_comm=$avg_comm MB"
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
