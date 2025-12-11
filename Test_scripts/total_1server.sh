#!/bin/bash

BASE_DIR="/workspace/lyl/SMASH"
BIN_DIR="$BASE_DIR/bin"
RESULTS_DIR="$BASE_DIR/Results"
OUTPUT_FILE="$RESULTS_DIR/total_1server.txt"
INPUT_FILE="$BASE_DIR/Input/Input-P.txt"
mkdir -p "$BASE_DIR/Input"
mkdir -p "$RESULTS_DIR"

echo "[Current machine] Generating random input file: $INPUT_FILE"
echo "n condition avg_offline_time avg_offline_comm avg_online_time avg_online_comm" > "$OUTPUT_FILE"

NS=(2 4 8 16 32)
NETS=("local" "lan" "wan")

: > "$INPUT_FILE"  
for ((k=1;k<=1;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done

for n in "${NS[@]}"; do
    for net in "${NETS[@]}"; do
        echo "Running n=$n, network=$net ..."

        OFF_TIMES=()
        OFF_COMMS=()
        ON_TIMES=()
        ON_COMMS=()

        PIDS=()
        TMP_FILES=()

        for ((i=1;i<=n;i++)); do
            TMP_FILE=$(mktemp)
            TMP_FILES+=("$TMP_FILE")

            "$BIN_DIR/test_lvt" "$i" 31947 "$n" "$net" > "$TMP_FILE" 2>&1 &
            PIDS+=($!)
        done

        for pid in "${PIDS[@]}"; do
            wait $pid
        done

        for tmpf in "${TMP_FILES[@]}"; do
            offline_line=$(grep "Offline time" "$tmpf")
            online_line=$(grep "Online time" "$tmpf")

            # Offline
            if [[ $offline_line =~ Offline\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
                OFF_TIMES+=("${BASH_REMATCH[1]}")
                OFF_COMMS+=("${BASH_REMATCH[2]}")
            fi

            # Online
            if [[ $online_line =~ Online\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
                ON_TIMES+=("${BASH_REMATCH[1]}")
                ON_COMMS+=("${BASH_REMATCH[2]}")
            fi

            rm -f "$tmpf"
        done

        sum_off_time=0
        sum_off_comm=0
        sum_on_time=0
        sum_on_comm=0

        for t in "${OFF_TIMES[@]}"; do
            sum_off_time=$(awk "BEGIN {print $sum_off_time + $t}")
        done
        for c in "${OFF_COMMS[@]}"; do
            sum_off_comm=$(awk "BEGIN {print $sum_off_comm + $c}")
        done
        for t in "${ON_TIMES[@]}"; do
            sum_on_time=$(awk "BEGIN {print $sum_on_time + $t}")
        done
        for c in "${ON_COMMS[@]}"; do
            sum_on_comm=$(awk "BEGIN {print $sum_on_comm + $c}")
        done

        avg_off_time=$(awk "BEGIN {print $sum_off_time / ${#OFF_TIMES[@]}}")
        avg_off_comm=$(awk "BEGIN {print $sum_off_comm / ${#OFF_COMMS[@]}}")
        avg_on_time=$(awk "BEGIN {print $sum_on_time / ${#ON_TIMES[@]}}")
        avg_on_comm=$(awk "BEGIN {print $sum_on_comm / ${#ON_COMMS[@]}}")

        echo "$n $net $avg_off_time $avg_off_comm $avg_on_time $avg_on_comm" >> "$OUTPUT_FILE"

        echo "Done n=$n, network=$net"
        echo "    offline avg: time=$avg_off_time s, comm=$avg_off_comm MB"
        echo "    online  avg: time=$avg_on_time s, comm=$avg_on_comm MB"
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
