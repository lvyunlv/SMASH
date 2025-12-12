#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"

mkdir -p "$RESULTS_DIR"

OUTPUT_FILE="$RESULTS_DIR/share_conversion.txt"

read_line_safely() {
    local file="$1"
    local key="$2"
    local line=""

    for attempt in {1..40}; do
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

echo "n condition avg_offline_time avg_offline_comm avg_online_time avg_online_comm" > "$OUTPUT_FILE"

NS=(2 4 8 16 32)
NETS=("local" "lan" "wan")
BASE_PORT=20000

for n in "${NS[@]}"; do
    for net in "${NETS[@]}"; do

        PORT=$((BASE_PORT + RANDOM % 5000))
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

            "$BIN_DIR/test_L2A_mascot" "$i" "$PORT" "$n" "$net" > "$TMP_FILE" 2>&1 &
            PIDS+=($!)
        done

        for pid in "${PIDS[@]}"; do
            wait $pid
        done

        for tmpf in "${TMP_FILES[@]}"; do

            offline_line=$(read_line_safely "$tmpf" "Offline time")
            online_line=$(read_line_safely "$tmpf" "Online time")

            offline_time=$(echo "$offline_line" | awk '
                /Offline[[:space:]]+time/ {
                    for(i=1;i<=NF;i++){
                        if($i=="time:") print $(i+1)
                    }
                }')
            offline_comm=$(echo "$offline_line" | awk '
                /Offline[[:space:]]+time/ {
                    for(i=1;i<=NF;i++){
                        if($i=="comm:") print $(i+1)
                    }
                }')

            offline_time=$(echo "$offline_time" | sed -E 's/[^0-9eE+.-]//g')
            offline_comm=$(echo "$offline_comm" | sed -E 's/[^0-9eE+.-]//g')

            online_time=$(echo "$online_line" | awk '
                /Online[[:space:]]+time/ {
                    for(i=1;i<=NF;i++){
                        if($i=="time:") print $(i+1)
                    }
                }')
            online_comm=$(echo "$online_line" | awk '
                /Online[[:space:]]+time/ {
                    for(i=1;i<=NF;i++){
                        if($i=="comm:") print $(i+1)
                    }
                }')

            online_time=$(echo "$online_time" | sed -E 's/[^0-9eE+.-]//g')
            online_comm=$(echo "$online_comm" | sed -E 's/[^0-9eE+.-]//g')

            if [[ -n "$offline_time" && -n "$offline_comm" ]]; then
                OFF_TIMES+=("$offline_time")
                OFF_COMMS+=("$offline_comm")
            fi

            if [[ -n "$online_time" && -n "$online_comm" ]]; then
                ON_TIMES+=("$online_time")
                ON_COMMS+=("$online_comm")
            fi

            rm -f "$tmpf"
        done

        sum_off_time=0
        sum_off_comm=0
        sum_on_time=0
        sum_on_comm=0

        for t in "${OFF_TIMES[@]}"; do
            sum_off_time=$(awk -v a="$sum_off_time" -v b="$t" 'BEGIN {print a+b}')
        done
        for c in "${OFF_COMMS[@]}"; do
            sum_off_comm=$(awk -v a="$sum_off_comm" -v b="$c" 'BEGIN {print a+b}')
        done
        for t in "${ON_TIMES[@]}"; do
            sum_on_time=$(awk -v a="$sum_on_time" -v b="$t" 'BEGIN {print a+b}')
        done
        for c in "${ON_COMMS[@]}"; do
            sum_on_comm=$(awk -v a="$sum_on_comm" -v b="$c" 'BEGIN {print a+b}')
        done

        avg_off_time=$(awk -v s="$sum_off_time" -v c="${#OFF_TIMES[@]}" 'BEGIN {print s/c}')
        avg_off_comm=$(awk -v s="$sum_off_comm" -v c="${#OFF_COMMS[@]}" 'BEGIN {print s/c}')
        avg_on_time=$(awk -v s="$sum_on_time" -v c="${#ON_TIMES[@]}" 'BEGIN {print s/c}')
        avg_on_comm=$(awk -v s="$sum_on_comm" -v c="${#ON_COMMS[@]}" 'BEGIN {print s/c}')

        echo "$n $net $avg_off_time $avg_off_comm $avg_on_time $avg_on_comm" >> "$OUTPUT_FILE"

        echo "Done n=$n, network=$net"
        echo "    offline avg: time=$avg_off_time s, comm=$avg_off_comm MB"
        echo "    online  avg: time=$avg_on_time s, comm=$avg_on_comm MB"
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
