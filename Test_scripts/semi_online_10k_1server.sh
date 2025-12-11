#!/bin/bash

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_DIR="$BASE_DIR/Input"
INPUT_FILE="$INPUT_DIR/Input-P.txt"
OUTPUT_FILE="$RESULTS_DIR/semi_online_10k_1server.txt"

mkdir -p "$INPUT_DIR"
mkdir -p "$RESULTS_DIR"

echo "n network avg_time(s) avg_comm(MB)" > "$OUTPUT_FILE"
echo "[Current machine] Generating random input file: $INPUT_FILE"

NS=(2 4 8 16 32)
NETS=("local" "lan" "wan")

: > "$INPUT_FILE"
for ((k=1;k<=10000;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done

read_online_line() {
    local file="$1"
    local line=""
    for attempt in {1..40}; do
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

            "$BIN_DIR/test_lvt_semi" "$i" 31947 "$n" "$net" > "$TMP_FILE" 2>&1 &
            PIDS+=($!)
        done

        for pid in "${PIDS[@]}"; do
            wait "$pid"
        done

        for tmpf in "${TMP_FILES[@]}"; do
            line=$(read_online_line "$tmpf")
            if [[ -n "$line" ]]; then
                t=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="time:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')
                c=$(echo "$line" | awk '{for(i=1;i<=NF;i++){if($i=="comm:") print $(i+1)}}' | sed -E 's/[^0-9eE+.-]//g')
                if [[ -n "$t" && -n "$c" ]]; then
                    TIMES+=("$t")
                    COMMS+=("$c")
                else
                    echo "[WARN] Missing Online time in $tmpf"
                fi
            else
                echo "[WARN] Missing Online time in $tmpf"
            fi
            rm -f "$tmpf"
        done

        if [[ ${#TIMES[@]} -eq 0 ]]; then
            echo "[ERROR] No valid Online time collected for n=$n, net=$net"
            avg_time="ERROR"
            avg_comm="ERROR"
        else
            sum_time=0
            sum_comm=0
            for t in "${TIMES[@]}"; do
                sum_time=$(awk -v a="$sum_time" -v b="$t" 'BEGIN {printf "%.10f", a+b}')
            done
            for c in "${COMMS[@]}"; do
                sum_comm=$(awk -v a="$sum_comm" -v b="$c" 'BEGIN {printf "%.10f", a+b}')
            done
            avg_time=$(awk -v s="$sum_time" -v c="${#TIMES[@]}" 'BEGIN {printf "%.10f", s/c}')
            avg_comm=$(awk -v s="$sum_comm" -v c="${#COMMS[@]}" 'BEGIN {printf "%.10f", s/c}')
        fi

        echo "$n $net $avg_time $avg_comm" >> "$OUTPUT_FILE"
        echo "Done n=$n, net=$net → avg_time=$avg_time s, avg_comm=$avg_comm MB"
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
