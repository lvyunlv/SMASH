#!/bin/bash

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_DIR="$BASE_DIR/Input"
INPUT_FILE="$INPUT_DIR/Input-P.txt"
OUTPUT_FILE="$RESULTS_DIR/online_10k_1server.txt"
LOG_DIR="$RESULTS_DIR/logs_online"

mkdir -p "$INPUT_DIR"
mkdir -p "$RESULTS_DIR"
mkdir -p "$LOG_DIR"

echo "n network avg_time(s) avg_comm(MB)" > "$OUTPUT_FILE"
echo "[Current machine] Generating random input file: $INPUT_FILE"

NS=(2 4 8 16 32)
NETS=("local" "lan" "wan")

: > "$INPUT_FILE"
for ((k=1;k<=10000;k++)); do
    echo $(( RANDOM % 11 )) >> "$INPUT_FILE"
done

BASE_PORT=9887

for n in "${NS[@]}"; do
    for net in "${NETS[@]}"; do

        PORT=$((BASE_PORT + RANDOM % 5000))
        echo "Running n=$n, network=$net ..."

        TIMES=()
        COMMS=()
        PIDS=()

        for ((i=1;i<=n;i++)); do
            LOG_FILE="$LOG_DIR/online_n${n}_net${net}_party${i}.log"

            stdbuf -o0 "$BIN_DIR/test_lvt_online" "$i" "$PORT" "$n" "$net" > "$LOG_FILE" 2>&1 &

            PIDS+=($!)
        done

        for pid in "${PIDS[@]}"; do
            wait "$pid"
        done

        for ((i=1;i<=n;i++)); do
            LOG_FILE="$LOG_DIR/online_n${n}_net${net}_party${i}.log"

            if [[ ! -f "$LOG_FILE" ]]; then
                echo "[WARN] Missing log file $LOG_FILE"
                continue
            fi

            time_val=$(awk '
                /Online[[:space:]]+time/ {
                    for(i=1;i<=NF;i++){
                        if($i=="time:") { print $(i+1); foundt=1 }
                        if($i=="comm:") { print $(i+1); foundc=1 }
                        if(foundt && foundc) exit
                    }
                }
            ' "$LOG_FILE")

            time_val=$(awk '/Online[[:space:]]+time/ { for(i=1;i<=NF;i++) if($i=="time:"){print $(i+1); exit} }' "$LOG_FILE")
            comm_val=$(awk '/Online[[:space:]]+time/ { for(i=1;i<=NF;i++) if($i=="comm:"){print $(i+1); exit} }' "$LOG_FILE")

            time_val=$(echo "$time_val" | sed -E 's/[^0-9eE+.-]//g')
            comm_val=$(echo "$comm_val" | sed -E 's/[^0-9eE+.-]//g')

            if [[ -n "$time_val" && -n "$comm_val" ]]; then
                TIMES+=("$time_val")
                COMMS+=("$comm_val")
            else
                echo "[WARN] Missing Online time/comm in $LOG_FILE (time='$time_val' comm='$comm_val')"
            fi
        done

        if [[ ${#TIMES[@]} -eq 0 ]]; then
            echo "[ERROR] No valid Online time collected for n=$n, net=$net"
            echo "$n $net ERROR ERROR" >> "$OUTPUT_FILE"
            continue
        fi

        sum_time=0
        sum_comm=0
        for t in "${TIMES[@]}"; do
            sum_time=$(awk -v a="$sum_time" -v b="$t" 'BEGIN {printf "%.12f", a+b}')
        done
        for c in "${COMMS[@]}"; do
            sum_comm=$(awk -v a="$sum_comm" -v b="$c" 'BEGIN {printf "%.12f", a+b}')
        done

        avg_time=$(awk -v s="$sum_time" -v c="${#TIMES[@]}" 'BEGIN {printf "%.12f", s/c}')
        avg_comm=$(awk -v s="$sum_comm" -v c="${#COMMS[@]}" 'BEGIN {printf "%.12f", s/c}')

        echo "$n $net $avg_time $avg_comm" >> "$OUTPUT_FILE"
        echo "Done n=$n, net=$net -> avg_time=$avg_time s, avg_comm=$avg_comm MB"
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
