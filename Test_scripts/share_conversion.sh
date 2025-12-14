#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
mkdir -p "$RESULTS_DIR"
./test_gen_File
TESTS=(
    # "test_L2A_mascot"
    # "test_A2L_mascot"
    # "test_L2A_spdz2k"
    # "test_A2L_spdz2k"
    # "test_B2A_mascot"
    # "test_B2A_spdz2k"
    # "test_A2B_mascot"
    "test_A2B_spdz2k"
)

NS=(32)
NETS=("wan")
BASE_PORT=62983

parse_value() {
    echo "$1" | sed -E "s/.*$2: ([0-9\.]+).*/\1/"
}

run_one_test() {
    local test_name=$1
    local n=$2
    local net=$3
    local port=$4
    local result_file=$5
    
    echo "======== Running $test_name, n=$n, net=$net ========"
    
    PIDS=()
    TMP_FILES=()
    
    for ((p=1; p<=n; p++)); do
        TMP_FILE=$(mktemp)
        TMP_FILES+=("$TMP_FILE")
        echo "Start $test_name party $p..."
        "$BIN_DIR/$test_name" "$p" "$port" "$n" "$net" > "$TMP_FILE" 2>&1 &
        PIDS+=($!)
        sleep 0.15
    done
    
    for pid in "${PIDS[@]}"; do
        wait $pid
    done
    
    total_off_comm=0
    total_off_time=0
    total_on_comm=0
    total_on_time=0
    count=0
    
    for TMP in "${TMP_FILES[@]}"; do
        offline_line=$(grep "Offline Communication" "$TMP")
        online_line=$(grep "Online Communication" "$TMP")
        
        off_comm=$(parse_value "$offline_line" "Offline Communication")
        off_time=$(parse_value "$offline_line" "Offline Time")
        on_comm=$(parse_value "$online_line" "Online Communication")
        on_time=$(parse_value "$online_line" "Online Time")
        
        if [[ -n "$off_comm" ]]; then
            total_off_comm=$(awk "BEGIN {print $total_off_comm + $off_comm}")
            total_off_time=$(awk "BEGIN {print $total_off_time + $off_time}")
            total_on_comm=$(awk "BEGIN {print $total_on_comm + $on_comm}")
            total_on_time=$(awk "BEGIN {print $total_on_time + $on_time}")
            count=$((count+1))
        fi
        
        rm -f "$TMP"
    done
    
    if [[ $count -gt 0 ]]; then
        avg_off_comm=$(awk "BEGIN {printf \"%.6f\", $total_off_comm / $count}")
        avg_off_time=$(awk "BEGIN {printf \"%.6f\", $total_off_time / $count}")
        avg_on_comm=$(awk "BEGIN {printf \"%.6f\", $total_on_comm / $count}")
        avg_on_time=$(awk "BEGIN {printf \"%.6f\", $total_on_time / $count}")
        
        echo "$n,$net,$avg_off_comm,$avg_off_time,$avg_on_comm,$avg_on_time" >> "$result_file"
        echo "==> $test_name finished: offline ${avg_off_time}ms, online ${avg_on_time}ms"
    else
        echo "==> $test_name: No valid data collected"
    fi
}

for test_bin in "${TESTS[@]}"; do
    RESULT_FILE="$RESULTS_DIR/${test_bin}_results.txt"
    echo "num_party,network,avg_offline_comm_KB,avg_offline_time_ms,avg_online_comm_KB,avg_online_time_ms" \
        > "$RESULT_FILE"
    
    echo "======= Testing $test_bin ======="
    for n in "${NS[@]}"; do
        for net in "${NETS[@]}"; do
            PORT=$((BASE_PORT + RANDOM % 5000 + n * 80))
            run_one_test "$test_bin" "$n" "$net" "$PORT" "$RESULT_FILE"
        done
    done
    echo "Results saved → $RESULT_FILE"
done

echo "================ ALL TESTS FINISHED ================"