#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

rm -rf "$BASE_DIR/build/cache"
"$BASE_DIR/build/bin/test_gen_File"

BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_DIR="$BASE_DIR/Input"

mkdir -p "$RESULTS_DIR"
mkdir -p "$INPUT_DIR"

INPUT_FILE="$INPUT_DIR/Input-P.txt"

echo "[INFO] Generating input file..."
: > "$INPUT_FILE"
echo $((RANDOM % 11)) >> "$INPUT_FILE"

TEST_NAME="test_lvt"

NS=(32 16 8 4 2)
NETS=("local" "lan" "wan")

BASE_PORT=7222

parse_value() {
    echo "$1" | sed -E "s/.*$2: ([0-9eE\.+-]+).*/\1/"
}

run_one_test() {
    local n=$1
    local net=$2
    local port=$3
    local result_file=$4

    echo "======== Running $TEST_NAME | n=$n | net=$net ========"

    PIDS=()
    TMP_FILES=()

    ERR_DIR="$RESULTS_DIR/error_logs"
    mkdir -p "$ERR_DIR"

    for ((p=1; p<=n; p++)); do
        TMP_FILE=$(mktemp)
        TMP_FILES+=("$TMP_FILE")

        if [[ $p -eq 1 ]]; then
            TS=$(date +"%Y%m%d_%H%M%S")
            ERR_FILE="$ERR_DIR/${TEST_NAME}_n${n}_${net}_party${p}_${TS}.err"
            echo "[INFO] Start party $p (logging stderr)"
            echo "[INFO] stderr → $ERR_FILE"

            "$BIN_DIR/$TEST_NAME" "$p" "$port" "$n" "$net" \
                > "$TMP_FILE" 2> "$ERR_FILE" &
        else
            echo "[INFO] Start party $p"
            "$BIN_DIR/$TEST_NAME" "$p" "$port" "$n" "$net" \
                > "$TMP_FILE" 2> /dev/null &
        fi

        PIDS+=($!)
        sleep 0.2
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
        offline_line=$(grep "Offline time" "$TMP")
        online_line=$(grep "Online time" "$TMP")

        off_time=$(parse_value "$offline_line" "Offline time")
        off_comm=$(parse_value "$offline_line" "comm")
        on_time=$(parse_value "$online_line" "Online time")
        on_comm=$(parse_value "$online_line" "comm")

        if [[ -n "$off_time" && -n "$off_comm" ]]; then
            total_off_time=$(awk "BEGIN {print $total_off_time + $off_time}")
            total_off_comm=$(awk "BEGIN {print $total_off_comm + $off_comm}")
            total_on_time=$(awk "BEGIN {print $total_on_time + $on_time}")
            total_on_comm=$(awk "BEGIN {print $total_on_comm + $on_comm}")
            count=$((count+1))
        fi

        rm -f "$TMP"
    done

    if [[ $count -gt 0 ]]; then
        avg_off_time=$(awk "BEGIN {printf \"%.6f\", $total_off_time / $count}")
        avg_off_comm=$(awk "BEGIN {printf \"%.6f\", $total_off_comm / $count}")
        avg_on_time=$(awk "BEGIN {printf \"%.6f\", $total_on_time / $count}")
        avg_on_comm=$(awk "BEGIN {printf \"%.6f\", $total_on_comm / $count}")

        echo "$n,$net,$avg_off_time,$avg_off_comm,$avg_on_time,$avg_on_comm" \
            >> "$result_file"

        echo "==> Done: offline ${avg_off_time}s, online ${avg_on_time}s"
    else
        echo "[WARN] No valid data collected (check error_logs/)"
    fi

    sleep 1
}

RESULT_FILE="$RESULTS_DIR/total_1server.txt"
echo "num_party,network,avg_offline_time_s,avg_offline_comm_MB,avg_online_time_s,avg_online_comm_MB" \
    > "$RESULT_FILE"

for n in "${NS[@]}"; do
    for net in "${NETS[@]}"; do
        PORT=$((BASE_PORT + n * 100))
        run_one_test "$n" "$net" "$PORT" "$RESULT_FILE"
    done
done

echo "================ ALL TESTS FINISHED ================"
echo "Results saved → $RESULT_FILE"
echo "Error logs saved → $RESULTS_DIR/error_logs/"
