#!/bin/bash

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$BASE_DIR/build/bin"
RESULTS_DIR="$BASE_DIR/Results"
INPUT_DIR="$BASE_DIR/Input"
INPUT_FILE="$INPUT_DIR/Input-P.txt"
OUTPUT_FILE="$RESULTS_DIR/qwen_nonlinear_malicious.txt"
LOG_DIR="$RESULTS_DIR/logs_online"

mkdir -p "$INPUT_DIR"
mkdir -p "$RESULTS_DIR"
mkdir -p "$LOG_DIR"

echo "token,function,dimension,size,n,network,avg_time(s),avg_comm(MB)" > "$OUTPUT_FILE"

TS=(2 4 8 16 32 64 128 256 512 1024 2048)
NS=(2)
NETS=("wan")
BASE_PORT=9887

for t in "${TS[@]}"; do

    declare -A FUNC_DIM_SIZE
    FUNC_DIM_SIZE["sin"]="[$t,128]=$((128*t))"
    FUNC_DIM_SIZE["cos"]="[$t,128]=$((128*t))"
    FUNC_DIM_SIZE["RMSNorm_scalar"]="[$t,1]=$t"
    FUNC_DIM_SIZE["RMSNorm_group8"]="[$t,8]=$((8*t))"
    FUNC_DIM_SIZE["RMSNorm_group16"]="[$t,16]=$((16*t))"
    FUNC_DIM_SIZE["SiLU"]="[$t,3072]=$((3072*t))"
    FUNC_DIM_SIZE["softmax"]="[16,$t,$t]=$((16*t*t))"

    for func in "${!FUNC_DIM_SIZE[@]}"; do

        dim_size_str=${FUNC_DIM_SIZE[$func]}
        dim=$(echo "$dim_size_str" | cut -d'=' -f1)
        size=$(echo "$dim_size_str" | cut -d'=' -f2)

        echo "[Generate Input] t=$t, function=$func, dimension=$dim, size=$size"

        TMP_INPUT="$INPUT_FILE.tmp"
        : > "$TMP_INPUT"
        for ((k=1;k<=size;k++)); do
            echo $(( RANDOM % 11 )) >> "$TMP_INPUT"
        done
        mv "$TMP_INPUT" "$INPUT_FILE"

        for n in "${NS[@]}"; do
            for net in "${NETS[@]}"; do

                PORT=$((BASE_PORT + RANDOM % 5000))
                echo "Running t=$t, func=$func, n=$n, network=$net ..."

                TIMES=()
                COMMS=()
                PIDS=()

                for ((i=1;i<=n;i++)); do
                    LOG_FILE="$LOG_DIR/qwen_nonlinear_malicious_${func}_t${t}_n${n}_net${net}_party${i}.log"

                    "$BIN_DIR/test_lvt_online" "$i" "$PORT" "$n" "$net" \
                        > "$LOG_FILE" 2>&1 &

                    PIDS+=($!)
                done

                for pid in "${PIDS[@]}"; do
                    wait "$pid"
                done

                for ((i=1;i<=n;i++)); do
                    LOG_FILE="$LOG_DIR/qwen_nonlinear_malicious_${func}_t${t}_n${n}_net${net}_party${i}.log"
                    [[ ! -f "$LOG_FILE" ]] && continue

                    time_val=$(awk '/Online[[:space:]]+time/ { for(i=1;i<=NF;i++) if($i=="time:"){print $(i+1); exit} }' "$LOG_FILE")
                    comm_val=$(awk '/Online[[:space:]]+time/ { for(i=1;i<=NF;i++) if($i=="comm:"){print $(i+1); exit} }' "$LOG_FILE")

                    time_val=$(echo "$time_val" | sed -E 's/[^0-9eE+.-]//g')
                    comm_val=$(echo "$comm_val" | sed -E 's/[^0-9eE+.-]//g')

                    [[ -n "$time_val" && -n "$comm_val" ]] && TIMES+=("$time_val") && COMMS+=("$comm_val")
                done

                if [[ ${#TIMES[@]} -eq 0 ]]; then
                    echo "$t,$func,$dim,$size,$n,$net,ERROR,ERROR" >> "$OUTPUT_FILE"
                    continue
                fi

                sum_time=0
                sum_comm=0
                for tval in "${TIMES[@]}"; do
                    sum_time=$(awk -v a="$sum_time" -v b="$tval" 'BEGIN {printf "%.12f", a+b}')
                done
                for cval in "${COMMS[@]}"; do
                    sum_comm=$(awk -v a="$sum_comm" -v b="$cval" 'BEGIN {printf "%.12f", a+b}')
                done

                avg_time=$(awk -v s="$sum_time" -v c="${#TIMES[@]}" 'BEGIN {printf "%.12f", s/c}')
                avg_comm=$(awk -v s="$sum_comm" -v c="${#COMMS[@]}" 'BEGIN {printf "%.12f", s/c}')

                echo "$t,$func,$dim,$size,$n,$net,$avg_time,$avg_comm" >> "$OUTPUT_FILE"
                echo "Done t=$t, func=$func -> avg_time=$avg_time s, avg_comm=$avg_comm MB"
            done
        done
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
