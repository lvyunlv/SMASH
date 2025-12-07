#!/bin/bash
# 文件路径: /workspace/lyl/SMASH/run_lvt_experiment.sh

BASE_DIR="/workspace/lyl/SMASH"
BIN_DIR="$BASE_DIR/bin"
RESULTS_DIR="$BASE_DIR/Results"
OUTPUT_FILE="$RESULTS_DIR/online_10k.txt"

# 创建结果目录
mkdir -p "$RESULTS_DIR"
echo "n condition avg_time(s) avg_comm(MB)" > "$OUTPUT_FILE"

# 定义参与方数和网络条件
NS=(2 4 8 16 32)
NETS=("local" "lan" "wan")

# 遍历每种n和网络条件
for n in "${NS[@]}"; do
    for net in "${NETS[@]}"; do
        echo "Running n=$n, network=$net ..."
        
        TIMES=()
        COMMS=()

        # 启动n个进程，使用端口从2222开始递增
        PIDS=()
        TMP_FILES=()
        for ((i=1;i<=n;i++)); do
            TMP_FILE=$(mktemp)
            TMP_FILES+=("$TMP_FILE")
            "$BIN_DIR/test_lvt" "$i" $((2222)) "$n" "$net" > "$TMP_FILE" 2>&1 &
            PIDS+=($!)
        done

        # 等待所有进程完成
        for pid in "${PIDS[@]}"; do
            wait $pid
        done

        # 提取每个进程的时间和通信
        for tmpf in "${TMP_FILES[@]}"; do
            # 匹配 "Online time: 1.12127 s, comm: 2.28884 MB"
            line=$(grep "Online time" "$tmpf")
            if [[ $line =~ Online\ time:\ ([0-9.]+)\ s,\ comm:\ ([0-9.]+)\ MB ]]; then
                TIMES+=("${BASH_REMATCH[1]}")
                COMMS+=("${BASH_REMATCH[2]}")
            fi
            rm -f "$tmpf"
        done

        # 计算平均值
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

        # 写入结果文件
        echo "$n $net $avg_time $avg_comm" >> "$OUTPUT_FILE"
        echo "Done n=$n, network=$net -> avg_time=$avg_time s, avg_comm=$avg_comm MB"
    done
done

echo "All experiments finished. Results saved to $OUTPUT_FILE"
