#!/bin/bash
set -euo pipefail

# === 参数与路径配置 ===
PORT=999
EXEC="../bin/test_lvt_semi"
LOGDIR="./logs_semi"
SUMMARY_LOG="${LOGDIR}/lvt_semi_summary.log"

mkdir -p "${LOGDIR}"
: > "${SUMMARY_LOG}"

PARTY_COUNTS=(2)

if [ ! -f "${EXEC}" ]; then
    echo "Error: Executable not found at ${EXEC}"
    exit 1
fi

# === 主测试循环 ===
for N in "${PARTY_COUNTS[@]}"; do
    echo "========== Testing with ${N} parties ==========" | tee -a "${SUMMARY_LOG}"

    PROCS=()
    TMPLOG="${LOGDIR}/party1_n${N}.log"

    for (( i=1; i<=N; i++ )); do
        CMD="${EXEC} ${i} ${PORT} ${N}"

        if [ "${i}" -eq 1 ]; then
            echo " Launching Party 1: ${CMD}" | tee -a "${SUMMARY_LOG}"
            ${CMD} > "${TMPLOG}" 2>&1 &
        else
            ${CMD} > "${LOGDIR}/party${i}_n${N}.log" 2>&1 &
        fi
        PROCS+=($!)
    done

    # 等待所有参与方完成
    for pid in "${PROCS[@]}"; do
        wait "${pid}"
    done

    # === 提取结果 ===
    {
        echo "----- Results for N=${N} (Party 1) -----"
        grep -E "Offline time|Online time" "${TMPLOG}" || echo "⚠️ No timing info found."
        echo ""
    } >> "${SUMMARY_LOG}"
done

echo "ALL TESTS COMPLETE. Summary in ${SUMMARY_LOG}"
