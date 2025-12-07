#!/bin/bash

# Simple LVT Storage Analysis Test Runner
# 简化的存储开销测试脚本

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_PORT=9000
BIN_DIR="../bin"

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_storage_test() {
    local num_parties=$1
    local table_size_bits=$2
    local m_bits=$3

    print_info "Testing storage with $num_parties parties, table_size=2^$table_size_bits, m_bits=$m_bits"

    # Start all parties
    local pids=""
    for ((party_id=1; party_id<=num_parties; party_id++)); do
        print_info "Starting storage analysis for Party $party_id..."
        # Run the storage analysis in background
        $BIN_DIR/simple_storage_analysis $party_id $BASE_PORT $num_parties $table_size_bits $m_bits &
        pids="$pids $!"
        sleep 0.5 # Small delay to ensure proper startup
    done

    # Wait for all parties to complete
    print_info "Waiting for all parties to complete..."
    for pid in $pids; do
        wait $pid
        if [ $? -eq 0 ]; then
            print_info "Party completed successfully (PID: $pid)"
        else
            print_error "Party failed (PID: $pid)"
        fi
    done
}

main() {
    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 <num_parties> [table_size_bits] [m_bits]"
        echo "Example: $0 2 24 24"
        exit 1
    fi

    local num_parties=$1
    local table_size_bits=${2:-24}  # 默认改为24
    local m_bits=${3:-24}           # 默认改为24

    print_header "Simple LVT Storage Analysis"
    print_info "Testing with $num_parties parties, table_size=2^$table_size_bits, m_bits=$m_bits"

    # Check if binary exists
    if [ ! -f "$BIN_DIR/simple_storage_analysis" ]; then
        print_error "Binary not found: $BIN_DIR/simple_storage_analysis"
        print_info "Please compile it first: make simple_storage_analysis"
        exit 1
    fi

    # Run the test
    run_storage_test "$num_parties" "$table_size_bits" "$m_bits"

    print_info "Storage analysis completed!"
    print_info "Results saved in: simple_storage_results.csv"
}

# Run main function
main "$@" 