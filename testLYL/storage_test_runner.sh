#!/bin/bash

# LVT Storage Analysis Test Runner
# 测试不同参数配置下的存储开销

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_PORT=9000
RESULTS_DIR="storage_results"
BIN_DIR="../bin"

# Test configurations
PARTY_COUNTS=(2 4 8 16 32 64)
TABLE_SIZE_BITS=(8 10 12 14 16)
M_BITS=(8 10 12 14 16)

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_info "Checking storage analysis binary..."
    if [ ! -f "$BIN_DIR/storage_analysis" ]; then
        print_error "Storage analysis binary not found: $BIN_DIR/storage_analysis"
        print_info "Please compile the storage_analysis.cpp first"
        exit 1
    fi
    print_info "Storage analysis binary found"
}

run_single_storage_test() {
    local num_parties=$1
    local table_size_bits=$2
    local m_bits=$3
    local results_dir=$4

    print_info "Testing storage with $num_parties parties, table_size=2^$table_size_bits, m_bits=$m_bits"

    # Start all parties
    local pids=""
    for ((party_id=1; party_id<=num_parties; party_id++)); do
        print_info "Starting storage analysis for Party $party_id..."
        # Run the storage analysis in background
        $BIN_DIR/storage_analysis $party_id $BASE_PORT $num_parties $table_size_bits $m_bits > "$results_dir/storage_p${num_parties}_t${table_size_bits}_m${m_bits}_party_${party_id}.log" 2>&1 &
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
            print_error "Party failed (PID: $pid). Check log for details."
        fi
    done
}

collect_storage_results() {
    local num_parties=$1
    local table_size_bits=$2
    local m_bits=$3
    local results_dir=$4
    local summary_file=$5

    print_info "Collecting storage results..."

    echo "=== Storage Analysis: $num_parties parties, table_size=2^$table_size_bits, m_bits=$m_bits ===" >> "$summary_file"
    echo "Date: $(date)" >> "$summary_file"

    # Extract storage information from logs
    for ((party_id=1; party_id<=num_parties; party_id++)); do
        local log_file="$results_dir/storage_p${num_parties}_t${table_size_bits}_m${m_bits}_party_${party_id}.log"
        if [ -f "$log_file" ]; then
            echo "--- Party $party_id Storage Analysis ---" >> "$summary_file"
            grep -E "(Total Storage|Peak Memory|Memory Growth|LUT Shares|Encrypted LUT)" "$log_file" >> "$summary_file" || true
            echo "" >> "$summary_file"
        fi
    done
}

run_storage_sweep_test() {
    local num_parties=$1
    local current_results_dir="$RESULTS_DIR/parties_${num_parties}"

    print_header "Storage Analysis with $num_parties parties"

    # Create results directory
    mkdir -p "$current_results_dir"

    # Test different table sizes and m_bits combinations
    for table_size_bits in "${TABLE_SIZE_BITS[@]}"; do
        for m_bits in "${M_BITS[@]}"; do
            # Skip invalid combinations
            if [ "$table_size_bits" -gt "$m_bits" ]; then
                print_warning "Skipping invalid combination: table_size_bits=$table_size_bits > m_bits=$m_bits"
                continue
            fi
            
            run_single_storage_test "$num_parties" "$table_size_bits" "$m_bits" "$current_results_dir"
            sleep 2 # Wait between tests
        done
    done

    # Collect results
    local summary_file="$current_results_dir/storage_summary.txt"
    > "$summary_file" # Clear previous summary

    for table_size_bits in "${TABLE_SIZE_BITS[@]}"; do
        for m_bits in "${M_BITS[@]}"; do
            if [ "$table_size_bits" -le "$m_bits" ]; then
                collect_storage_results "$num_parties" "$table_size_bits" "$m_bits" "$current_results_dir" "$summary_file"
            fi
        done
    done

    print_info "Completed storage analysis with $num_parties parties. Results in $current_results_dir"
}

run_all_storage_tests() {
    print_header "Running All Storage Analysis Tests"
    check_dependencies

    for num_parties in "${PARTY_COUNTS[@]}"; do
        run_storage_sweep_test "$num_parties"
        echo ""
        sleep 5 # Wait between different party counts
    done

    print_info "All storage analysis tests completed."
}

show_storage_results() {
    print_header "Storage Analysis Results Summary"

    if [ ! -d "$RESULTS_DIR" ]; then
        print_warning "No results directory found."
        return
    fi

    for num_parties in "${PARTY_COUNTS[@]}"; do
        local current_results_dir="$RESULTS_DIR/parties_${num_parties}"
        local summary_file="$current_results_dir/storage_summary.txt"

        if [ -f "$summary_file" ]; then
            echo -e "${GREEN}=== $num_parties Parties Storage Results ===${NC}"
            cat "$summary_file"
            echo ""
        else
            print_warning "No storage results found for $num_parties parties in $current_results_dir"
        fi
    done
}

generate_storage_report() {
    print_header "Generating Storage Analysis Report"
    
    local report_file="$RESULTS_DIR/storage_analysis_report.txt"
    > "$report_file"
    
    echo "LVT Protocol Storage Analysis Report" >> "$report_file"
    echo "Generated on: $(date)" >> "$report_file"
    echo "================================================" >> "$report_file"
    echo "" >> "$report_file"
    
    # Collect data from all CSV files
    for num_parties in "${PARTY_COUNTS[@]}"; do
        local current_results_dir="$RESULTS_DIR/parties_${num_parties}"
        local csv_file="$current_results_dir/storage_analysis_results.csv"
        
        if [ -f "$csv_file" ]; then
            echo "Storage Analysis for $num_parties Parties:" >> "$report_file"
            echo "----------------------------------------" >> "$report_file"
            cat "$csv_file" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done
    
    print_info "Storage analysis report generated: $report_file"
}

main() {
    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 {test-all|test <num>|results|report}"
        echo "  test-all: Run all storage tests for all party counts"
        echo "  test <num>: Run storage tests for specific party count"
        echo "  results: Show storage results summary"
        echo "  report: Generate comprehensive storage analysis report"
        exit 1
    fi

    case "$1" in
        test-all)
            run_all_storage_tests
            ;;
        test)
            if [ -z "$2" ]; then
                print_error "Please specify number of parties for 'test' command."
                exit 1
            fi
            check_dependencies
            run_storage_sweep_test "$2"
            ;;
        results)
            show_storage_results
            ;;
        report)
            generate_storage_report
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Usage: $0 {test-all|test <num>|results|report}"
            exit 1
            ;;
    esac
}

# Run main function
main "$@" 