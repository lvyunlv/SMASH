#!/bin/bash

# Network Test Runner for SMASH LVT
# Supports Local, LAN, and WAN network environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NUM_PARTIES=2  # Default to 3 parties
BASE_PORT=7000
CONFIG_DIR="network_configs"
RESULTS_DIR="B2A_spdz2k_2"
LVT_BINARY="../bin/test_B2A_spdz2k"  # Path to the LVT binary

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
    print_info "Checking dependencies..."
    
    # Check if tc (traffic control) is available
    if ! command -v tc &> /dev/null; then
        print_error "tc (traffic control) not found. Please install iproute2"
        exit 1
    fi
    
    # Check if the LVT binary exists
    if [ ! -f "$LVT_BINARY" ]; then
        print_error "LVT binary not found at $LVT_BINARY. Please compile the project first"
        exit 1
    fi
    
    print_info "Dependencies check passed"
}

setup_network_simulation() {
    local env_name=$1
    local interface=${2:-"lo"}
    
    print_info "Setting up network simulation for $env_name environment"
    
    # Remove existing traffic control rules
    sudo tc qdisc del dev $interface root 2>/dev/null || true
    
    case $env_name in
        "local")
            print_info "Local environment - no network simulation needed"
            ;;
        "lan")
            print_info "LAN environment - 1Gbps bandwidth, 0.1ms latency"
            sudo tc qdisc add dev $interface root handle 1:0 netem delay 0.1ms rate 1gbit
            ;;
        "wan")
            print_info "WAN environment - 200Mbps bandwidth, 100ms latency"
            sudo tc qdisc add dev $interface root handle 1:0 netem delay 100ms rate 200mbit
            ;;
        *)
            print_error "Unknown environment: $env_name"
            return 1
            ;;
    esac
}

cleanup_network_simulation() {
    local interface=${1:-"lo"}
    print_info "Cleaning up network simulation"
    sudo tc qdisc del dev $interface root 2>/dev/null || true
}

generate_network_configs() {
    print_info "Generating network configuration files"
    
    mkdir -p $CONFIG_DIR
    
    # Generate configs for each environment
    for env_name in local lan wan; do
        local network_file="$CONFIG_DIR/${env_name}_network.txt"
        
        print_info "Creating $network_file"
        > $network_file
        
        i=0
        while [ $i -lt $NUM_PARTIES ]; do
            echo "127.0.0.1 $((BASE_PORT + i))" >> $network_file
            i=$((i + 1))
        done
        
        print_info "Generated $network_file"
    done
}

run_single_test() {
    local env_name=$1
    local network_file="$CONFIG_DIR/${env_name}_network.txt"
    local results_file="$RESULTS_DIR/${env_name}_results.txt"
    
    print_header "Running $env_name Network Test"
    print_info "Network file: $network_file"
    print_info "Results file: $results_file"
    print_info "Using binary: $LVT_BINARY"
    
    # Setup network simulation
    setup_network_simulation $env_name
    
    # Create results directory
    mkdir -p $RESULTS_DIR
    
    # Start all parties
    local pids=""
    party_id=1
    while [ $party_id -le $NUM_PARTIES ]; do
        print_info "Starting Party $party_id"
        
        # Run the party in background
        $LVT_BINARY $party_id $BASE_PORT $NUM_PARTIES $network_file > "$RESULTS_DIR/party_${party_id}_${env_name}.log" 2>&1 &
        pids="$pids $!"
        
        # Small delay to ensure proper startup
        sleep 0.5
        party_id=$((party_id + 1))
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
    
    # Cleanup network simulation
    cleanup_network_simulation
    
    # Collect results
    collect_results $env_name $results_file
    
    print_info "$env_name test completed"
}

run_sweep_tests() {
    local sweep_parties="2"
    for n in $sweep_parties; do
        print_header "Sweep Test: $n Parties"
        NUM_PARTIES=$n
        CONFIG_DIR="network_configs_$n"
        RESULTS_DIR="test_results_$n"
        generate_network_configs
        run_all_tests
    done
    print_info "Sweep test completed. Results in test_results_* directories."
}

collect_results() {
    local env_name=$1
    local results_file=$2
    
    print_info "Collecting results for $env_name"
    
    echo "=== $env_name Network Test Results ===" > $results_file
    echo "Date: $(date)" >> $results_file
    echo "Environment: $env_name" >> $results_file
    echo "Number of Parties: $NUM_PARTIES" >> $results_file
    echo "" >> $results_file
    
    # Extract timing information from logs
    party_id=1
    while [ $party_id -le $NUM_PARTIES ]; do
        local log_file="$RESULTS_DIR/party_${party_id}_${env_name}.log"
        if [ -f "$log_file" ]; then
            echo "--- Party $party_id Log ---" >> $results_file
            grep -E "(Offline time|Online time|comm:)" "$log_file" >> $results_file || true
            echo "" >> $results_file
        fi
        party_id=$((party_id + 1))
    done
}

run_all_tests() {
    print_header "Running All Network Tests"
    
    for env_name in local lan wan; do
        run_single_test $env_name
        echo ""
        sleep 2  # Wait between tests
    done
}

show_results() {
    print_header "Test Results Summary"
    
    if [ ! -d "$RESULTS_DIR" ]; then
        print_warning "No results directory found"
        return
    fi
    
    for env_name in local lan wan; do
        local results_file="$RESULTS_DIR/${env_name}_results.txt"
        if [ -f "$results_file" ]; then
            echo -e "${GREEN}=== $env_name Results ===${NC}"
            cat "$results_file"
            echo ""
        else
            print_warning "No results file found for $env_name"
        fi
    done
}

usage() {
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Options:"
    echo "  -p NUM              Number of parties (default: 3)"
    echo "  -h                  Show this help message"
    echo ""
    echo "Commands:"
    echo "  generate            Generate network configuration files"
    echo "  test ENV            Run test for specific environment (local/lan/wan)"
    echo "  test-all            Run tests for all environments"
    echo "  results             Show test results"
    echo ""
    echo "Examples:"
    echo "  $0 generate                    # Generate configs for 3 parties"
    echo "  $0 -p 4 test lan               # Test LAN environment with 4 parties"
    echo "  $0 test-all                    # Test all environments"
    echo "  $0 results                     # Show results"
}

main() {
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case $1 in
            -p)
                NUM_PARTIES="$2"
                shift 2
                ;;
            -h)
                usage
                exit 0
                ;;
            generate)
                check_dependencies
                generate_network_configs
                exit 0
                ;;
            test)
                if [ -z "$2" ]; then
                    print_error "Please specify environment (local/lan/wan)"
                    exit 1
                fi
                check_dependencies
                generate_network_configs
                run_single_test "$2"
                exit 0
                ;;
            test-all)
                check_dependencies
                generate_network_configs
                run_all_tests
                exit 0
                ;;
            test-sweep)
                check_dependencies
                run_sweep_tests
                exit 0
                ;;
            results)
                show_results
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Default action
    usage
}

# Run main function
main "$@"