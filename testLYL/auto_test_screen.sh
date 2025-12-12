#!/bin/bash

# Automated Protocol Testing using Screen
# This script creates multiple screen sessions for distributed testing

set -e

# Configuration
BASE_PORT=8000
BIN_DIR="../bin"
SCREEN_SESSION_PREFIX="smash_test"

echo "=== SMASH Protocol Automated Testing (Screen) ==="
echo ""

check_screen() {
    if ! command -v screen &> /dev/null; then
        echo "ERROR: screen is not installed. Please install it first:"
        echo "  sudo apt-get install screen"
        exit 1
    fi
}

run_protocol_test() {
    local program=$1
    local num_parties=$2
    
    echo "Testing $program with $num_parties parties..."
    
    # Kill existing screen sessions
    screen -ls | grep "$SCREEN_SESSION_PREFIX" | cut -d. -f1 | xargs -r kill
    
    # Create screen sessions for each party
    party_id=1
    while [ $party_id -le $num_parties ]; do
        local session_name="${SCREEN_SESSION_PREFIX}_${program}_${party_id}"
        echo "Creating screen session: $session_name"
        
        screen -dmS $session_name bash -c "
            cd /workspace/lyl/SMASH/build/bin
            echo 'Starting $program Party $party_id...'
            ./$program $party_id $BASE_PORT $num_parties
            echo 'Party $party_id completed. Press Enter to close...'
            read
        "
        party_id=$((party_id + 1))
    done
    
    echo "All screen sessions created. Use 'screen -ls' to see sessions."
    echo "Use 'screen -r <session_name>' to attach to a session."
    echo "Example: screen -r ${SCREEN_SESSION_PREFIX}_${program}_1"
    echo ""
}

show_screen_help() {
    echo "Screen Commands:"
    echo "  screen -ls                    # List all screen sessions"
    echo "  screen -r <session_name>      # Attach to a session"
    echo "  screen -d <session_name>      # Detach from a session"
    echo "  screen -X -S <session_name> quit  # Kill a session"
    echo "  pkill screen                  # Kill all screen sessions"
    echo ""
}

case $1 in
    test)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 test <program> <num_parties>"
            echo "Example: $0 test test_A2L_spdz2k 4"
            exit 1
        fi
        check_screen
        run_protocol_test $2 $3
        show_screen_help
        ;;
    list)
        echo "Active screen sessions:"
        screen -ls | grep "$SCREEN_SESSION_PREFIX" || echo "No active sessions"
        ;;
    kill)
        echo "Killing all test sessions..."
        screen -ls | grep "$SCREEN_SESSION_PREFIX" | cut -d. -f1 | xargs -r kill
        echo "All sessions killed."
        ;;
    *)
        echo "Usage: $0 {test <program> <num_parties>|list|kill}"
        echo ""
        echo "Examples:"
        echo "  $0 test test_A2L_spdz2k 4    # Test A2L_spdz2k with 4 parties"
        echo "  $0 list                      # List active sessions"
        echo "  $0 kill                      # Kill all sessions"
        echo ""
        echo "Available programs:"
        echo "  test_A2L_spdz2k test_A2L_mascot test_A2B_spdz2k test_A2B_mascot"
        echo "  test_B2A_spdz2k test_B2A_mascot test_L2A_spdz2k test_L2A_mascot"
        ;;
esac