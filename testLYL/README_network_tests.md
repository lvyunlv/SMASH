 # SMASH LVT Network Testing Guide

This guide explains how to run the SMASH LVT (Lookup Table) tests under different network conditions to evaluate performance across various network environments.

## Network Environments

The testing framework supports three network environments:

1. **Local Setting**: 
   - Bandwidth: Up to 10 Gbps
   - Latency: 0.1 ms
   - Use case: Same machine testing

2. **LAN Setting**: 
   - Bandwidth: Up to 1 Gbps
   - Latency: 0.1 ms
   - Use case: Local area network testing

3. **WAN Setting**: 
   - Bandwidth: Up to 200 Mbps
   - Latency: 100 ms
   - Use case: Wide area network testing

## Prerequisites

1. **System Requirements**:
   - Linux system with `tc` (traffic control) support
   - Sudo privileges for network simulation
   - Compiled SMASH LVT binary

2. **Dependencies**:
   ```bash
   # Install iproute2 for traffic control
   sudo apt-get install iproute2
   
   # Ensure you have sudo privileges
   sudo -v
   ```

## Quick Start

### 1. Generate Network Configurations

```bash
# Generate configs for 3 parties (default)
./run_network_tests.sh generate

# Generate configs for 4 parties
./run_network_tests.sh -p 4 generate
```

### 2. Run Tests

#### Test All Environments
```bash
# Run tests for all environments with 3 parties
./run_network_tests.sh test-all

# Run tests for all environments with 4 parties
./run_network_tests.sh -p 4 test-all
```

#### Test Specific Environment
```bash
# Test LAN environment
./run_network_tests.sh test lan

# Test WAN environment with 4 parties
./run_network_tests.sh -p 4 test wan

# Test local environment
./run_network_tests.sh test local
```

### 3. View Results

```bash
# Show all test results
./run_network_tests.sh results
```

## Manual Network Configuration

If you want to run tests across multiple machines, you need to modify the network configuration files:

### 1. Edit Network Files

For each environment, edit the corresponding network file in `network_configs/`:

```bash
# Example for LAN environment with 3 machines
cat > network_configs/lan_network.txt << EOF
192.168.1.10 8000
192.168.1.11 8001
192.168.1.12 8002
EOF
```

### 2. Run Tests on Each Machine

On each machine, run:

```bash
# Machine 1 (Party 1)
./lvt 1 8000 3 network_configs/lan_network.txt

# Machine 2 (Party 2) 
./lvt 2 8001 3 network_configs/lan_network.txt

# Machine 3 (Party 3)
./lvt 3 8002 3 network_configs/lan_network.txt
```

## Network Simulation Details

The testing framework uses Linux Traffic Control (`tc`) to simulate different network conditions:

### Local Environment
- No network simulation applied
- Uses loopback interface (127.0.0.1)
- Maximum performance baseline

### LAN Environment
```bash
# Applied network rules:
sudo tc qdisc add dev lo root handle 1:0 netem delay 0.1ms rate 1gbit
```

### WAN Environment
```bash
# Applied network rules:
sudo tc qdisc add dev lo root handle 1:0 netem delay 100ms rate 200mbit
```

## Output Files

Test results are stored in the `test_results/` directory:

```
test_results/
├── local_results.txt
├── lan_results.txt
├── wan_results.txt
├── party_1_local.log
├── party_2_local.log
├── party_3_local.log
└── ...
```

### Result Format

Each result file contains:
- Test environment configuration
- Timing information (Offline/Online time)
- Communication overhead
- Party-specific logs

Example output:
```
=== lan Network Test Results ===
Date: Mon Aug 5 15:30:00 UTC 2024
Environment: lan
Network Config: 1Gbps 0.1ms
Number of Parties: 3

--- Party 1 Log ---
Offline time: 2.5 s, comm: 15.2 MB
Online time: 0.8 s, comm: 3.1 MB
```

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   ```bash
   # Ensure sudo privileges
   sudo -v
   ```

2. **tc command not found**:
   ```bash
   # Install iproute2
   sudo apt-get install iproute2
   ```

3. **Port already in use**:
   ```bash
   # Check for running processes
   netstat -tulpn | grep :8000
   
   # Kill existing processes
   pkill -f lvt
   ```

4. **Network simulation not working**:
   ```bash
   # Check current tc rules
   sudo tc qdisc show dev lo
   
   # Clear all rules
   sudo tc qdisc del dev lo root
   ```

### Debug Mode

To run with verbose output:

```bash
# Enable debug output
export DEBUG=1
./run_network_tests.sh test lan
```

## Performance Analysis

### Key Metrics

1. **Offline Time**: Time for key generation and share generation
2. **Online Time**: Time for actual lookup operations
3. **Communication**: Total data transferred between parties

### Expected Results

- **Local**: Fastest performance, minimal network overhead
- **LAN**: Moderate performance degradation due to bandwidth limits
- **WAN**: Significant performance impact due to high latency and low bandwidth

### Optimization Tips

1. **For WAN testing**: Consider reducing the number of parties or input size
2. **For LAN testing**: Optimize for bandwidth utilization
3. **For Local testing**: Focus on CPU-bound optimizations

## Advanced Configuration

### Custom Network Parameters

You can modify the network simulation parameters in `run_network_tests.sh`:

```bash
# Edit the NETWORK_CONFIGS array
declare -A NETWORK_CONFIGS=(
    ["custom"]="500Mbps 50ms"
)
```

### Multi-Machine Setup

For distributed testing across multiple machines:

1. **Synchronize time**:
   ```bash
   sudo ntpdate pool.ntp.org
   ```

2. **Configure firewall**:
   ```bash
   sudo ufw allow 8000:8010/tcp
   ```

3. **Use SSH for coordination**:
   ```bash
   # Create a coordination script
   for host in host1 host2 host3; do
       ssh $host "cd /path/to/smash && ./lvt $PARTY_ID $PORT $NUM_PARTIES $NETWORK_FILE"
   done
   ```

## Contributing

To add new network environments or modify testing parameters:

1. Edit `run_network_tests.sh`
2. Update the `NETWORK_CONFIGS` array
3. Test with your new configuration
4. Update this documentation

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the log files in `test_results/`
3. Ensure all prerequisites are met
4. Contact the development team