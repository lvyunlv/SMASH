 #!/usr/bin/env python3
"""
Network Test Configuration Script for SMASH LVT
Supports Local, LAN, and WAN network environments
"""

import json
import os
import sys
import subprocess
import time
from typing import Dict, List, Tuple

class NetworkConfig:
    def __init__(self):
        self.configs = {
            "local": {
                "bandwidth": "10Gbps",
                "latency": "0.1ms",
                "description": "Local setting: 10 Gbps bandwidth, 0.1 ms latency"
            },
            "lan": {
                "bandwidth": "1Gbps", 
                "latency": "0.1ms",
                "description": "LAN setting: 1 Gbps bandwidth, 0.1 ms latency"
            },
            "wan": {
                "bandwidth": "200Mbps",
                "latency": "100ms", 
                "description": "WAN setting: 200 Mbps bandwidth, 100 ms latency"
            }
        }
    
    def generate_config_files(self, num_parties: int, base_port: int = 8000):
        """Generate network configuration files for different environments"""
        configs = {}
        
        for env_name, env_config in self.configs.items():
            configs[env_name] = {
                "environment": env_name,
                "config": env_config,
                "parties": []
            }
            
            # Generate party configurations
            for i in range(num_parties):
                party_config = {
                    "party_id": i + 1,
                    "ip": "127.0.0.1",  # Will be replaced with actual IPs
                    "port": base_port + i,
                    "network_params": env_config
                }
                configs[env_name]["parties"].append(party_config)
        
        return configs
    
    def save_configs(self, configs: Dict, output_dir: str = "network_configs"):
        """Save network configurations to files"""
        os.makedirs(output_dir, exist_ok=True)
        
        for env_name, config in configs.items():
            # Save JSON config
            json_file = os.path.join(output_dir, f"{env_name}_config.json")
            with open(json_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Save network file for C++ program
            network_file = os.path.join(output_dir, f"{env_name}_network.txt")
            with open(network_file, 'w') as f:
                for party in config["parties"]:
                    f.write(f"{party['ip']} {party['port']}\n")
            
            print(f"Generated {env_name} config: {json_file}")
            print(f"Generated {env_name} network file: {network_file}")

def setup_network_simulation(env_name: str, interface: str = "lo"):
    """Setup network simulation using tc (traffic control)"""
    if env_name == "local":
        # Local: no simulation needed
        return
    
    # Remove existing rules
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", interface, "root"], 
                   stderr=subprocess.DEVNULL)
    
    if env_name == "lan":
        # LAN: 1Gbps bandwidth, 0.1ms latency
        subprocess.run([
            "sudo", "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:0",
            "netem", "delay", "0.1ms", "rate", "1gbit"
        ])
    elif env_name == "wan":
        # WAN: 200Mbps bandwidth, 100ms latency
        subprocess.run([
            "sudo", "tc", "qdisc", "add", "dev", interface, "root", "handle", "1:0", 
            "netem", "delay", "100ms", "rate", "200mbit"
        ])

def run_test(env_name: str, num_parties: int, config_dir: str = "network_configs"):
    """Run the LVT test for a specific network environment"""
    network_file = os.path.join(config_dir, f"{env_name}_network.txt")
    
    if not os.path.exists(network_file):
        print(f"Error: Network file {network_file} not found")
        return False
    
    print(f"\n=== Running {env_name.upper()} Network Test ===")
    print(f"Network file: {network_file}")
    
    # Setup network simulation
    setup_network_simulation(env_name)
    
    # Run the test for each party
    processes = []
    for party_id in range(1, num_parties + 1):
        cmd = [
            "./lvt", str(party_id), "8000", str(num_parties), network_file
        ]
        print(f"Starting Party {party_id}: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        processes.append(process)
    
    # Wait for all processes to complete
    print("Waiting for all parties to complete...")
    for i, process in enumerate(processes):
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            print(f"Party {i+1} completed successfully")
        else:
            print(f"Party {i+1} failed: {stderr.decode()}")
    
    # Cleanup network simulation
    if env_name != "local":
        subprocess.run(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"], 
                       stderr=subprocess.DEVNULL)
    
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 network_test_config.py <command> [options]")
        print("Commands:")
        print("  generate <num_parties> - Generate network config files")
        print("  test <environment> <num_parties> - Run test for specific environment")
        print("  test-all <num_parties> - Run tests for all environments")
        return
    
    command = sys.argv[1]
    config = NetworkConfig()
    
    if command == "generate":
        if len(sys.argv) < 3:
            print("Error: Please specify number of parties")
            return
        
        num_parties = int(sys.argv[2])
        configs = config.generate_config_files(num_parties)
        config.save_configs(configs)
        
    elif command == "test":
        if len(sys.argv) < 4:
            print("Error: Please specify environment and number of parties")
            return
        
        env_name = sys.argv[2]
        num_parties = int(sys.argv[3])
        
        if env_name not in config.configs:
            print(f"Error: Unknown environment '{env_name}'")
            print(f"Available environments: {list(config.configs.keys())}")
            return
        
        run_test(env_name, num_parties)
        
    elif command == "test-all":
        if len(sys.argv) < 3:
            print("Error: Please specify number of parties")
            return
        
        num_parties = int(sys.argv[2])
        
        # Generate configs first
        configs = config.generate_config_files(num_parties)
        config.save_configs(configs)
        
        # Run tests for all environments
        for env_name in config.configs.keys():
            run_test(env_name, num_parties)
            time.sleep(2)  # Wait between tests
            
    else:
        print(f"Error: Unknown command '{command}'")

if __name__ == "__main__":
    main()