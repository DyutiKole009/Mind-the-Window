#!/usr/bin/env python3

import argparse
import csv
import datetime
import json
import subprocess
import sys
import time
from pathlib import Path

# Assuming these exist in your config.py
from config import (
    BASE_DIR,
    CONFIGS,
    SERVER_IP,
    SERVER_PORT,
    TRACE_DIR,
    RESULT_DIR,
    ITERATIONS,
    PROVIDER_PATH,
    get_runtime_env,
)

def setup_directories(config_name: str, session: str, network: str):
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # Create sub-directory based on network configuration
    config_trace_dir = TRACE_DIR / date_str / session / network / config_name
    config_trace_dir.mkdir(parents=True, exist_ok=True)
    
    session_result_dir = RESULT_DIR / date_str / session / network
    session_result_dir.mkdir(parents=True, exist_ok=True)
    
    return config_trace_dir, session_result_dir

def run_experiment(args):
    session_name = args.session or datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    config_trace_dir, session_result_dir = setup_directories(args.config, session_name, args.network)
    
    client_bin = BASE_DIR / "client" / "tls_client"
    csv_path = session_result_dir / "metadata.csv"

    print(f"--- Starting Session: {session_name} | Network: {args.network} | Config: {args.config} ---")

    for i in range(1, args.iterations + 1):
        pcap_path = config_trace_dir / f"iteration_{i:04d}.pcap"
        
        # 1. Start tcpdump with -U (packet-buffered)
        tcpdump_cmd = ["sudo", "tcpdump", "-U", "-i", "any", "-w", str(pcap_path), 
                       "host", SERVER_IP, "and", "tcp", "port", str(SERVER_PORT)]
        
        tcpdump_proc = subprocess.Popen(tcpdump_cmd, stderr=subprocess.DEVNULL)
        time.sleep(1.5) # Stabilize interface
        
        # 2. Run tls_client
        client_cmd = [str(client_bin), "--host", SERVER_IP, "--port", str(SERVER_PORT), 
                      "--group", CONFIGS[args.config]["group"], "--provider-path", PROVIDER_PATH]
        
        # --- NEW LINES ADDED HERE TO GENERATE DECRYPTION KEYS FOR EACH ITERATION ---
        keylog_path = config_trace_dir / f"iteration_{i:04d}.keys"
        iteration_env = get_runtime_env().copy()
        iteration_env["SSLKEYLOGFILE"] = str(keylog_path)
        # --- END OF ADDED LINES ---

        try:
            # Modified only the env parameter to use our new iteration_env containing the keylog file path
            result = subprocess.run(client_cmd, env=iteration_env, capture_output=True, text=True, timeout=10)
            meas = json.loads(result.stdout)
        except Exception as e:
            meas = {"success": False, "stage": "execution", "error": str(e)}
        
        # 3. Graceful shutdown
        time.sleep(1.0) # Cooldown to flush buffers
        tcpdump_proc.terminate()
        tcpdump_proc.wait(timeout=5)

        # 4. Save metadata
        file_exists = csv_path.exists() and csv_path.stat().st_size > 0
        
        row_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "iteration": i, "config": args.config, "algorithm": CONFIGS[args.config]["display"],
            "network": args.network, "isp": args.isp, "success": meas.get("success", False),
            "tcp_time_ms": meas.get("tcp_time_ms", ""), "tls_time_ms": meas.get("tls_time_ms", ""),
            "total_time_ms": meas.get("total_time_ms", ""), "rtt_ms": meas.get("rtt_ms", ""),
            "cipher": meas.get("cipher", ""), "negotiated_group": meas.get("group", ""),
            "error_stage": meas.get("stage", "") if not meas.get("success") else "",
            "total_packets": "", "tcp_segments": "", "retransmissions": "", 
            "handshake_bytes": "", "handshake_flights": "",
            "pcap_file": pcap_path.relative_to(TRACE_DIR.parent).as_posix()
        }
        
        with open(csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=row_data.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(row_data)
        
        status = "Success" if meas.get("success") else f"Failed ({meas.get('stage')})"
        print(f"Iteration {i:04d}: {status}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("config", choices=CONFIGS.keys())
    parser.add_argument("--network", required=True)
    parser.add_argument("--isp", required=True)
    parser.add_argument("--session")
    parser.add_argument("-n", "--iterations", type=int, default=ITERATIONS)
    run_experiment(parser.parse_args())
