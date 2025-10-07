#!/usr/bin/env python3
"""
AI Firewall Classification System - Data Collector
===================================================
Collects network behavioral features from target hosts for firewall classification.

CAUTION: This script sends network probes. Use only on networks you own or have
explicit permission to test. Do not flood targets with excessive traffic.

Usage:
    python3 data_collector.py --targets 192.168.56.10,192.168.56.11
    python3 data_collector.py --targets-file targets.txt --output dataset.csv
    python3 data_collector.py --targets 192.168.56.10 --debug

Features collected (11 stable features):
    - L3: avg_latency, packet_loss, ttl_return, icmp_reachable
    - L4: filtered_ports_count, scan_time, syn_ack_ratio, tcp_reset_ratio
    - L7: response_time, header_modified
    - Meta: firewall_label
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any


# Feature columns in exact order (only stable features)
FEATURE_COLUMNS = [
    'timestamp', 'host', 'avg_latency', 'packet_loss', 'ttl_return', 'icmp_reachable',
    'filtered_ports_count', 'scan_time', 'syn_ack_ratio', 'tcp_reset_ratio',
    'response_time', 'header_modified', 'firewall_label'
]

# Global label mapping
LABEL_MAP = {}


def check_required_tools():
    """Check if all required external tools are installed."""
    required_tools = ['ping', 'nmap', 'curl', 'hping3']
    missing_tools = []
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"ERROR: Missing required tools: {', '.join(missing_tools)}", file=sys.stderr)
        print("\nInstallation instructions:", file=sys.stderr)
        print("  sudo apt update", file=sys.stderr)
        print(f"  sudo apt install -y {' '.join(missing_tools)}", file=sys.stderr)
        sys.exit(1)
    
    # Check if running with sudo privileges for nmap/hping3
    if os.geteuid() != 0:
        print("WARNING: Script not running as root. nmap and hping3 may require sudo.")
        print("Consider running: sudo python3 data_collector.py ...\n")


def run_command(cmd: List[str], timeout: int = 15, debug: bool = False) -> Optional[str]:
    """
    Execute a shell command and return stdout.
    Returns None if command fails or times out.
    """
    try:
        if debug:
            print(f"  Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if debug and result.returncode != 0:
            print(f"  Command failed with code {result.returncode}: {result.stderr[:200]}")
        
        return result.stdout if result.returncode == 0 else result.stdout + result.stderr
    
    except subprocess.TimeoutExpired:
        if debug:
            print(f"  Command timed out after {timeout}s")
        return None
    except Exception as e:
        if debug:
            print(f"  Command error: {e}")
        return None


def parse_ping(output: Optional[str]) -> Dict[str, Any]:
    """Parse ping output to extract avg_latency, packet_loss, ttl_return, icmp_reachable."""
    features = {'avg_latency': '', 'packet_loss': '', 'ttl_return': '', 'icmp_reachable': 0}
    
    if not output:
        return features
    
    # Check for successful reply and extract TTL
    if 'bytes from' in output.lower() or 'icmp_seq=' in output.lower():
        features['icmp_reachable'] = 1
        if ttl_match := re.search(r'ttl=(\d+)', output, re.IGNORECASE):
            features['ttl_return'] = int(ttl_match.group(1))
    
    # Extract packet loss percentage
    if loss_match := re.search(r'(\d+\.?\d*)%\s+packet loss', output, re.IGNORECASE):
        features['packet_loss'] = float(loss_match.group(1))
    
    # Extract average latency (try both formats)
    rtt_patterns = [r'rtt.*?=\s*[\d.]+/([\d.]+)/', r'round-trip.*?=\s*[\d.]+/([\d.]+)/']
    for pattern in rtt_patterns:
        if rtt_match := re.search(pattern, output, re.IGNORECASE):
            features['avg_latency'] = float(rtt_match.group(1))
            break
    
    return features


def parse_nmap(output: Optional[str]) -> Dict[str, Any]:
    """Parse nmap output to extract filtered_ports_count and scan_time."""
    features = {'filtered_ports_count': 0, 'scan_time': ''}
    
    if not output:
        return features
    
    features['filtered_ports_count'] = len(re.findall(r'\d+/tcp\s+filtered', output, re.IGNORECASE))
    
    if time_match := re.search(r'scanned in ([\d.]+) seconds', output, re.IGNORECASE):
        features['scan_time'] = float(time_match.group(1))
    
    return features


def parse_hping3(output: Optional[str], sent_count: int = 5) -> float:
    """Parse hping3 output to calculate response ratio (0.0-1.0)."""
    if not output:
        return 0.0
    
    reply_count = len(re.findall(r'flags=|len=\d+', output, re.IGNORECASE))
    if reply_count == 0:
        reply_count = len(re.findall(r'^\s*\d+\s+bytes from', output, re.MULTILINE))
    
    ratio = reply_count / sent_count if sent_count > 0 else 0.0
    return max(0.0, min(1.0, ratio))


def parse_hping3_rst(output: Optional[str], sent_count: int = 5) -> float:
    """Parse hping3 output to calculate RST ratio (0.0-1.0)."""
    if not output:
        return 0.0
    
    rst_count = len(re.findall(r'flags=.*R', output, re.IGNORECASE))
    ratio = rst_count / sent_count if sent_count > 0 else 0.0
    return max(0.0, min(1.0, ratio))


def parse_curl(output: Optional[str]) -> Dict[str, Any]:
    """Parse curl output to detect proxy/cache headers."""
    if not output:
        return {'header_modified': 0}
    
    proxy_headers = ['via:', 'x-cache:', 'x-proxy', 'proxy-agent:', 'x-forwarded']
    header_modified = any(header in output.lower() for header in proxy_headers)
    
    return {'header_modified': 1 if header_modified else 0}


def measure_curl_time(ip: str, timeout: int = 5) -> Optional[float]:
    """Measure HTTP response time in milliseconds."""
    cmd = ['curl', '-s', '-I', '-w', '%{time_total}', '-o', '/dev/null', 
           '--max-time', str(timeout), f'http://{ip}']
    
    if output := run_command(cmd, timeout=timeout + 2):
        try:
            return float(output.strip().split('\n')[-1]) * 1000
        except (ValueError, IndexError):
            pass
    return None


def collect_features(ip: str, debug: bool = False) -> Dict[str, Any]:
    """
    Collect all network features for a single target IP.
    Only collects the 11 stable features that don't vary by environment.
    """
    global LABEL_MAP
    
    print(f"[*] Collecting data from {ip}...")
    
    features = {
        'timestamp': int(time.time()),
        'host': ip
    }
    
    # Initialize all features as empty
    for col in FEATURE_COLUMNS[2:]:
        features[col] = ''
    
    # L3: ICMP - Standard ping
    print(f"  [L3] Running ping tests...")
    ping_output = run_command(['ping', '-c', '5', ip], timeout=10, debug=debug)
    features.update(parse_ping(ping_output))
    
    # L3: ICMP - Large packet ping (detect higher loss with large packets)
    ping_large_output = run_command(['ping', '-c', '5', '-s', '1400', ip], timeout=10, debug=debug)
    if ping_large_output:
        large_ping_features = parse_ping(ping_large_output)
        if large_ping_features['packet_loss'] and (
            not features['packet_loss'] or large_ping_features['packet_loss'] > features['packet_loss']
        ):
            features['packet_loss'] = large_ping_features['packet_loss']
    
    # L4: TCP - nmap port scan
    print(f"  [L4] Running nmap scan...")
    nmap_output = run_command(['nmap', '-sS', '-p', '1-1024', ip, '-oN', '-'], 
                              timeout=120, debug=debug)
    features.update(parse_nmap(nmap_output))
    
    # L4: TCP - hping3 SYN tests
    print(f"  [L4] Testing SYN/ACK ratio (port 80)...")
    hping3_80 = run_command(['hping3', '-S', '-p', '80', '-c', '5', ip], timeout=10, debug=debug)
    features['syn_ack_ratio'] = parse_hping3(hping3_80, 5)
    
    print(f"  [L4] Testing RST ratio (port 22)...")
    hping3_22 = run_command(['hping3', '-S', '-p', '22', '-c', '5', ip], timeout=10, debug=debug)
    features['tcp_reset_ratio'] = parse_hping3_rst(hping3_22, 5)
    
    # L7: HTTP - Measure response time
    print(f"  [L7] Measuring HTTP response time...")
    if response_time := measure_curl_time(ip, timeout=5):
        features['response_time'] = response_time
    
    # L7: HTTP - Detect proxy/cache headers
    print(f"  [L7] Testing header modification...")
    curl_output = run_command(['curl', '-s', '-I', '-H', 'X-AIFW-Test: 1', 
                               '--max-time', '5', f'http://{ip}'], timeout=8, debug=debug)
    if curl_output:
        features.update(parse_curl(curl_output))
    
    # Ensure header_modified has default value
    features['header_modified'] = features.get('header_modified') or 0
    
    # Auto-detect proxy by testing common proxy ports if not already detected
    if features['header_modified'] == 0:
        print(f"  [L7] Testing for proxy on common ports...")
        proxy_ports = [3128, 8080, 8888]  # Common proxy ports (Squid, HTTP proxies)
        for port in proxy_ports:
            proxy_output = run_command(['curl', '-s', '-I', '-x', f'http://{ip}:{port}', 
                                       'http://example.com', '--connect-timeout', '3'], 
                                       timeout=10, debug=debug)
            if proxy_output:
                output_lower = proxy_output.lower()
                proxy_indicators = ['via:', 'x-squid', 'cache-status:', 'x-cache', 'x-forwarded', 'squid']
                if any(indicator in output_lower for indicator in proxy_indicators):
                    features['header_modified'] = 1
                    print(f"  [L7] ✓ Proxy detected on port {port}")
                    if debug:
                        matched = [ind for ind in proxy_indicators if ind in output_lower]
                        print(f"      Indicators found: {', '.join(matched)}")
                    break
    
    # Format numeric fields with consistent decimals
    decimal_formats = {
        'avg_latency': 3, 'scan_time': 2, 'packet_loss': 2,
        'syn_ack_ratio': 3, 'tcp_reset_ratio': 3, 'response_time': 3
    }
    for field, decimals in decimal_formats.items():
        if features[field] != '':
            features[field] = round(float(features[field]), decimals)
    
    # Apply label mapping if available
    if ip in LABEL_MAP:
        features['firewall_label'] = LABEL_MAP[ip]
        if debug:
            print(f"  Applied label: {LABEL_MAP[ip]}")
    
    print(f"[✓] Completed data collection for {ip}")
    return features


def write_csv(data: List[Dict[str, Any]], output_file: str, append: bool = False):
    """Write collected features to CSV file."""
    file_exists = os.path.exists(output_file)
    mode = 'a' if append and file_exists else 'w'
    write_header = not (append and file_exists)
    
    print(f"\n[*] {'Appending' if mode == 'a' else 'Writing'} {len(data)} rows to {output_file}...")
    
    with open(output_file, mode, newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
        if write_header:
            writer.writeheader()
        
        for row in data:
            csv_row = {col: row.get(col, '') if row.get(col, '') != '' and row.get(col) is not None else '' 
                      for col in FEATURE_COLUMNS}
            writer.writerow(csv_row)
    
    print(f"[✓] Dataset saved to {output_file}")


def main():
    global LABEL_MAP
    
    parser = argparse.ArgumentParser(
        description='AI Firewall Classification System - Data Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--targets',
        type=str,
        help='Comma-separated list of target IP addresses'
    )
    
    parser.add_argument(
        '--targets-file',
        type=str,
        help='File containing target IPs, one per line'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='dataset.csv',
        help='Output CSV file (default: dataset.csv)'
    )
    
    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel workers (default: 1, sequential)'
    )
    
    parser.add_argument(
        '--repeat',
        type=int,
        default=1,
        help='Number of times to repeat data collection for each target (default: 1)'
    )
    
    parser.add_argument(
        '--label-map',
        type=str,
        help='Comma-separated IP to label mapping (e.g., "192.168.56.10=0,192.168.56.11=1")'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug output'
    )
    
    args = parser.parse_args()
    
    # Parse label mapping
    if args.label_map:
        LABEL_MAP = {ip.strip(): int(label.strip()) 
                    for mapping in args.label_map.split(',') 
                    if '=' in mapping 
                    for ip, label in [mapping.split('=', 1)]}
        print(f"Loaded label mappings: {LABEL_MAP}\n")
    
    # Parse target IPs
    targets = []
    if args.targets:
        targets = [ip.strip() for ip in args.targets.split(',')]
    elif args.targets_file:
        if not os.path.exists(args.targets_file):
            print(f"ERROR: File not found: {args.targets_file}", file=sys.stderr)
            sys.exit(1)
        with open(args.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)
    
    if not targets:
        print("ERROR: No target IPs provided", file=sys.stderr)
        sys.exit(1)
    
    separator = "=" * 70
    print(f"\n{separator}")
    print("AI Firewall Classification System - Data Collector")
    print(separator)
    print(f"Targets: {len(targets)} hosts | Output: {args.output}")
    print(f"Parallel: {args.parallel} | Repeat: {args.repeat} | Debug: {args.debug}")
    print(f"{separator}\n")
    
    check_required_tools()
    
    # Repeat data collection N times
    total_collected = 0
    for iteration in range(args.repeat):
        if args.repeat > 1:
            print(f"\n{'='*70}\nITERATION {iteration + 1}/{args.repeat}\n{'='*70}\n")
        
        all_features = []
        
        # Collect data (parallel or sequential)
        if args.parallel > 1:
            print(f"[*] Starting parallel collection with {args.parallel} workers...\n")
            with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                futures = {executor.submit(collect_features, ip, args.debug): ip for ip in targets}
                for future in as_completed(futures):
                    try:
                        all_features.append(future.result())
                    except Exception as e:
                        print(f"[!] Error collecting from {futures[future]}: {e}")
        else:
            print("[*] Starting sequential collection...\n")
            for ip in targets:
                try:
                    all_features.append(collect_features(ip, args.debug))
                except Exception as e:
                    print(f"[!] Error collecting from {ip}: {e}")
                print()
        
        # Write results
        if all_features:
            write_csv(all_features, args.output, append=(iteration > 0))
            total_collected += len(all_features)
            print(f"[✓] Iteration {iteration + 1}: Collected {len(all_features)} samples")
        else:
            print(f"[!] Iteration {iteration + 1}: No data collected", file=sys.stderr)
        
        # Delay between iterations
        if iteration < args.repeat - 1:
            print(f"\n[*] Waiting 2s before next iteration...")
            time.sleep(2)
    
    # Final summary
    if total_collected > 0:
        print(f"\n{'='*70}")
        print(f"[✓] COMPLETED: {total_collected} samples ({args.repeat} × {len(targets)} hosts)")
        print(f"    Dataset: {args.output}")
        print(f"{'='*70}")
    else:
        print("[!] No data collected", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
