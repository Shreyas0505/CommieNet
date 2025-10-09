#!/usr/bin/env python3
"""
Network Device Scanner
Scans the local network to detect connected devices and their IP addresses
"""

import socket
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_network_range(ip):
    """Get the network range based on local IP (assumes /24 subnet)"""
    network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return network

def ping_host(ip):
    """Ping a host to check if it's alive"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout = '-w' if platform.system().lower() == 'windows' else '-W'
    
    command = ['ping', param, '1', timeout, '1', str(ip)]
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False

def get_hostname(ip):
    """Try to get the hostname for an IP address"""
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"

def get_mac_address(ip):
    """Try to get MAC address from ARP table"""
    try:
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode()
            mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        else:
            output = subprocess.check_output(f"arp -n {ip}", shell=True).decode()
            mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        
        if mac:
            return mac.group(0)
    except Exception:
        pass
    return "N/A"

def scan_network():
    """Scan the local network for connected devices"""
    local_ip = get_local_ip()
    print(f"[*] Local IP: {local_ip}")
    
    network = get_network_range(local_ip)
    print(f"[*] Scanning network: {network}")
    print(f"[*] This may take a minute...\n")
    
    active_hosts = []
    
    # Use ThreadPoolExecutor for faster scanning
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(ping_host, str(ip)): ip for ip in network.hosts()}
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    active_hosts.append(str(ip))
            except Exception:
                pass
    
    return active_hosts

def display_results(hosts):
    """Display the scan results in a formatted table"""
    print("=" * 80)
    print(f"{'IP Address':<18} {'Hostname':<30} {'MAC Address':<20}")
    print("=" * 80)
    
    for ip in sorted(hosts, key=lambda x: ipaddress.IPv4Address(x)):
        hostname = get_hostname(ip)
        mac = get_mac_address(ip)
        print(f"{ip:<18} {hostname:<30} {mac:<20}")
    
    print("=" * 80)
    print(f"\n[*] Total devices found: {len(hosts)}")

def main():
    print("\n" + "=" * 80)
    print(" Network Device Scanner".center(80))
    print("=" * 80 + "\n")
    
    try:
        active_hosts = scan_network()
        
        if active_hosts:
            display_results(active_hosts)
        else:
            print("[!] No active hosts found on the network")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()