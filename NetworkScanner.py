import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Function to scan for active hosts using ARP request
def scan_network(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    active_hosts = []
    for element in answered_list:
        active_host = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        active_hosts.append(active_host)
    return active_hosts

# Function to scan for open ports using TCP SYN scan
def scan_ports(target_ip, ports):
    open_ports = []
    for port in ports:
        response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            sr(IP(dst=target_ip)/TCP(dport=response.sport, flags="R"), timeout=1, verbose=False)
    return open_ports

# Function to perform basic vulnerability scanning (e.g., check for common ports)
def vulnerability_scan(target_ip, open_ports):
    vulnerabilities = []
    for port in open_ports:
        if port == 80:
            vulnerabilities.append("HTTP Service Detected on Port 80")
        elif port == 443:
            vulnerabilities.append("HTTPS Service Detected on Port 443")
        # Add more checks for common vulnerabilities
    return vulnerabilities

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network_scanner.py target_ip")
        sys.exit(1)

    target_ip = sys.argv[1]
    ports = range(1, 1001)  # Scan ports from 1 to 1000

    print(f"Scanning network for active hosts...")
    active_hosts = scan_network(target_ip)
    print(f"Active Hosts:")
    for host in active_hosts:
        print(f"\tIP: {host['ip']}\tMAC: {host['mac']}")

    print(f"\nScanning for open ports on {target_ip}...")
    open_ports = scan_ports(target_ip, ports)
    print(f"Open Ports:")
    for port in open_ports:
        print(f"\tPort: {port}")

    print(f"\nPerforming vulnerability scan on {target_ip}...")
    vulnerabilities = vulnerability_scan(target_ip, open_ports)
    if vulnerabilities:
        print(f"Potential Vulnerabilities:")
        for vulnerability in vulnerabilities:
            print(f"\t- {vulnerability}")
    else:
        print("No potential vulnerabilities found.")
