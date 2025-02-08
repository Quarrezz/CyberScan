import socket
import requests
import random
import ssl
import argparse
import paramiko
import subprocess
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, UDP, send, sr1
import sys
import re
sys.path.append("/home/roott/Masaüstü/VsCode/CyberSecurity/")
from core import osint_lookup, web_scan, vuln_scan
from core.exploit_finder import fetch_exploit_info

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

def get_target_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def netcat_banner_grab(target, port):
    try:
        with socket.create_connection((target, port), timeout=2) as s:
            s.sendall(b"\n")
            return s.recv(1024).decode(errors='ignore').strip()
    except:
        return "Unknown"

def metasploit_banner_grab(target, port):
    try:
        result = subprocess.run(["msfconsole", "-q", "-x", f"use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; set PORTS {port}; run; exit"], capture_output=True, text=True)
        return result.stdout.split("\n")[-2] if result.stdout else "Unknown"
    except:
        return "Unknown"

def ssh_banner_grab(target, port):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, port=port, username="invalid", password="invalid", timeout=2)
    except paramiko.ssh_exception.SSHException as e:
        return str(e)
    except:
        return "Unknown"
    finally:
        client.close()

def smbclient_enum(target):
    try:
        conn = SMBConnection("guest", "", "scanner", target)
        conn.connect(target, 445)
        return "SMB Shared Resources Accessible"
    except:
        return "Unknown"

def udp_scan(target, port):
    try:
        packet = IP(dst=target)/UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=False)
        return "Open" if response else "Filtered/Closed"
    except:
        return "Unknown"

def run_nmap_scan(target, port):
    try:
        result = subprocess.run(["nmap", "-sV", "-p", str(port), target], capture_output=True, text=True)
        output_lines = result.stdout.split("\n")
        for line in output_lines:
            if str(port) in line:
                return line.strip(), fetch_exploit_info(line.strip(), port)
        return "Unknown", "None"
    except:
        return "Unknown", "None"

def scan_target(domain, mode, exclude_nmap):
    target_ip = get_target_ip(domain)
    if not target_ip:
        print("[❌] Unable to resolve domain.")
        return
    
    print(f"\n[🔍] Target Information:")
    print(f"  - Domain: {domain}")
    print(f"  - IP: {target_ip}")
    osint_lookup(domain)
    web_scan(domain)
    
    print("\n[🚀] Scanning Common Ports...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(lambda port: scan_port(target_ip, port, mode, exclude_nmap), COMMON_PORTS))
    print("\n[✅] Scan Completed!")

def scan_port(target, port, mode, exclude_nmap):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((target, port))
            if result == 0:
                service = socket.getservbyport(port, "tcp") if port in COMMON_PORTS else "Unknown"
                
                version_info = "Unknown"
                if mode == "fast":
                    version_info = netcat_banner_grab(target, port)
                elif mode == "deep":
                    version_info = (
                        netcat_banner_grab(target, port) or
                        metasploit_banner_grab(target, port) or
                        ssh_banner_grab(target, port) or
                        smbclient_enum(target)
                    )
                
                exploit_info = "None"
                if not exclude_nmap and version_info == "Unknown":
                    version_info, exploit_info = run_nmap_scan(target, port)
                else:
                    exploit_info = fetch_exploit_info(service, port)
                
                print(f"  [+] {port}/TCP | {service} | Version: {version_info} | Exploit: {exploit_info if exploit_info else 'None'}")
    except Exception as e:
        print(f"  [⚠] Error scanning port {port}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Advanced CyberSecurity Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--fast", action="store_true", help="Perform a fast scan using Netcat only")
    parser.add_argument("--deep", action="store_true", help="Perform a deep scan using multiple methods")
    parser.add_argument("--exclude-nmap", action="store_true", help="Exclude Nmap from the scanning process")
    args = parser.parse_args()

    scan_mode = "deep" if args.deep else "fast" if args.fast else "normal"
    scan_target(args.domain, scan_mode, args.exclude_nmap)

if __name__ == "__main__":
    main()
