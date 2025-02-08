#!/usr/bin/env python3

import sys
sys.path.append("/home/roott/Masaüstü/VsCode/CyberSecurity/")
import argparse
from core.port_scanner import scan_target

# Define command-line arguments
parser = argparse.ArgumentParser(
    description="Advanced CyberSecurity Scanner - Port & Vulnerability Scanner"
)
parser.add_argument("domain", help="Target domain or IP address")
parser.add_argument("--fast", action="store_true", help="Perform a quick scan using Netcat")
parser.add_argument("--deep", action="store_true", help="Perform a deep scan using Netcat, Metasploit, SSH, SMB")
parser.add_argument("--exclude-nmap", action="store_true", help="Scan without using Nmap")
args = parser.parse_args()

# Determine the scan mode based on user input
scan_mode = "deep" if args.deep else "fast" if args.fast else "normal"

# Start the scanning process
scan_target(args.domain, scan_mode, args.exclude_nmap)