# 🔍 CyberScan - Advanced Cyber Security Scanner

CyberScan is an advanced cybersecurity tool designed for penetration testers and security researchers. It helps you perform **fast and deep scanning** of target domains, detect vulnerabilities, and fetch exploit information.

## 🚀 Features
- **Fast and Deep Scanning Modes**: Choose between quick scans or comprehensive analysis.
- **Multiple Scanning Methods**: Uses **Netcat, Metasploit, SSH, SMBClient, Telnet**, and more.
- **Exploit Fetching**: Automatically retrieves exploit information from known databases.
- **Nmap Integration (Optional)**: Can be used for additional scanning without showing Nmap-specific output.
- **OSINT and Web Vulnerability Analysis**: Fetches public information and web security details.

---

## 🛠 Installation

Clone the repository and install the required dependencies:

```bash
git clone https://github.com/Quarrezz/cyberscan.git
cd cyberscan
pip install -r requirements.txt
```
📌 Usage
Once installed, you can run CyberScan with the following options:

---

# Display help menu

cyberscan --help


🔹 Fast Scan
Performs a quick scan using Netcat:

cyberscan target.com --fast



🔹 Deep Scan
Performs an in-depth scan using Netcat, Metasploit, SSH, SMB, and more:

cyberscan target.com --deep



🔹 Deep Scan Without Nmap
To exclude Nmap from scanning, use:

cyberscan target.com --deep --exclude-nmap



🔹 Save Scan Results
Saves the output to a file:

cyberscan target.com --deep --write results.txt

---

📊 Example Output
```bash
[🔍] Target Information:
  - Domain: target.com
  - IP: 192.168.1.1
  - Server: Apache/2.4.41 (Ubuntu)
  - OS: Linux

[🚀] Scanning Common Ports...
  
  [+] 21/TCP | ftp | Version: 220 Microsoft FTP Service | Exploit: None
  
  [+] 80/TCP | http | Version: Apache/2.4.41 | Exploit: CVE-2021-41773
  
  [+] 443/TCP | https | Version: OpenSSL 1.1.1 | Exploit: None

[✅] Scan Completed!
```

---

🔧 Troubleshooting
If you face any issues with missing dependencies, try:

pip install -r requirements.txt

If cyberscan command is not found, try:

sudo python setup.py install

---

📜 License
CyberScan is released under the MIT License. You are free to use, modify, and distribute this tool with proper credit.


🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.


🛡️ Disclaimer
This tool is intended for educational and authorized penetration testing purposes only. Do not use this tool for illegal activities. The author takes no responsibility for any misuse.
