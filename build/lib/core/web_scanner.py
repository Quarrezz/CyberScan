import requests
import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

def web_scan(domain):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        response = requests.get(f"http://{domain}", headers=headers, timeout=5)
        waf = "Cloudflare" if "cloudflare" in response.text.lower() else "Unknown"
        print("\n[WEB SCANNER] Scan Summary:")
        print(f"  - WAF: {waf}")
    except requests.exceptions.RequestException:
        print("[WEB SCANNER] Unable to analyze target.")
