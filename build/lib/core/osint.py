import requests

def osint_lookup(domain):
    subdomains = []
    try:
        response = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=5)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomain = entry["name_value"]
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
    except requests.exceptions.RequestException:
        print("[OSINT] Subdomain lookup failed.")
    
    if subdomains:
        print("\n[OSINT] Found Subdomains:")
        for sub in subdomains:
            print(f"  - {sub}")
    else:
        print("[OSINT] No subdomains found.")
