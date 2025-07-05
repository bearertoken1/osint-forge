import requests
from config import BEARER_TOKEN  # Import BEARER_TOKEN from config.py

def dark_web_scan(keyword):
    print(f"[+] Scanning dark web for mentions of: {keyword}")
    try:
        # Example API for dark web mentions (replace with a real API)
        url = f"https://api.darkwebmonitoring.com/search?query={keyword}"
        headers = {"Authorization": f"Bearer {BEARER_TOKEN}"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            mentions = data.get("mentions", [])
            print(f"[+] Found {len(mentions)} mentions on the dark web.")
            return {"keyword": keyword, "mentions": mentions}
        else:
            print("[!] Could not fetch dark web mentions. API might be rate-limited or invalid.")
            return None
    except Exception as e:
        print(f"[!] Error during dark web scan: {e}")
        return None
