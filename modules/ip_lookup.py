import requests

def run(ip):
    print(f"[+] IP Lookup: {ip}")
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = res.json()
        for k, v in data.items():
            print(f"{k}: {v}")
    except:
        print("[-] Failed to reach ipinfo.io")
