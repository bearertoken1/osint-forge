import socket
import whois
import subprocess

def run(domain):
    print(f"[+] Domain OSINT: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"Resolved IP: {ip}")
    except:
        print("[-] Domain could not be resolved")
        return

    try:
        w = whois.whois(domain)
        print("\n[WHOIS]")
        for k, v in w.items():
            print(f"{k}: {v}")
    except:
        print("[-] WHOIS failed")

    try:
        print("\n[NSLOOKUP]")
        subprocess.run(["nslookup", domain])
    except:
        print("[-] nslookup failed")

    try:
        print("\n[DIG]")
        subprocess.run(["dig", domain])
    except:
        print("[-] dig failed")
