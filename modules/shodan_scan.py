import socket
import subprocess

def custom_ip_scan(ip):
    print(f"[+] Scanning IP: {ip}")
    results = {}
    try:
        # Perform a basic port scan using nmap
        nmap_command = ["nmap", "-sS", "-Pn", "-p", "1-1000", ip]
        nmap_result = subprocess.run(nmap_command, capture_output=True, text=True)
        results['nmap'] = nmap_result.stdout

        # Perform a reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            results['reverse_dns'] = hostname
        except socket.herror:
            results['reverse_dns'] = "No reverse DNS found"

        # Perform a WHOIS lookup
        try:
            whois_command = ["whois", ip]
            whois_result = subprocess.run(whois_command, capture_output=True, text=True)
            results['whois'] = whois_result.stdout
        except Exception as e:
            results['whois'] = f"Error during WHOIS lookup: {e}"

        print(f"[+] Scan completed for IP: {ip}")
        return results
    except Exception as e:
        print(f"[!] Error during IP scan: {e}")
        return None
