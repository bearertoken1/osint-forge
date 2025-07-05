import socket
import subprocess

def custom_domain_scan(domain):
    print(f"[+] Scanning domain: {domain}")
    results = {}
    try:
        # Resolve the domain to an IP address
        try:
            ip = socket.gethostbyname(domain)
            results['resolved_ip'] = ip
        except socket.gaierror:
            results['resolved_ip'] = "Could not resolve domain"

        # Perform a WHOIS lookup
        try:
            whois_command = ["whois", domain]
            whois_result = subprocess.run(whois_command, capture_output=True, text=True)
            results['whois'] = whois_result.stdout
        except Exception as e:
            results['whois'] = f"Error during WHOIS lookup: {e}"

        # Perform a DNS record lookup
        try:
            dig_command = ["dig", domain, "ANY"]
            dig_result = subprocess.run(dig_command, capture_output=True, text=True)
            results['dns_records'] = dig_result.stdout
        except Exception as e:
            results['dns_records'] = f"Error during DNS lookup: {e}"

        print(f"[+] Scan completed for domain: {domain}")
        return results
    except Exception as e:
        print(f"[!] Error during domain scan: {e}")
        return None
