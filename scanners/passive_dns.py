import requests

def passive_dns_scan(domain):
    """
    Perform passive DNS and historical DNS scanning for a given domain.
    Uses public sources to gather DNS records without requiring an API key.
    """
    print(f"[+] Performing passive DNS scan for: {domain}")
    results = []

    try:
        # Example: Using crt.sh for historical DNS records
        crtsh_url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(crtsh_url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            for entry in data:
                if 'name_value' in entry:
                    subdomains = entry['name_value'].split('\n')
                    results.extend(subdomains)

            # Remove duplicates and sort
            results = sorted(set(results))
            print(f"[+] Found {len(results)} historical DNS records.")
            for record in results:
                print(f"    - {record}")
        else:
            print(f"[!] Failed to fetch data from crt.sh. Status code: {response.status_code}")

    except Exception as e:
        print(f"[!] Error during passive DNS scan: {e}")

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Passive DNS and Historical DNS Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    args = parser.parse_args()

    passive_dns_scan(args.domain)
