import requests

def ct_log_monitor(domain):
    """
    Monitor Certificate Transparency (CT) logs for newly issued certificates
    related to a target domain. Uses public CT log endpoints.
    """
    print(f"[+] Monitoring CT logs for: {domain}")
    results = []

    try:
        crtsh_url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(crtsh_url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            for entry in data:
                if 'name_value' in entry:
                    subdomains = entry['name_value'].split('\n')
                    results.extend(subdomains)

            results = sorted(set(results))
            print(f"[+] Found {len(results)} certificates in CT logs.")
            for record in results:
                print(f"    - {record}")
        else:
            print(f"[!] Failed to fetch data from crt.sh. Status code: {response.status_code}")

    except Exception as e:
        print(f"[!] Error during CT log monitoring: {e}")

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Certificate Transparency (CT) Log Monitor")
    parser.add_argument("domain", help="Target domain to monitor")
    args = parser.parse_args()

    ct_log_monitor(args.domain)
