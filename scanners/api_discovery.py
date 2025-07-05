import requests


def api_endpoint_discovery(domain, wordlist="api_wordlist.txt"):
    """
    Discover API endpoints on the target domain using a wordlist.
    """
    print(f"[+] Discovering API endpoints for: {domain}")
    results = []

    try:
        with open(wordlist, "r") as f:
            endpoints = [line.strip() for line in f]

        for endpoint in endpoints:
            url = f"{domain}/{endpoint}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] Found API endpoint: {url}")
                    results.append(url)
            except requests.RequestException:
                pass

        print(f"[+] Total API endpoints discovered: {len(results)}")
    except Exception as e:
        print(f"[!] Error during API endpoint discovery: {e}")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="API Endpoint Discovery")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument(
        "-w",
        "--wordlist",
        default="api_wordlist.txt",
        help="Path to API wordlist",
    )
    args = parser.parse_args()

    api_endpoint_discovery(args.domain, args.wordlist)
