import requests

def content_discovery(domain, wordlist="content_wordlist.txt"):
    """
    Discover hidden directories and files on the target domain using a wordlist.
    """
    print(f"[+] Performing content discovery for: {domain}")
    results = []

    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f]

        for path in paths:
            url = f"{domain}/{path}"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] Found: {url}")
                    results.append(url)
            except requests.RequestException:
                pass

        print(f"[+] Total content discovered: {len(results)}")
    except Exception as e:
        print(f"[!] Error during content discovery: {e}")

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Content Discovery and Directory Bruteforcing")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-w", "--wordlist", default="content_wordlist.txt", help="Path to content wordlist")
    args = parser.parse_args()

    content_discovery(args.domain, args.wordlist)
