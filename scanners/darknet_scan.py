import requests


def darknet_scan(keywords, onion_list="onion_sites.txt"):
    """
    Scan darknet marketplaces and forums for mentions of target keywords.
    """
    print(f"[+] Scanning darknet for keywords: {', '.join(keywords)}")
    results = {}

    try:
        with open(onion_list, "r") as f:
            sites = [line.strip() for line in f]

        for site in sites:
            try:
                response = requests.get(site, timeout=10)
                if response.status_code == 200:
                    for keyword in keywords:
                        if keyword.lower() in response.text.lower():
                            if site not in results:
                                results[site] = []
                            results[site].append(keyword)
                            print(f"[+] Found keyword '{keyword}' on {site}")
            except requests.RequestException:
                pass

        print(f"[+] Total sites with matches: {len(results)}")
    except Exception as e:
        print(f"[!] Error during darknet scan: {e}")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Darknet Marketplace and Forum Scanner"
    )
    parser.add_argument("keywords", nargs="+", help="Keywords to search for")
    parser.add_argument(
        "-l",
        "--list",
        default="onion_sites.txt",
        help="Path to onion site list",
    )
    args = parser.parse_args()

    darknet_scan(args.keywords, args.list)
