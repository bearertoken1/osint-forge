import requests

def web_fingerprinting(url):
    """
    Perform web application fingerprinting to identify CMS, frameworks,
    server software, and other technologies used by the target website.
    """
    print(f"[+] Performing web fingerprinting for: {url}")
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        print("[+] HTTP Headers:")
        for key, value in headers.items():
            print(f"    {key}: {value}")

        # Basic fingerprinting based on headers
        if 'server' in headers:
            print(f"[+] Server: {headers['server']}")
        if 'x-powered-by' in headers:
            print(f"[+] X-Powered-By: {headers['x-powered-by']}")

        # Example: Detecting CMS from headers or content
        if 'wordpress' in response.text.lower():
            print("[+] Detected CMS: WordPress")
        elif 'drupal' in response.text.lower():
            print("[+] Detected CMS: Drupal")
        elif 'joomla' in response.text.lower():
            print("[+] Detected CMS: Joomla")

    except Exception as e:
        print(f"[!] Error during web fingerprinting: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Web Application Fingerprinting")
    parser.add_argument("url", help="Target URL to fingerprint")
    args = parser.parse_args()

    web_fingerprinting(args.url)
