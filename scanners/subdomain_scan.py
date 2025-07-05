import argparse
import subprocess
import requests

def subdomain_scan(domain, subdomain_list="subdomains.txt", output_file=None):
    print(f"[+] Scanning for subdomains of: {domain}")
    results = []
    takeover_vulnerabilities = []
    try:
        # Use a subdomain list to test for subdomains
        with open(subdomain_list, "r") as f:
            subdomains = [line.strip() for line in f]

        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                response = requests.get(f"http://{full_domain}", timeout=5)
                if response.status_code == 200:
                    results.append(full_domain)

                    # Check for subdomain takeover vulnerabilities
                    takeover_signatures = [
                        "NoSuchBucket",  # AWS S3
                        "There isn't a GitHub Pages site here.",  # GitHub Pages
                        "The specified bucket does not exist",  # Google Cloud Storage
                        "No such app",  # Heroku
                        "Domain not found"  # DigitalOcean
                    ]

                    if any(signature in response.text for signature in takeover_signatures):
                        takeover_vulnerabilities.append(full_domain)
            except requests.RequestException:
                pass

        print(f"[+] Found {len(results)} subdomains.")
        if takeover_vulnerabilities:
            print(f"[!] Potential subdomain takeover vulnerabilities detected:")
            for vuln in takeover_vulnerabilities:
                print(f"    - {vuln}")

        # Save results to a file if specified
        if output_file:
            with open(output_file, "w") as f:
                f.write("Subdomains:\n")
                f.writelines(f"{sub}\n" for sub in results)
                f.write("\nPotential Takeover Vulnerabilities:\n")
                f.writelines(f"{vuln}\n" for vuln in takeover_vulnerabilities)
            print(f"[+] Results saved to {output_file}")

        return {"subdomains": results, "takeover_vulnerabilities": takeover_vulnerabilities}
    except Exception as e:
        print(f"[!] Error during subdomain scan: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdomain Scanner with Takeover Detection")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-l", "--list", default="subdomains.txt", help="Path to subdomain list file")
    parser.add_argument("-o", "--output", help="File to save the results")
    args = parser.parse_args()

    subdomain_scan(args.domain, args.list, args.output)
