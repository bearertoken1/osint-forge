# Credits
# OSINT Forge developed by bearertoken
# GitHub: https://github.com/bearertoken1
# Discord: @bearertoken

import argparse
import requests
import sys
import socket
import whois
import hashlib
import os
from utilities.reverse_image import reverse_image_search
from utilities.email_pattern import email_pattern_generator
from utilities.metadata_extract import extract_metadata
from utilities.custom_scan import custom_scan
from scanners.discord_scan import discord_user_scan
from utilities.site_list import get_site_list
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser
import json
from datetime import datetime
import itertools
import threading
import time
from utilities.crypto_scan import crypto_wallet_scan
from scanners.dark_web_scan import dark_web_scan
from scanners.censys_scan import custom_domain_scan as censys_scan
from modules.shodan_scan import custom_ip_scan
from scanners.leak_scan import leaked_credentials_scan
from config import BEARER_TOKEN
from scanners.subdomain_scan import subdomain_scan
import subprocess
from utilities.spider_crawl import spider_crawl_user, spider_crawl_domain

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Dummy:
        def __getattr__(self, name): return ''
    Fore = Style = Dummy()

BANNER = r"""
╔════════════════════════════════════════════════════════════════════════════════════════════════╗
║   ________    _________.___ __________________ ___________________ __________  _____________ ║
║  \_____  \  /   _____/|   |\      \__    ___/ \_   _____/\_____  \\______   \/  _____/\_   _║
║   /   |   \ \_____  \ |   |/   |   \|    |     |    __)   /   |   \|       _/   \  ___ |    ║
║  /    |    \/        \|   /    |    \    |     |     \   /    |    \    |   \    \_\  \|   ║
║  \_______  /_______  /|___\____|__  /____|     \___  /   \_______  /____|_  /\______  /___ ║
║          \/        \/             \/               \/            \/       \/        \/     ║
╚══════════════════════════════════════════════════════════════════════════════════════════════╝
"""

def print_banner():
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    print(Fore.YELLOW + "Welcome to OSINT Forge - The Ultimate API-Free OSINT Toolkit" + Style.RESET_ALL)
    print(Fore.GREEN + "Developed by bearertoken" + Style.RESET_ALL)
    print(Fore.MAGENTA + "GitHub: https://github.com/bearertoken1" + Style.RESET_ALL)
    print(Fore.MAGENTA + "Discord: @bearertoken" + Style.RESET_ALL)
    print("\n")

# Enhanced AI analysis
def ai_analyze(text):
    hints = []
    if "gmail.com" in text:
        hints.append("Likely a Google account, try Google recovery and search leaks.")
    if "yahoo.com" in text:
        hints.append("Yahoo address, check Yahoo recovery and old breach dumps.")
    if text.isdigit() and len(text) in [10, 11]:
        hints.append("Possible phone number, try SMS-based services and search leaks.")
    if "." in text and not text.replace(".", "").isdigit():
        hints.append("Looks like a domain or IP, check DNS, WHOIS, and passive DNS.")
    if len(hints) == 0:
        hints.append("No AI hints found, try manual OSINT techniques.")
    print(Fore.MAGENTA + "[AI] " + " ".join(hints) + Style.RESET_ALL)
    return hints

# Save results to JSON
def save_to_json(data, filename, args=None):
    if args and not args.output:
        return
    if not args or not args.output:
        return  # Skip saving if no output flag is provided

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(Fore.CYAN + f"[+] JSON output saved to {filename}" + Style.RESET_ALL)

# Generate text report
def generate_text_report(data, filename, args=None):
    """
    Generate a plain text report instead of a PDF.

    Args:
        data (dict): The data to include in the report.
        filename (str): The name of the output file.
        args (argparse.Namespace): Additional arguments (optional).
    """
    if args and not args.output:
        return

    with open(filename, "w", encoding="utf-8") as f:
        f.write("OSINT Report\n")
        f.write("=" * 50 + "\n\n")
        for key, value in data.items():
            f.write(f"{key}: {value}\n")

    print(Fore.CYAN + f"[+] Text report saved to {filename}" + Style.RESET_ALL)

def output_to_file(data, prefix="osint_output", args=None):
    if args and not args.output:
        return
    if not args or not args.output:
        return  # Skip saving if no output flag is provided

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{ts}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)
    print(Fore.CYAN + f"[+] Output saved to {filename}" + Style.RESET_ALL)

def get_ip_for_username(username):
    try:
        resp = requests.get(f"https://api.hackertarget.com/dnslookup/?q={username}", timeout=5)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines:
                if "A" in line and not line.startswith("A"):
                    ip = line.split()[-1]
                    return ip
    except Exception:
        pass
    return None

def check_breaches(email_or_username):
    try:
        resp = requests.get(f"https://haveibeenpwned.com/unifiedsearch/{email_or_username}", headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        if resp.status_code == 200 and "BreachName" in resp.text:
            print(Fore.RED + f"[!] Breach found for {email_or_username} on HaveIBeenPwned!" + Style.RESET_ALL)
        else:
            print(f"[!] No breach found for {email_or_username} on HaveIBeenPwned (manual check recommended).")
    except Exception:
        print("[!] Could not check HaveIBeenPwned (rate limited or blocked).")

def user_osint(username, threads=10, timeout=5, site_limit=None, fast=False):
    print_banner()
    print(Fore.LIGHTBLUE_EX + f"[+] Username OSINT: {username}" + Style.RESET_ALL)
    output_lines = []
    if fast:
        sites = get_site_list(100, main_only=True)
    else:
        sites = get_site_list(site_limit, main_only=True)
    found_count = 0
    def check_site(site_url_tuple):
        site, url = site_url_tuple
        try:
            check_url = url.replace("{username}", username)
            r = requests.get(check_url, timeout=timeout)
            if r.status_code == 200:
                return (site, check_url, True)
            else:
                return (site, check_url, False)
        except Exception:
            return (site, url, None)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_site = {executor.submit(check_site, s): s for s in sites}
        for future in as_completed(future_to_site):
            site, url, found = future.result()
            if found is True:
                msg = f"-> {site}: Found! {url}"
                print(Fore.GREEN + msg + Style.RESET_ALL)
                output_lines.append(msg)
                found_count += 1
            elif found is False:
                msg = f"-> {site}: Not found."
                print(msg)
                output_lines.append(msg)
            else:
                msg = f"-> {site}: Error checking."
                print(msg)
                output_lines.append(msg)
    print(Fore.LIGHTYELLOW_EX + f"-> Checked {len(sites)} sites, found {found_count} profiles." + Style.RESET_ALL)
    output_lines.append(f"-> Checked {len(sites)} sites, found {found_count} profiles.")
    print("-> For more, try Sherlock, WhatsMyName, or manual searching.")
    output_lines.append("-> For more, try Sherlock, WhatsMyName, or manual searching.")
    print(f"-> Google dork: inurl:{username}")
    output_lines.append(f"-> Google dork: inurl:{username}")
    print("[OSINT Protection] Use unique usernames per site, avoid reusing handles.")
    output_lines.append("[OSINT Protection] Use unique usernames per site, avoid reusing handles.")
    ai_analyze(username)
    ip = get_ip_for_username(username)
    if ip:
        msg = f"[+] Possible IP found for {username}: {ip}"
        print(Fore.LIGHTCYAN_EX + msg + Style.RESET_ALL)
        output_lines.append(msg)
    else:
        msg = "[+] No IP found for username (not a domain or not resolvable)."
        print(msg)
        output_lines.append(msg)
    check_breaches(username)
    output_lines.append("[+] Breach check attempted (see above).")
    print("[*] For deep web crawling, try the --spider option!")
    output_lines.append("[*] For deep web crawling, try the --spider option!")
    output_lines.append("-" * 50)
    output_to_file("\n".join(output_lines), prefix=f"osint_user_{username}")

def email_osint(email):
    print_banner()
    print(Fore.LIGHTBLUE_EX + f"[+] Email OSINT: {email}" + Style.RESET_ALL)
    output_lines = []
    try:
        if email.endswith("@gmail.com"):
            print("-> Gmail detected, try Google Account recovery.")
            output_lines.append("-> Gmail detected, try Google Account recovery.")
        elif email.endswith("@yahoo.com"):
            print("-> Yahoo detected, try Yahoo Account recovery.")
            output_lines.append("-> Yahoo detected, try Yahoo Account recovery.")
        elif email.endswith("@outlook.com") or email.endswith("@hotmail.com"):
            print("-> Microsoft email detected, try Outlook/Hotmail Account recovery.")
            output_lines.append("-> Microsoft email detected, try Outlook/Hotmail Account recovery.")
        else:
            print("-> Unknown provider, try searching for breaches or leaks.")
            output_lines.append("-> Unknown provider, try searching for breaches or leaks.")
        print("-> Check for breaches: https://haveibeenpwned.com/")
        output_lines.append("-> Check for breaches: https://haveibeenpwned.com/")
        gravatar_hash = hashlib.md5(email.strip().lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
        resp = requests.get(gravatar_url, timeout=5)
        if resp.status_code == 200:
            print("-> Gravatar profile found!")
            print(f"   {gravatar_url}")
            output_lines.append("-> Gravatar profile found!")
            output_lines.append(f"   {gravatar_url}")
        else:
            print("-> No Gravatar profile found.")
            output_lines.append("-> No Gravatar profile found.")
        print("-> Try searching this email on Facebook, Twitter, LinkedIn, Instagram, etc.")
        output_lines.append("-> Try searching this email on Facebook, Twitter, LinkedIn, Instagram, etc.")
        print(f"-> Search in Google: \"{email}\"")
        output_lines.append(f"-> Search in Google: \"{email}\"")
        print("-> Check public paste sites: pastebin.com, ghostbin.com, etc.")
        output_lines.append("-> Check public paste sites: pastebin.com, ghostbin.com, etc.")
        print("-> Check public code repos: GitHub, GitLab, Bitbucket.")
        output_lines.append("-> Check public code repos: GitHub, GitLab, Bitbucket.")
        print("-> Check public leaks: https://dehashed.com/ (manual, free limited)")
        output_lines.append("-> Check public leaks: https://dehashed.com/ (manual, free limited)")
        print("[OSINT Protection] Use email aliases, avoid reusing emails, check for leaks regularly.")
        output_lines.append("[OSINT Protection] Use email aliases, avoid reusing emails, check for leaks regularly.")
        ai_analyze(email)
        check_breaches(email)
        output_lines.append("[+] Breach check attempted (see above).")
        output_lines.append("-" * 50)
        output_to_file("\n".join(output_lines), prefix=f"osint_email_{email.replace('@','_')}")
    except Exception as e:
        print(Fore.RED + f"Error during email OSINT: {e}" + Style.RESET_ALL)

def ip_osint(ip):
    print_banner()
    print(Fore.YELLOW + f"[+] IP Lookup: {ip}" + Style.RESET_ALL)
    output_lines = []
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            for k, v in data.items():
                msg = f"{k}: {v}"
                print(msg)
                output_lines.append(msg)
        else:
            print("[-] Could not fetch IP info.")
            output_lines.append("[-] Could not fetch IP info.")
        print("-> Try Shodan.io, Censys.io, and AbuseIPDB.com for more advanced IP analysis.")
        output_lines.append("-> Try Shodan.io, Censys.io, and AbuseIPDB.com for more advanced IP analysis.")
        print("-> Check for open ports: use nmap (manual).")
        output_lines.append("-> Check for open ports: use nmap (manual).")
        print("-> Check for blacklists: https://mxtoolbox.com/blacklists.aspx")
        output_lines.append("-> Check for blacklists: https://mxtoolbox.com/blacklists.aspx")
        print("[OSINT Protection] Use VPNs, proxies, and avoid exposing your real IP.")
        output_lines.append("[OSINT Protection] Use VPNs, proxies, and avoid exposing your real IP.")
        ai_analyze(ip)
        output_lines.append("-" * 50)
        output_to_file("\n".join(output_lines), prefix=f"osint_ip_{ip.replace('.','_')}")
    except Exception as e:
        print(Fore.RED + f"Error during IP OSINT: {e}" + Style.RESET_ALL)

def phone_osint(phone):
    print_banner()
    print(Fore.YELLOW + f"[+] Phone OSINT: {phone}" + Style.RESET_ALL)
    output_lines = []
    try:
        if phone.startswith("1") and len(phone) == 11:
            msg = "-> US/Canada country code detected."
            print(msg)
            output_lines.append(msg)
        elif phone.startswith("+44"):
            msg = "-> UK number detected."
            print(msg)
            output_lines.append(msg)
        else:
            msg = "-> Unknown prefix. Try Google search or TrueCaller."
            print(msg)
            output_lines.append(msg)
        print("-> Try searching on Facebook, WhatsApp, or Telegram.")
        output_lines.append("-> Try searching on Facebook, WhatsApp, or Telegram.")
        print("-> Check numverify.com, sync.me, and TrueCaller (manual, free limited).")
        output_lines.append("-> Check numverify.com, sync.me, and TrueCaller (manual, free limited).")
        print(f"-> Google dork: \"{phone}\"")
        output_lines.append(f"-> Google dork: \"{phone}\"")
        print("[OSINT Protection] Don't post your phone number publicly, use burner numbers.")
        output_lines.append("[OSINT Protection] Don't post your phone number publicly, use burner numbers.")
        ai_analyze(phone)
        check_breaches(phone)
        output_lines.append("[+] Breach check attempted (see above).")
        output_lines.append("-" * 50)
        output_to_file("\n".join(output_lines), prefix=f"osint_phone_{phone}")
    except Exception as e:
        print(Fore.RED + f"Error during phone OSINT: {e}" + Style.RESET_ALL)

def domain_osint(domain, spider=False, args=None):
    print_banner()
    print(f"[+] Domain OSINT: {domain}")
    output_lines = []
    results = {}
    try:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(domain)
        msg = f"-> Resolved IP: {ip}"
        print(msg)
        output_lines.append(msg)
        results['Resolved IP'] = ip

        # WHOIS lookup
        try:
            import whois
            w = whois.whois(domain) if hasattr(whois, "whois") else whois.query(domain)
            print("-> WHOIS info:")
            output_lines.append("-> WHOIS info:")
            if hasattr(w, "items"):
                for k, v in w.items():
                    whois_msg = f"   {k}: {v}"
                    print(whois_msg)
                    output_lines.append(whois_msg)
                    results[f"WHOIS {k}"] = v
            else:
                print(w)
                output_lines.append(str(w))
        except Exception as e:
            error_msg = f"WHOIS lookup failed: {e}"
            print(error_msg)
            output_lines.append(error_msg)

        # VirusTotal API request
        vt_url = f"https://www.virustotal.com/ui/domains/{domain}"
        resp = api_request(vt_url)
        if resp and resp.status_code == 200 and "data" in resp.json():
            data = resp.json()["data"]
            vt_msg = f"   Reputation: {data.get('attributes', {}).get('reputation', 'N/A')}"
            print(vt_msg)
            output_lines.append(vt_msg)
            results['VirusTotal Reputation'] = data.get('attributes', {}).get('reputation', 'N/A')
            vt_cat = f"   Categories: {data.get('attributes', {}).get('categories', 'N/A')}"
            print(vt_cat)
            output_lines.append(vt_cat)
        else:
            print("   Could not fetch summary, opening in browser...")
            output_lines.append("   Could not fetch summary, opening in browser...")
            webbrowser.open(vt_url)

        # urlscan.io summary
        print("-> urlscan.io summary:")
        output_lines.append("-> urlscan.io summary:")
        urlscan_url = f"https://urlscan.io/domain/{domain}"
        try:
            resp = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=10)
            if resp.status_code == 200 and "results" in resp.json():
                results = resp.json()["results"]
                scan_msg = f"   Found {len(results)} scan(s). See browser for details."
                print(scan_msg)
                output_lines.append(scan_msg)
            else:
                print("   Could not fetch summary, opening in browser...")
                output_lines.append("   Could not fetch summary, opening in browser...")
                webbrowser.open(urlscan_url)
        except Exception:
            print("   Could not fetch summary, opening in browser...")
            output_lines.append("   Could not fetch summary, opening in browser...")
            webbrowser.open(urlscan_url)

        # crt.sh certificates
        print("-> crt.sh certificates:")
        output_lines.append("-> crt.sh certificates:")
        crt_url = f"https://crt.sh/?q={domain}"
        try:
            resp = requests.get(f"https://crt.sh/?q={domain}", timeout=10)
            if resp.status_code == 200 and "Issuer" in resp.text:
                print("   Certificates found. See browser for details.")
                output_lines.append("   Certificates found. See browser for details.")
            else:
                print("   Could not fetch summary, opening in browser...")
                output_lines.append("   Could not fetch summary, opening in browser...")
                webbrowser.open(crt_url)
        except Exception:
            print("   Could not fetch summary, opening in browser...")
            output_lines.append("   Could not fetch summary, opening in browser...")
            webbrowser.open(crt_url)

        # DNSDumpster
        print("-> DNSDumpster:")
        output_lines.append("-> DNSDumpster:")
        dnsdump_url = "https://dnsdumpster.com/"
        print("   Automated scraping not supported. Opening in browser...")
        output_lines.append("   Automated scraping not supported. Opening in browser...")
        webbrowser.open(dnsdump_url)

        # SecurityTrails
        print("-> SecurityTrails:")
        output_lines.append("-> SecurityTrails:")
        st_url = f"https://securitytrails.com/domain/{domain}"
        print("   Automated scraping not supported. Opening in browser...")
        output_lines.append("   Automated scraping not supported. Opening in browser...")
        webbrowser.open(st_url)

        print("[OSINT Protection] Use privacy WHOIS, avoid exposing personal info in DNS.")
        output_lines.append("[OSINT Protection] Use privacy WHOIS, avoid exposing personal info in DNS.")
        ai_analyze(domain)
        print("[*] For deep crawling, try the --spider option!")
        output_lines.append("[*] For deep crawling, try the --spider option!")
        if spider:
            from utilities.spider_crawl import spider_crawl_domain
            spider_crawl_domain(domain)
        output_lines.append("-" * 50)
        output_to_file("\n".join(output_lines), prefix=f"osint_domain_{domain}")

        # Save results to JSON and text report
        json_filename = f"osint_domain_{domain}.json"
        text_filename = f"osint_domain_{domain}.txt"
        save_to_json(results, json_filename, args=args)
        generate_text_report(results, text_filename, args=args)

    except Exception as e:
        print(Fore.RED + f"Error during domain OSINT: {e}" + Style.RESET_ALL)

# Spinner for minimal output
def spinner():
    for char in itertools.cycle(['|', '/', '-', '\\']):
        if not spinning:
            break
        sys.stdout.write(f'\r{char} Running...')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r')

# Global variable to control spinner
spinning = False

# Wrapper for API requests with bearer token support
def api_request(url, headers=None, timeout=10):
    if headers is None:
        headers = {}
    headers['Authorization'] = f'Bearer {BEARER_TOKEN}'
    try:
        return requests.get(url, headers=headers, timeout=timeout)
    except Exception as e:
        print(f"[!] Error during API request: {e}")
        return None

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="OSINT Forge - The Ultimate API-Free OSINT Toolkit",
        epilog="Use '--help' for more information on available commands."
    )

    # Define flags for each command
    parser.add_argument("--username", help="Perform username OSINT across multiple platforms")
    parser.add_argument("--email", help="Analyze email addresses for breaches and metadata")
    parser.add_argument("--domain", help="Perform domain OSINT including WHOIS and DNS lookups")
    parser.add_argument("--ip", help="Geolocate and analyze IP addresses")
    parser.add_argument("--phone", help="Analyze phone numbers for breaches")
    parser.add_argument("--subdomain", help="Enumerate subdomains for a given domain")
    parser.add_argument("--darkweb", help="Search the dark web for specific keywords")
    parser.add_argument("--reverse-image", help="Perform reverse image searches")
    parser.add_argument("--email-pattern", help="Generate email patterns")
    parser.add_argument("--metadata", help="Extract metadata from files")
    parser.add_argument("--custom-scan", help="Perform custom scans")
    parser.add_argument("--crypto-scan", help="Scan cryptocurrency wallets")
    parser.add_argument("--shodan-scan", help="Perform Shodan scans")
    parser.add_argument("--iot-scan", help="Scan IoT devices")
    parser.add_argument("--api-discovery", help="Discover hidden API endpoints")
    parser.add_argument("--output", action="store_true", help="Enable output to files")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Debugging the command logic
    print(f"[DEBUG] Arguments received: {args}")

    # Handle each flag
    if args.username:
        print(f"[DEBUG] Executing username OSINT for: {args.username}")
        user_osint(args.username)
    elif args.email:
        print(f"[DEBUG] Executing email OSINT for: {args.email}")
        email_osint(args.email)
    elif args.domain:
        print(f"[DEBUG] Executing domain OSINT for: {args.domain}")
        domain_osint(args.domain, args=args)
    elif args.ip:
        print(f"[DEBUG] Executing IP OSINT for: {args.ip}")
        ip_osint(args.ip)
    elif args.phone:
        print(f"[DEBUG] Executing phone OSINT for: {args.phone}")
        phone_osint(args.phone)
    elif args.subdomain:
        print(f"[DEBUG] Executing subdomain OSINT for: {args.subdomain}")
        subdomain_scan(args.subdomain)
    elif args.darkweb:
        print(f"[DEBUG] Executing dark web OSINT for: {args.darkweb}")
        dark_web_scan(args.darkweb)
    elif args.reverse_image:
        print(f"[DEBUG] Executing reverse image search for: {args.reverse_image}")
        reverse_image_search(args.reverse_image)
    elif args.email_pattern:
        print(f"[DEBUG] Generating email patterns for: {args.email_pattern}")
        email_pattern_generator(args.email_pattern)
    elif args.metadata:
        print(f"[DEBUG] Extracting metadata from: {args.metadata}")
        extract_metadata(args.metadata)
    elif args.custom_scan:
        print(f"[DEBUG] Performing custom scan for: {args.custom_scan}")
        custom_scan(args.custom_scan)
    elif args.crypto_scan:
        print(f"[DEBUG] Scanning cryptocurrency wallet: {args.crypto_scan}")
        crypto_wallet_scan(args.crypto_scan)
    elif args.shodan_scan:
        print(f"[DEBUG] Performing Shodan scan for: {args.shodan_scan}")
        custom_ip_scan(args.shodan_scan)
    elif args.iot_scan:
        print(f"[DEBUG] Scanning IoT devices in range: {args.iot_scan}")
        iot_scan(args.iot_scan)  # Ensure this function is defined elsewhere
    elif args.api_discovery:
        print(f"[DEBUG] Discovering APIs for domain: {args.api_discovery}")
        api_discovery(args.api_discovery)  # Ensure this function is defined elsewhere
    else:
        print("[ERROR] No valid command provided. Use '--help' for available options.")

    if not args.verbose:
        spinning = True
        spinner_thread = threading.Thread(target=spinner)
        spinner_thread.start()
        # Stop spinner if running
        spinning = False
        spinner_thread.join()

if __name__ == "__main__":
    main()