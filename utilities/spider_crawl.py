try:
    from bs4 import BeautifulSoup
except ImportError:
    print("BeautifulSoup4 (bs4) is not installed. Please run: pip install beautifulsoup4")
    exit(1)
import requests
import re

def spider_crawl_user(username):
    print(f"[+] Spider crawling for username: {username}")
    search_urls = [
        f"https://www.google.com/search?q={username}",
        f"https://duckduckgo.com/html/?q={username}",
        f"https://www.bing.com/search?q={username}",
    ]
    found_links = set()
    found_socials = set()
    found_keywords = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    for url in search_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if username in href and href.startswith("http"):
                    found_links.add(href)
                if any(s in href for s in ["twitter.com", "instagram.com", "facebook.com", "github.com"]):
                    found_socials.add(href)
            for kw in ["leak", "dump", "paste", "breach", "discord", "telegram"]:
                if kw in resp.text.lower():
                    found_keywords.add(kw)
        except Exception as e:
            print(f"Error crawling {url}: {e}")
    print(f"Found {len(found_links)} links mentioning {username}:")
    for link in found_links:
        print("->", link)
    if found_socials:
        print("Social links found:")
        for s in found_socials:
            print("->", s)
    if found_keywords:
        print("Keywords found in results:", ", ".join(found_keywords))

def spider_crawl_domain(domain):
    print(f"[+] Spider crawling domain: {domain}")
    to_visit = [f"http://{domain}"]
    visited = set()
    found_emails = set()
    found_phones = set()
    found_socials = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    while to_visit and len(visited) < 50:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("http") and domain in href and href not in visited:
                    to_visit.append(href)
                if any(s in href for s in ["twitter.com", "instagram.com", "facebook.com", "github.com"]):
                    found_socials.add(href)
            emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", resp.text))
            found_emails.update(emails)
            phones = set(re.findall(r"\+?\d[\d\-\(\) ]{7,}\d", resp.text))
            found_phones.update(phones)
        except Exception as e:
            print(f"Error crawling {url}: {e}")
    print(f"Visited {len(visited)} pages. Found emails:")
    for email in found_emails:
        print("->", email)
    if found_phones:
        print("Phone numbers found:")
        for p in found_phones:
            print("->", p)
    if found_socials:
        print("Social links found:")
        for s in found_socials:
            print("->", s)
