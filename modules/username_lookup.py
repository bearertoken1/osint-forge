import requests
from concurrent.futures import ThreadPoolExecutor

SITES = {
    "github": "https://github.com/{username}",
    "twitter": "https://twitter.com/{username}",
    "reddit": "https://www.reddit.com/user/{username}",
    "instagram": "https://www.instagram.com/{username}",
    "devto": "https://dev.to/{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "medium": "https://medium.com/@{username}",
    "soundcloud": "https://soundcloud.com/{username}",
    "pinterest": "https://www.pinterest.com/{username}",
    "kaggle": "https://www.kaggle.com/{username}",
    "askfm": "https://ask.fm/{username}",
    "flickr": "https://www.flickr.com/people/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "keybase": "https://keybase.io/{username}"
}

def check(site, url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return f"[FOUND] {site}: {url}"
        return f"[MISS] {site}"
    except:
        return f"[ERROR] {site}"

def run(username):
    print(f"[+] Checking username across {len(SITES)} sites...")
    urls = {k: v.format(username=username) for k, v in SITES.items()}
    with ThreadPoolExecutor(20) as pool:
        for result in pool.map(lambda kv: check(kv[0], kv[1]), urls.items()):
            print(result)