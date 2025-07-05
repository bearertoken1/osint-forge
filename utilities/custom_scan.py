from utilities.site_list import get_site_by_keys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

def custom_scan(username, site_keys, threads=10, timeout=5):
    if not site_keys:
        print("No sites specified. Use --sites site1 site2 ...")
        return
    sites = get_site_by_keys(site_keys)
    if not sites:
        print("No valid sites found for keys:", site_keys)
        return
    print(f"Custom scan for {username} on {len(sites)} sites:")
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
    found_count = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_site = {executor.submit(check_site, s): s for s in sites}
        for future in as_completed(future_to_site):
            site, url, found = future.result()
            if found is True:
                print(f"-> {site}: Found! {url}")
                found_count += 1
            elif found is False:
                print(f"-> {site}: Not found.")
            else:
                print(f"-> {site}: Error checking.")
    print(f"-> Checked {len(sites)} sites, found {found_count} profiles.")
