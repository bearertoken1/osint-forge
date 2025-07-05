import os

def reverse_image_search(image_path):
    print("[+] Reverse Image Search Links (manual upload required):")
    print("Google: https://images.google.com/")
    print("Yandex: https://yandex.com/images/")
    print("Bing: https://www.bing.com/visualsearch")
    print("TinEye: https://tineye.com/")
    print("Upload your image to these services for best results.")

def email_pattern_generator(name, domain):
    print("[+] Common Email Patterns:")
    name = name.strip().lower()
    parts = name.split()
    if len(parts) < 2:
        print("Please provide a full name (first and last).")
        return
    first, last = parts[0], parts[-1]
    patterns = [
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{first}_{last}@{domain}",
        f"{last}{first}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{first}{last[0]}@{domain}",
    ]
    for p in patterns:
        print("->", p)

def extract_metadata(file_path):
    print("[+] File Metadata:")
    if not os.path.exists(file_path):
        print("File does not exist.")
        return
    stat = os.stat(file_path)
    print("Size:", stat.st_size, "bytes")
    print("Created:", stat.st_ctime)
    print("Modified:", stat.st_mtime)
    print("Accessed:", stat.st_atime)
    print("Absolute Path:", os.path.abspath(file_path))
