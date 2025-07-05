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
        f"{first}{last[:3]}@{domain}",
        f"{first[:3]}{last}@{domain}",
        f"{first}.{last}{domain[-4:]}@{domain}",
        f"{last}.{first}@{domain}",
        f"{first}-{last}@{domain}",
        f"{last}-{first}@{domain}",
    ]
    for p in patterns:
        print("->", p)
    print(f"[+] Generated {len(patterns)} email patterns for {name} at {domain}")
