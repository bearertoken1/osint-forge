def run(email):
    print(f"[+] Basic email OSINT: {email}")
    if "gmail" in email:
        print("-> Gmail detected, consider trying Google Account recovery to validate.")
    if email.endswith("@protonmail.com"):
        print("-> ProtonMail detected, often used for anonymity.")
    print("-> To enhance, consider using HaveIBeenPwned manually (free).")