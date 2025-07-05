import os

def leaked_credentials_scan(email_or_username):
    print(f"[+] Scanning for leaked credentials: {email_or_username}")
    try:
        # Updated dataset path to use the 'data/' directory
        dataset_path = os.path.join("data", "breach_dataset.txt")
        if not os.path.exists(dataset_path):
            print(f"[!] Breach dataset not found at {dataset_path}. Please ensure the file exists.")
            return None

        with open(dataset_path, "r", encoding="utf-8") as f:
            leaks = [line.strip() for line in f if email_or_username in line]

        print(f"[+] Found {len(leaks)} leaked credentials.")
        return {"email_or_username": email_or_username, "leaks": leaks}
    except Exception as e:
        print(f"[!] Error during leaked credentials scan: {e}")
        return None
