import os
from datetime import datetime

def extract_metadata(file_path):
    print("[+] File Metadata:")
    if not os.path.exists(file_path):
        print("File does not exist.")
        return
    stat = os.stat(file_path)
    print("Size:", stat.st_size, "bytes")
    print("Created:", datetime.fromtimestamp(stat.st_ctime))
    print("Modified:", datetime.fromtimestamp(stat.st_mtime))
    print("Accessed:", datetime.fromtimestamp(stat.st_atime))
    print("Absolute Path:", os.path.abspath(file_path))
    print("File Extension:", os.path.splitext(file_path)[1])
    print("Is Directory:", os.path.isdir(file_path))
    print("Is File:", os.path.isfile(file_path))
    try:
        with open(file_path, 'rb') as f:
            first_bytes = f.read(10)
            print("First 10 bytes (hex):", first_bytes.hex())
    except Exception as e:
        print(f"Could not read file: {e}")
