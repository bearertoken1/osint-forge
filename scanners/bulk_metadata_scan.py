from PIL import Image
from PIL.ExifTags import TAGS
import os


def extract_metadata(file_path):
    """
    Extract metadata from an image file.
    """
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        if exif_data:
            metadata = {TAGS.get(tag, tag): value for tag, value in exif_data.items()}
            return metadata
        return None
    except Exception as e:
        print(f"[!] Error extracting metadata from {file_path}: {e}")
        return None


def bulk_metadata_scan(directory):
    """
    Perform bulk metadata scanning for all images in a directory.
    """
    print(f"[+] Scanning directory for metadata: {directory}")
    results = {}

    try:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file.lower().endswith((".jpg", ".jpeg", ".png")):
                    metadata = extract_metadata(file_path)
                    if metadata:
                        results[file_path] = metadata

        print(f"[+] Metadata extracted from {len(results)} files.")
    except Exception as e:
        print(f"[!] Error during bulk metadata scan: {e}")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bulk Metadata and Exif Data Scanner")
    parser.add_argument("directory", help="Directory containing images to scan")
    args = parser.parse_args()

    bulk_metadata_scan(args.directory)
