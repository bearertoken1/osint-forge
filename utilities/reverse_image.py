import webbrowser


def reverse_image_search(image_path):
    print("[+] Reverse Image Search Links (manual upload required):")
    print("Google: https://images.google.com/")
    webbrowser.open("https://images.google.com/")
    print("Yandex: https://yandex.com/images/")
    webbrowser.open("https://yandex.com/images/")
    print("Bing: https://www.bing.com/visualsearch")
    webbrowser.open("https://www.bing.com/visualsearch")
    print("TinEye: https://tineye.com/")
    webbrowser.open("https://tineye.com/")
    print("Upload your image to these services for best results.")
    print(f"Image path provided: {image_path}")
