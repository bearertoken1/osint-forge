def run(phone):
    print(f"[+] Phone OSINT: {phone}")
    if phone.startswith("+1"):
        print("-> North America")
    elif phone.startswith("+44"):
        print("-> United Kingdom")
    elif phone.startswith("+91"):
        print("-> India")
    elif phone.startswith("+81"):
        print("-> Japan")
    else:
        print("-> Unknown prefix. Try Google search or TrueCaller.")
