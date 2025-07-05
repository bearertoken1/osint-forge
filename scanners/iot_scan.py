import socket

def iot_device_scan(ip_range, ports=[80, 443, 8080, 1883]):
    """
    Scan for IoT devices and network services in the given IP range.
    """
    print(f"[+] Scanning IP range: {ip_range}")
    results = []

    try:
        for ip in ip_range:
            for port in ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            print(f"[+] Open port {port} on {ip}")
                            results.append((ip, port))
                except Exception as e:
                    print(f"[!] Error scanning {ip}:{port} - {e}")

        print(f"[+] Total open ports found: {len(results)}")
    except Exception as e:
        print(f"[!] Error during IoT device scan: {e}")

    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IoT Device and Network Service Scanner")
    parser.add_argument("ip_range", nargs='+', help="List of IPs to scan")
    parser.add_argument("-p", "--ports", nargs='+', type=int, default=[80, 443, 8080, 1883], help="Ports to scan")
    args = parser.parse_args()

    iot_device_scan(args.ip_range, args.ports)
