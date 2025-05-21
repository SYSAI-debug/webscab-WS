#!/usr/bin/env python3
"""
...
---------------------------------------------------------------------
...
---------------------------------------------------------------------
"""

import socket
import sys
import threading
from time import time

# Lock for thread-safe printing
print_lock = threading.Lock()

def scan_port(ip, port, timeout=1):
    """
    Attempt to connect to a given port on the target IP address.
    If successful, print that the port is open and try to grab a banner.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        with print_lock:
            print(f"[+] Port {port} is open")
        try:
            banner = s.recv(1024).decode('utf-8').strip()
            if banner:
                with print_lock:
                    print(f"    Banner: {banner}")
        except Exception:
            pass
        s.close()
    except Exception:
        pass

def port_scan(ip, start_port, end_port):
    """
    Scan a range of ports on the target IP using multithreading.
    """
    threads = []
    start_time = time()
    for port in range(start_port, end_port+1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(f"\nScanning complete in {time() - start_time:.2f} seconds")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_IP>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    print(f"Starting vulnerability scan on {target_ip}...")
    # Scan ports 1 to 1024. Change this range as needed.
    port_scan(target_ip, 1, 1024)

if __name__ == "__main__":
    main()
