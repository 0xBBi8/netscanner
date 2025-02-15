#!/usr/bin/env python3

import requests
import socket
import ipaddress
import subprocess
import struct
import platform
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Number of threads for scanning
THREADS = 50

ASCII_LOGO = """
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
Netscanner by 0xBBi8
"""


def get_public_ip():
    """ Retrieves the public IP address using an external service. """
    try:
        response = requests.get("https://api64.ipify.org?format=text", timeout=5)
        return response.text.strip()
    except requests.RequestException:
        return "Unknown"


def get_local_ip():
    """ Retrieves the local IP address of the machine. """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    return s.getsockname()[0]


def get_subnet_mac(interface):
    """ Retrieves the subnet on macOS by extracting and converting the netmask from hex. """
    try:
        result = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
        ip, netmask_hex = None, None
        for line in result.stdout.split("\n"):
            if "inet " in line and "netmask" in line:
                parts = line.split()
                ip = parts[1]  # Local IP
                netmask_hex = parts[3]  # Hexadecimal netmask (e.g., 0xffffff00)
                break

        if ip and netmask_hex:
            # Convert netmask from hex to decimal
            netmask = socket.inet_ntoa(struct.pack(">I", int(netmask_hex, 16)))
            subnet = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(subnet)
    except Exception:
        pass
    return "Unknown"


def icmp_ping(ip):
    """ Pings a device to check if it is online. """
    system = platform.system()
    cmd = ["ping", "-c", "1", ip] if system == "Darwin" else ["ping", "-n", "-c", "1", ip]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def get_hostname(ip):
    """ Attempts to retrieve the hostname/DNS name of a device if available. """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown hostname"


def write_output(output_data, filepath):
    """ Saves the scanning results to the specified file path. """
    try:
        with open(filepath, "w") as file:
            file.write(output_data)
        print(f"[+] Results saved to {filepath}")
    except Exception as e:
        print(f"[-] Error saving results: {e}")


def main():
    """ Main function that initiates the network scan in the correct order. """
    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument("-O", "--output", help="Save output to a specified file path", type=str)
    args = parser.parse_args()

    print(ASCII_LOGO)

    public_ip = get_public_ip()
    local_ip = get_local_ip()
    subnet = get_subnet_mac("en8")  # Specify the correct interface (you showed it was en8)

    output_data = []
    output_data.append("--------------------------------------------------")
    output_data.append("                Network Scanner                   ")
    output_data.append("--------------------------------------------------")
    output_data.append(f"Public IP  : {public_ip}")
    output_data.append(f"Local IP   : {local_ip}")
    output_data.append(f"Subnet     : {subnet}")
    output_data.append("--------------------------------------------------\n")

    print("\n".join(output_data))

    # Generate all IP addresses in the network
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        ips = [str(ip) for ip in network.hosts()]
    except ValueError:
        print("[!] Subnet calculation failed. Check your configuration.")
        return

    # Create a thread pool for parallel scanning
    active_hosts = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(icmp_ping, ip): ip for ip in ips}

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    hostname = get_hostname(ip)
                    output_line = f"[+] {ip} is online - {hostname}"
                    print(output_line)
                    output_data.append(output_line)
                    active_hosts.append(ip)
            except Exception as e:
                print(f"[-] Error scanning {ip}: {e}")

    if not active_hosts:
        output_data.append("\n[!] No active devices found via ping.")
    else:
        output_data.append(f"\n[+] A total of {len(active_hosts)} active devices were found.")
    output_data.append("--------------------------------------------------")

    if args.output:
        write_output("\n".join(output_data), args.output)


if __name__ == "__main__":
    main()