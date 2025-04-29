import sys
import subprocess
import socket
import random
import psutil
from scapy.all import ARP, Ether, srp
import manuf
import os
import nmap  # Import nmap library

# Function to install missing packages via pip
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Function to install nmap if it's not found
def install_nmap():
    if sys.platform.startswith('linux'):
        subprocess.check_call(['sudo', 'apt-get', 'install', '-y', 'nmap'])
    elif sys.platform.startswith('darwin'):
        subprocess.check_call(['brew', 'install', 'nmap'])
    elif sys.platform.startswith('win'):
        subprocess.check_call(['choco', 'install', 'nmap'])  # If you use Chocolatey package manager
    else:
        print("Unsupported platform, please install nmap manually.")

# Function to check and install necessary dependencies
def check_and_install_dependencies():
    required_libraries = ['scapy', 'psutil', 'manuf', 'python-nmap']
    
    # Ensure that python-nmap is installed
    try:
        __import__('nmap')
    except ImportError:
        print("'python-nmap' library is not installed. Installing...")
        install_package('python-nmap')

    # Check if nmap is installed
    try:
        subprocess.check_call(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("'nmap' is not installed. Installing...")
        install_nmap()  # Install nmap if not found

    # Ensure the other required Python libraries are installed
    for library in required_libraries:
        try:
            __import__(library)
            print(f"'{library}' is already installed.")
        except ImportError:
            print(f"'{library}' is not installed. Installing...")
            install_package(library)

check_and_install_dependencies()

# Function to check if the script is running with sudo privileges
def check_sudo():
    if os.geteuid() != 0:
        print("This script requires sudo privileges to access network connections.")
        print("Please enter your password to proceed.")
        python_path = sys.executable  # Get the path to the current Python executable
        subprocess.check_call(['sudo', python_path] + sys.argv)  # Re-run the script with sudo privileges
        sys.exit(0)

check_sudo()

# Function to get the router's IP address (default gateway)
def get_router_ip():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                # Default gateway is typically the router's IP address
                route = psutil.net_if_stats()
                for route_info in psutil.net_if_stats().values():
                    if 'default' in route_info:
                        return route_info['gateway']
    return None

# Function to scan the router's firewall using Nmap
def scan_router_firewall(router_ip):
    nm = nmap.PortScanner()
    print(f"Scanning the router {router_ip} for open ports to infer firewall type...")

    try:
        # Run nmap scan on common ports (HTTP, HTTPS, SSH, etc.) with a timeout of 10 seconds
        nm.scan(router_ip, '22,80,443,53,4433', timeout=10)
        firewall_info = "Unknown"
        
        if 'scan' in nm[router_ip]:
            open_ports = nm[router_ip]['scan'].keys()
            if len(open_ports) == 0:
                firewall_info = "Highly likely behind a firewall (all ports closed)"
            elif 80 in open_ports or 443 in open_ports:
                firewall_info = "Possible firewall with HTTP/HTTPS filtering"
            elif 22 in open_ports:
                firewall_info = "Possible firewall with SSH access"
            else:
                firewall_info = "Firewall detected with open ports"
        else:
            firewall_info = "No response from router"
        
        return firewall_info
    except Exception as e:
        print(f"Error during nmap scan: {e}")
        return "Scan failed"

# Function to get the actual IP address of the machine on the local network
def get_local_ip():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                return addr.address  # Return the first non-loopback IPv4 address
    return None  # No local IP found

# Function to calculate the network range (assuming a /24 subnet)
def get_ip_range():
    local_ip = get_local_ip()
    if local_ip is None:
        print("Could not find a local IP address.")
        return None

    ip_parts = local_ip.split('.')
    network_range = f'{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24'  # Class C range assumption
    print(f"Scanning network range: {network_range}")
    return network_range

# Function to calculate distance based on RSSI
def calculate_distance(rssi, A=-30, n=2.5):
    if rssi == 0:
        return float("inf")
    distance = 10 ** ((A - rssi) / (10 * n))
    return distance

# Function to get vendor from MAC address
def get_vendor(mac):
    try:
        vendor = manuf.manuf(mac)
        return vendor if vendor else "Unknown"
    except Exception as e:
        print(f"Error getting vendor for {mac}: {str(e)}")
        return "Unknown"

# Function to get the RSSI (Signal Strength) for a device (simulated)
def get_rssi(ip):
    return random.randint(-90, -30)  # Simulated RSSI values between -90 and -30 dBm

# Function to get device name from IP address
def get_device_name(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"

# Function to scan the network using ARP requests
def scan_network(ip_range):
    print(f"Scanning network range: {ip_range}")
    
    # Create ARP request packet
    arp_request = ARP(pdst=ip_range)
    ether_request = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether_request/arp_request
    
    # Send the packet and receive responses (timeout set to 15 seconds)
    result = srp(packet, timeout=15, verbose=False)[0]  # Increased timeout to 15 seconds
    
    devices = []
    scanned_ips = 0  # Variable to count scanned IPs
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_vendor(mac)
        rssi = get_rssi(ip)
        distance = calculate_distance(rssi)
        device_name = get_device_name(ip)
        
        devices.append({'ip': ip, 'mac': mac, 'vendor': vendor, 'rssi': rssi, 
                        'distance (m)': distance, 'name': device_name})
        
        scanned_ips += 1  # Increment the scanned IP count
    
    print(f"\nScanned {scanned_ips} IPs.")
    return devices

# Function to display device details with their active connection destinations and firewall info
def display_devices(devices):
    print(f"{'Device Name':<25}{'IP Address':<20}{'MAC Address':<20}{'Vendor':<25}{'RSSI (dBm)':<15}{'Distance (m)':<15}")
    print("-" * 150)  # Adjust the separator length based on new column widths
    
    for device in devices:
        print(f"{device['name']:<25}{device['ip']:<20}{device['mac']:<20}{device['vendor']:<25}{device['rssi']:<15}{device['distance (m)']:<15.2f}")

# Main function to start scanning and displaying devices
def main():
    ip_range = get_ip_range()
    if ip_range is None:
        print("Unable to detect network range. Exiting.")
        return
    
    devices = scan_network(ip_range)  # Scan the network
    
    if not devices:
        print("No devices found.")
    else:
        display_devices(devices)  # Display the devices
    
    # Get router IP address (default gateway)
    router_ip = get_router_ip()
    if router_ip is None:
        print("Unable to detect router IP address. Exiting.")
        return
    
    # Scan the router's firewall
    firewall_info = scan_router_firewall(router_ip)
    print(f"\nRouter Firewall Info ({router_ip}): {firewall_info}")

if __name__ == "__main__":
    main()
