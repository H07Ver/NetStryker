# Network Scanning and Device Information Tool
## Project Description
This Python script is designed to scan a local network, detect devices, and provide detailed information about each device such as its IP address, MAC address, vendor, RSSI (signal strength), and estimated distance from the scanning device. The script also scans the router's firewall to detect open ports and infers firewall types. Additionally, it checks for necessary dependencies like nmap, psutil, and scapy, installing them if they are missing.

This tool is meant for network administrators, cybersecurity professionals, and educational purposes in controlled environments. It can be used to discover devices on the local network and inspect the security of network infrastructure, including firewall configurations.

## Key Features:
Network Scanning: Scans a local network range to identify connected devices and retrieve their details such as IP, MAC, vendor, RSSI, and distance.
Router Firewall Scan: Analyzes the router's firewall for open ports to infer firewall type and security status.
Device Information: Provides detailed information about each device on the network, including device names (if available), MAC addresses, vendors, signal strength (RSSI), and approximate distance from the scanning device.
Dependency Management: Automatically installs required libraries (scapy, psutil, manuf, and nmap), ensuring all dependencies are present before running the script.

## Prerequisites:
Python 3.x
scapy library
psutil library
manuf library (for vendor lookup from MAC addresses)
python-nmap library
nmap tool (installed automatically if not found)
sudo privileges for accessing network interfaces and performing system-level operations
Installation Instructions
Clone the repository:

```bash
git clone https://github.com/yourusername/network-scanning-tool.git
cd network-scanning-tool
```
Install required dependencies: This script checks and installs any missing dependencies, so simply running the script will handle it automatically.

However, if you prefer to install the dependencies manually, use the following commands:

```bash
pip install scapy psutil manuf python-nmap
```
nmap will be installed automatically by the script if it's not found on your system.

Run the script: Once the dependencies are installed, you can run the script with:

```bash
python network_scanning_tool.py
```
Permissions: The script requires sudo privileges to access network interfaces and perform network scans. If the script detects that it is not running with sudo privileges, it will prompt you to enter your password and automatically re-run the script with elevated permissions.

## How It Works
Dependency Check: The script first checks if the necessary Python packages (scapy, psutil, manuf, and python-nmap) are installed. If any package is missing, it installs them using pip. It also verifies if nmap is installed and installs it based on the operating system.

Network Scan: The script scans the local network range to find devices connected to the network using ARP requests. For each device, it collects:

IP Address
MAC Address
Vendor Information (using the MAC address)
RSSI (Signal Strength)
Estimated Distance from the scanning machine
Router Firewall Scan: It scans the router (default gateway) for open ports and tries to determine the firewall type based on which ports are open. Common ports such as HTTP (80), HTTPS (443), SSH (22), and others are checked.

Displaying Results: The script displays a list of detected devices on the network with the collected information, including the firewall status of the router.

## Example Output
```bash
Scanning network range: 192.168.1.1/24
Scanned 10 IPs.

Device Name              IP Address        MAC Address        Vendor                RSSI (dBm)   Distance (m)
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Device1                  192.168.1.2       00:14:22:01:23:45  Cisco Systems         -52          10.2
Device2                  192.168.1.3       00:25:96:67:89:01  Samsung Electronics   -64          15.5
...
Scanning the router 192.168.1.1 for open ports to infer firewall type...
Router Firewall Info (192.168.1.1): Possible firewall with HTTP/HTTPS filtering
```

## Dependencies
This script uses the following libraries:

psutil: Used to gather network interface details (IP addresses and network statistics).
scapy: Used for crafting and sending ARP requests to discover devices on the network.
manuf: Used for identifying the vendor of a device based on its MAC address.
nmap: Used for scanning the router's firewall to detect open ports.
python-nmap: Python library to interact with Nmap for automated scanning.

## Notes:
Be cautious when running network scanning tools, as scanning networks without permission can be illegal and unethical.
This script should only be used on networks where you have explicit permission to conduct scanning or testing.
Ensure you have backups of any important data before performing network scanning or any other potentially destructive actions.

## Legal Disclaimer
The creator of this tool disclaims any liability for the consequences of using it on unauthorized networks or systems. Use this script only for ethical, educational, or authorized testing purposes.

By running this tool, you acknowledge that you are responsible for any actions taken and must comply with all local laws and regulations related to network scanning and penetration testing.
