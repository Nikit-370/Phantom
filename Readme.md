# Phantom Framework

The **Phantom Framework** is a collection of Python scripts designed for various network security and penetration testing tasks. This framework includes tools for Brute Force attacks, Subdomain discovery, Banner Grabbing, Packet Sniffing, Directory Discovery, Network Scanning, and ARP Spoofing.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Tools](#tools)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Before using these tools, ensure you have the following prerequisites:

- Python 3.x installed on your system.
- Required Python packages, which can be installed using `pip`:
  - `requests`
  - `colorama`
  - `paramiko`
  - `termcolor`
  - `scapy`
  - `IPy`

## Usage

1. Clone or download this repository to your local machine.

2. Open a terminal or command prompt.

3. Navigate to the directory where the Phantom Framework scripts are located.

4. Run a specific script by executing `python script_name.py`, where `script_name.py` is the name of the script you want to use. Follow the on-screen instructions to provide any required input.

5. You can choose from various tools provided in the framework, such as Brute Force, Subdomain Finder, Banner Grabbing, Packet Sniffer, Directory Discovery, Network Scanner, and ARP Spoofing.

## Tools

### Brute Force

The Brute Force tool allows you to perform SSH brute force attacks to discover login credentials for a target.

### Subdomain Finder

The Subdomain Finder tool discovers subdomains associated with a target domain by querying the ThreatCrowd API.

### Banner Grabbing

The Banner Grabbing tool retrieves banners from common ports on a target host to identify services and software running on those ports.

### Packet Sniffer

The Packet Sniffer tool captures network packets and attempts to extract login credentials from HTTP traffic.

### Directory Discovery

The Directory Discovery tool scans a target URL for common directory names to identify accessible directories.

### Network Scanner

The Network Scanner tool scans a target IP address for open ports to identify potential vulnerabilities.

### ARP Spoofing

The ARP Spoofing tool allows you to perform ARP spoofing attacks to intercept network traffic between a target and a router.

## Contributing

Contributions to the Phantom Framework are welcome! If you have ideas for additional features or improvements, please open an issue or submit a pull request.

## License

The Phantom Framework is open-source and available under the [MIT License](LICENSE).

**Note:** Use these tools responsibly and only on systems and networks you have permission to test and assess. Unauthorized use is prohibited and may be illegal.
