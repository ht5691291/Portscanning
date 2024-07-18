#!/bin/python3
from scapy.all import *
import re

try:
    target_host = input("Please enter the target host address: ")

    # Ask the user if they want to scan all ports
    scan_all_ports = input("Do you want to scan all ports? (y/n): ").lower()
    if scan_all_ports == 'y':
        port_list = range(1, 65536)  # Scan all ports
    else:
        port_input = input("Enter the ports you want to scan (separated by commas): ")
        port_list = [int(port) for port in port_input.split(",")]

    # Ask the user if they want to save the output to a text file
    save_to_file = input("Do you want to save the output to a text file? (y/n): ").lower()

    # Ask the user which scan method they want to use
    scan_method = input("Which scan method do you want to use? (syn/ack): ").lower()

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_host):
        print("\nInitiating Scan...")
        print("Target Host:", target_host)
        print("Ports to Scan:", port_list)

        answered, unanswered = sr(IP(dst=target_host) / TCP(dport=port_list, flags=scan_method[0].upper()), verbose=0, timeout=2)

        for sent_packet, received_packet in answered:
            if received_packet.haslayer(TCP) and received_packet.getlayer(TCP).flags == 0x12:
                print("[+] Port {} is Open".format(sent_packet[TCP].dport))
                # Service and Version Scanning
                response = sr1(IP(dst=target_host) / TCP(dport=sent_packet[TCP].dport, flags="S"), timeout=1, verbose=0)
                if response:
                    if response.haslayer(TCP):
                        if response.getlayer(TCP).flags == 0x12:
                            send_rst = sr(IP(dst=target_host) / TCP(dport=sent_packet[TCP].dport, flags="R"), timeout=1, verbose=0)
                            print("[*] Service:", response.sprintf("%TCP.sport%"))
                        elif response.getlayer(TCP).flags == 0x14:
                            print("[*] Service: Closed")
            

        if save_to_file == 'y':
            with open("port_scan_output.txt", "w") as file:
                for sent_packet, received_packet in answered:
                    if received_packet.haslayer(TCP) and received_packet.getlayer(TCP).flags == 0x12:
                        file.write("[+] Port {} is Open\n".format(sent_packet[TCP].dport))
                    else:
                        file.write("[-] Port {} is Closed\n".format(sent_packet[TCP].dport))
            print("Scan results saved to port_scan_output.txt")

except (ValueError, RuntimeError, TypeError, NameError):
    print("[-] An Error Occurred During the Scan")
    print("[-] Exiting Scan...")
