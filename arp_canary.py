#!/usr/bin/env python
# -*- coding: utf-8 -*-
import scapy.all as scapy

interface = "tun0"
verbose = True


class ARPcanary:

    @staticmethod
    def get_mac(ip):
        arprequest = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arprequest_broadcast = broadcast / arprequest
        answered = scapy.srp(arprequest_broadcast,
            timeout=2,
            verbose=True)[0]
        return answered[0][1].hwsrc

    def sniff(self, iface):
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

    def _spoof(self, target_ip, spoof_ip):
        target_mac = self.get_mac(target_ip)
        packet = scapy.ARP(op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip)
        scapy.send(packet, verbose=verbose)

    def _restore(self, destination, source):
        dest_mac = self.get_mac(destination)
        source_mac = self.get_mac(source)
        packet = scapy.ARP(op=2,
            pdst=destination,
            hwdst=dest_mac,
            psrc=source,
            hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=verbose)


if __name__ == "__main__":
    print("[*] Beginning ARP spoof detection")
    snitch = ARPsnitch()
    snitch.sniff(interface)
    print("[*] Complete")
