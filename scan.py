import manuf
from sniffer import Analyzer
from scapy.all import ARP, Ether, srp

from typing import Dict, Tuple, List

def scan() -> Tuple[List[str], Dict[str, str]]:
    target_ip: str = "192.168.1.0/24"
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []

    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("IP Address\t\t\tMAC Address\t\t\tInfo")
    print("----------------------------------------------------------------------------")

    vendor = manuf.MacParser()
    ret_mac: List[str] = []
    ret_arp: Dict[str, str] = dict()
    k: int = 0
    for device in devices:
        ret_mac.append(device['mac'])
        ret_arp[device['mac']] = device['ip']
        print(f"{k} -> {device['ip']} \t\t {device['mac']} \t\t {vendor.get_manuf(device['mac'])}")
        k+=1
    return ret_mac, ret_arp

arp = scan()
print("--------------\n--------------")

net: str = input("choose what to sniff: (type 'all' to sniff all) ")
if net.lower() != 'all':
    target_mac = arp[0][int(net)]
    target_ip = arp[1][target_mac]
    print(f"sniffing {target_ip} {target_mac}...")
else:
    print(f"sniffing all...")

Analyzer.sniff()
