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
    print("\tIP Address\t\t\tMAC Address\t\tInfo")
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

def run():
    arp = scan()
    print("--------------\n--------------")
    while (1):
        mode: str = input("1- Sniffing 2- Spoofing 3- Data transfers 4- Domains\n")
        try:
            if int(mode) == 1:
                net: str = input("Choose what to sniff: (type 'all' to sniff all) ")
                if net.lower() != 'all':
                    target_mac = arp[0][int(net)]
                    target_ip = arp[1][target_mac]
                    print(f"Sniffing {target_ip} {target_mac}...")
                    Analyzer.sniff(target_ip, target_mac)
                else:
                    print(f"Sniffing all...")
                    Analyzer.sniff()
            if int(mode) == 2:
                net: str = input("Choose what to spoof: ")
                target_mac = arp[0][int(net)]
                target_ip = arp[1][target_mac]
                Analyzer.spoof(target_ip)
                exit()
            if int(mode) == 3:
                Analyzer.speed(plot=True)
                exit()
            if int(mode) == 4:
                Analyzer.domains(plot=True)
                exit()
        except:
            print("Wrong entry")

if __name__ == "__main__":
    run()
