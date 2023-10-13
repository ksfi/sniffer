import manuf
from scapy.all import ARP, Ether, srp

from typing import Dict, Tuple, List

class Scan:
    @staticmethod
    def arp_dynamic() -> Tuple[List[str], Dict[str, str]]:
        target_ip: str = "192.168.1.0/24"
        devices: List[Dict[str, str]] = []
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("\n\tIP Address\t\t\tMAC Address\t\tInfo")
        print("----------------------------------------------------------------------------")
        vendor = manuf.MacParser()
        ret_mac: List[str] = []
        ret_arp: Dict[str, str] = dict()
        for k, device in enumerate(devices):
            ret_mac.append(device['mac'])
            ret_arp[device['mac']] = device['ip']
            print(f"{k} -> {device['ip']} \t\t {device['mac']} \t\t {vendor.get_manuf(device['mac'])}")
        return ret_mac, ret_arp

    @staticmethod
    def arp_cache() -> Tuple[List[str], Dict[str, str]]:
        import subprocess
        result: str = subprocess.check_output("arp -a", shell=True, text=True)
        arp_cache: List[str] = result.strip().split('\n')

        print("\n\tIP Address\t\t\tMAC Address\t\tInfo")
        print("----------------------------------------------------------------------------")
        vendor = manuf.MacParser()
        ret_mac: List[str] = []
        ret_arp: Dict[str, str] = dict()
        for k, entry in enumerate(arp_cache):
            spl: str = entry.split(' ')
            ret_mac.append(spl[3])
            ret_arp[spl[3]] = spl[1][1:-1]
            print(f"{k} -> {spl[1][1:-1]} \t\t {spl[3]} \t\t {vendor.get_manuf(spl[3])}")
        return ret_mac, ret_arp

if __name__ == "__main__":
    Scan.arp_cache()
