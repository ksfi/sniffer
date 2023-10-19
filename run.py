from sniffer import Analyzer
from scan import Scan

def run():
#     TODO: argparse
#     parser = argparse.ArgumentParser(description="Network Monitoring Script")
# 
#     parser.add_argument("--sniff", action="store_true", help="Sniff network traffic")
#     parser.add_argument("--spoof", action="store_true", help="Spoof network")
#     parser.add_argument("--data-transfers", action="store_true", help="Analyze data transfers")
#     parser.add_argument("--domains", action="store_true", help="Analyze domains")
# 
#     args = parser.parse_args()
# 
#     if args.sniff:
#         pass
#     elif args.spoof:
#         pass
#     elif args.data_transfers:
#         pass
#     elif args.domains:
#         pass
#     else:
#         pass

    while (1):
        print("\nWatching the network...")
        arp = Scan.scan()
        # TODO switch to arp_cache
        devices: int = len(arp[0])
        if devices == 0:
            print("No activity detected on the network")
        print("--------------\n--------------")
        mode: str = input("\n1- Sniffing 2- Spoofing 3- Data transfers 4- Domains 5- ARP cache r- Refresh\n--> ")
        try:
            if int(mode) == 1:
                if devices > 0:
                    net: str = input("Choose what to sniff: (type 'all' to sniff all) ")
                else:
                    net: str = 'all'
                if net.lower() != 'all':
                    target_mac = arp[0][int(net)]
                    target_ip = arp[1][target_mac]
                    print(f"Sniffing {target_ip} {target_mac}...")
                    Analyzer.sniff(target_ip, target_mac)
                else:
                    print(f"Sniffing all...")
                    Analyzer.sniff()
            if int(mode) == 2:
                if devices == 0:
                    print("Nothing to spoof...")
                    target_mac = arp[0][int(net)]
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
            if int(mode) == 5:
                Scan.arp_cache()
        except:
            if mode == 'r':
                print("Refreshing...")
            else:
                print("Wrong entry")

if __name__ == "__main__":
#     Scan.arp_cache()
    run()
