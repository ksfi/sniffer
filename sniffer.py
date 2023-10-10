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
    pass
