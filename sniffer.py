import time
import scapy.all as sc
import matplotlib.pyplot as plt

from typing import IO, List, Tuple

class Analyzer:
    @staticmethod
    def speed(plot: bool = False, nb_iter: int = 100) -> None:
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

if __name__ == "__main__":
    Analyzer.speed(plot=True)
