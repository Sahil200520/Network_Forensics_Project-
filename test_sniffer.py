import sys
import os
import json

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR
import probe_sniffer

def create_sample_pcap(filepath):
    packets = []
    
    # 1. ARP packet
    arp_pkt = Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op="who-has", hwsrc="11:22:33:44:55:66", psrc="192.168.1.50",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.1"
    )
    packets.append(arp_pkt)
    
    # 2. IPv4 TCP packet
    tcp_pkt = Ether(src="11:22:33:44:55:66", dst="66:55:44:33:22:11") / IP(
        src="192.168.1.50", dst="8.8.8.8"
    ) / TCP(sport=12345, dport=443, seq=1000)
    packets.append(tcp_pkt)
    
    # 3. DNS query packet (Layer 7 test)
    dns_pkt = Ether(src="11:22:33:44:55:66", dst="66:55:44:33:22:11") / IP(
        src="192.168.1.50", dst="8.8.8.8"
    ) / UDP(sport=5353, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="threat-actor-command.ru")
    )
    packets.append(dns_pkt)
    
    # 4. HTTP Host packet (Layer 7 test)
    http_payload = b"GET /admin/login HTTP/1.1\r\nHost: insecure-portal.org\r\nUser-Agent: python\r\n\r\n"
    http_pkt = Ether(src="11:22:33:44:55:66", dst="66:55:44:33:22:11") / IP(
        src="192.168.1.50", dst="8.8.8.8"
    ) / TCP(sport=51221, dport=80, seq=2000) / Raw(load=http_payload)
    packets.append(http_pkt)
    
    # 5. Handcrafted authentic TLS Client Hello packet (Layer 7 SNI test)
    # Total length: 5 (Record) + 4 (Handshake) + 2 (Version) + 32 (Random) + 1 (SessionID length) 
    # + 4 (Cipher Suites) + 2 (Compression) + 2 (Extensions Length) + 29 (SNI Ext) = 81 bytes
    tls_payload = (
        b"\x16\x03\x01\x00\x5a"  # TLS Record: Handshake, Version 3.1, Length 90
        b"\x01\x00\x00\x56"      # Handshake: Client Hello, Length 86
        b"\x03\x03"              # Version 3.3 (TLS 1.2)
        + b"\x00" * 32           # 32 bytes of random bytes
        + b"\x00"                # Session ID Length: 0
        b"\x00\x02\x00\x2f"      # Cipher Suites Length: 2, Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
        b"\x01\x00"              # Compression Methods Length: 1, Method: null
        b"\x00\x2d"              # Extensions Length: 45
        b"\x00\x00"              # Extension Type: Server Name
        b"\x00\x19"              # Extension Length: 25
        b"\x00\x17"              # Server Name List Length: 23
        b"\x00"                  # Server Name Type: host_name (0)
        b"\x00\x14"              # Server Name Length: 20
        + b"malicious-site20.com"  # Hostname string (exactly 20 bytes)
    )
    # Pad to match record header length field
    tls_payload += b"\x00" * (95 - len(tls_payload))

    tls_pkt = Ether(src="11:22:33:44:55:66", dst="66:55:44:33:22:11") / IP(
        src="192.168.1.50", dst="8.8.8.8"
    ) / TCP(sport=51222, dport=443, seq=3000) / Raw(load=tls_payload)
    packets.append(tls_pkt)
    
    # Write to PCAP
    wrpcap(filepath, packets)
    print(f"Created industrial mock PCAP file with {len(packets)} packets at {filepath}")

def main():
    pcap_path = "mock_capture_industrial.pcap"
    create_sample_pcap(pcap_path)
    
    parsed_packets = []
    def collector(data):
        parsed_packets.append(data)
        
    print("\nParsing PCAP file with BPF filter...")
    # Test start_sniffer with BPF filter parameter
    probe_sniffer.start_sniffer(
        pcap_file=pcap_path,
        bpf_filter="tcp or udp or arp",
        packet_handler=collector
    )
    
    print("\nParsed Packet Schema Results:")
    print(json.dumps(parsed_packets, indent=2))
    
    # Basic assertions
    assert len(parsed_packets) == 5
    
    # ARP assertion
    p1 = parsed_packets[0]
    assert p1["layer4"]["protocol"] == "ARP"
    
    # TCP assertion
    p2 = parsed_packets[1]
    assert p2["layer4"]["protocol"] == "TCP"
    
    # DNS L7 assertion
    p3 = parsed_packets[2]
    assert p3["layer4"]["protocol"] == "UDP"
    assert p3["layer7"]["dns_query"] == "threat-actor-command.ru"
    
    # HTTP Host L7 assertion
    p4 = parsed_packets[3]
    assert p4["layer4"]["protocol"] == "TCP"
    assert p4["layer7"]["http_host"] == "insecure-portal.org"
    
    # TLS SNI L7 assertion
    p5 = parsed_packets[4]
    assert p5["layer4"]["protocol"] == "TCP"
    assert p5["layer7"]["tls_sni"] == "malicious-site20.com"
    
    print("\nAll Ingestion and L7 parsing assertions PASSED! Industrial-grade sniffer is fully functional.")
    
    # Clean up
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

if __name__ == "__main__":
    main()
