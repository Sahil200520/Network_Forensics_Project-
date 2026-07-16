# PROBE Passive Network Forensics & Mitigation Engine
## Implementation & Walkthrough Report (Phases 1 & 2)

This document provides a comprehensive overview of the design, code structures, and test walkthroughs for both **Phase 1: Ingestion & Parsing Engine** and **Phase 2: Mitigation & Active Defense Engine** of the **PROBE** system.

---

# Phase 1: Ingestion & Parsing Engine

## 1. Overview & Architecture
Phase 1 focuses on high-speed, thread-safe network ingestion. The ingestion engine is designed using a **Producer-Consumer architecture** to isolate packet capture from dissection, ensuring zero packet drops during burst traffic:

1. **Producer (Capture Thread)**: Uses Scapy to capture raw packet frames from a live interface (using `AsyncSniffer`) or sequential buffers from an offline PCAP file. It instantly transfers captured objects to a thread-safe FIFO `queue.Queue`.
2. **Consumer (Worker Thread)**: Extracts and parses Layer 2 (MAC) and Layer 3/4 header metadata, normalizes it to the Phase 1 target schema, and forwards the JSON-compatible structure to the designated output handler.
3. **Privilege validation**: Validates root/sudo scope for live captures, automatically skipping it for local file analysis.

## 2. Phase 1 Implementation Code
The source code is located at [probe_sniffer.py](file:///c:/Users/aswin/Desktop/Network%20Forences/probe_sniffer.py).

### Core Components:
- **`check_privileges()`**: Asserts Unix root (`os.getuid() == 0`) or Windows Administrator status.
- **`parse_packet(packet, interface_name)`**: Normalizes packet data into:
  - **Timestamp**: Converted from packet Unix time to `"YYYY-MM-DD HH:MM:SS.ffffff"`.
  - **Layer 2**: extracts `src_mac` and `dst_mac` for Ethernet and IEEE 802.3 packets.
  - **Layer 3**: Identifies IPv4 and IPv6 addresses. Integrates ARP address discovery by mapping ARP `psrc` and `pdst` to `src_ip` and `dst_ip` under Layer 3 for forensics utility.
  - **Layer 4**: Extracts transport protocols (`TCP`, `UDP`, `ICMP`, `ARP`, or `OTHER`) and port numbers (`src_port`, `dst_port`).
- **`ProbeSniffer`**: Encapsulates thread management, background parsing loops, and safe shutdown sentinels.

## 3. Phase 1 Verification & Walkthrough
To verify Phase 1, we executed [test_probe_sniffer.py](file:///C:/Users/aswin/.gemini/antigravity-ide/brain/3c014cc1-86d5-4631-8b48-457ed7b16815/scratch/test_probe_sniffer.py), which builds a mock PCAP containing ARP, TCP, UDP, ICMP, and IPv6 traffic and processes it:

### Test Outputs:
```json
[
  {
    "timestamp": "2026-07-16 10:01:22.898694",
    "network_interface": "mock_capture.pcap",
    "layer2": {
      "src_mac": "11:22:33:44:55:66",
      "dst_mac": "ff:ff:ff:ff:ff:ff"
    },
    "layer3": {
      "ip_version": 4,
      "src_ip": "192.168.1.50",
      "dst_ip": "192.168.1.1"
    },
    "layer4": {
      "protocol": "ARP",
      "src_port": null,
      "dst_port": null
    },
    "packet_size_bytes": 42
  },
  {
    "timestamp": "2026-07-16 10:01:22.899042",
    "network_interface": "mock_capture.pcap",
    "layer2": {
      "src_mac": "11:22:33:44:55:66",
      "dst_mac": "66:55:44:33:22:11"
    },
    "layer3": {
      "ip_version": 4,
      "src_ip": "192.168.1.50",
      "dst_ip": "8.8.8.8"
    },
    "layer4": {
      "protocol": "TCP",
      "src_port": 12345,
      "dst_port": 443
    },
    "packet_size_bytes": 54
  },
  {
    "timestamp": "2026-07-16 10:01:22.899324",
    "network_interface": "mock_capture.pcap",
    "layer2": {
      "src_mac": "11:22:33:44:55:66",
      "dst_mac": "66:55:44:33:22:11"
    },
    "layer3": {
      "ip_version": 4,
      "src_ip": "192.168.1.50",
      "dst_ip": "8.8.8.8"
    },
    "layer4": {
      "protocol": "UDP",
      "src_port": 5353,
      "dst_port": 53
    },
    "packet_size_bytes": 42
  },
  {
    "timestamp": "2026-07-16 10:01:22.899464",
    "network_interface": "mock_capture.pcap",
    "layer2": {
      "src_mac": "11:22:33:44:55:66",
      "dst_mac": "66:55:44:33:22:11"
    },
    "layer3": {
      "ip_version": 4,
      "src_ip": "192.168.1.50",
      "dst_ip": "8.8.8.8"
    },
    "layer4": {
      "protocol": "ICMP",
      "src_port": null,
      "dst_port": null
    },
    "packet_size_bytes": 42
  },
  {
    "timestamp": "2026-07-16 10:01:22.899714",
    "network_interface": "mock_capture.pcap",
    "layer2": {
      "src_mac": "11:22:33:44:55:66",
      "dst_mac": "66:55:44:33:22:11"
    },
    "layer3": {
      "ip_version": 6,
      "src_ip": "fe80::1",
      "dst_ip": "fe80::2"
    },
    "layer4": {
      "protocol": "TCP",
      "src_port": 54321,
      "dst_port": 80
    },
    "packet_size_bytes": 74
  }
]
```
All parser checks and assertions succeeded.

---

# Phase 2: Mitigation & Active Defense Engine

## 1. Overview & Architecture
Phase 2 ingests detected threat alerts and executes network-level countermeasures:

1. **Bi-Directional TCP RST Injection**: Disrupts established connection channels. For maximum reliability, the engine injects spoofed TCP packets in *both directions* (Source -> Target and Target -> Source), forcing TCP endpoints to immediately tear down half-open/established sockets.
2. **Safe Firewall Rule Generation**: Constructs Linux `iptables` and `ip6tables` shell commands to drop traffic from threat actor IPs.
3. **OS Command Injection Defense**: Enforces input parameters checks:
   - Validates IP formats via python's `ipaddress` parser.
   - Enforces a protocol whitelist (`TCP`, `UDP`).
   - Asserts port range parameters (`1 <= port <= 65535`).

## 2. Phase 2 Implementation Code
The source code is located at [probe_mitigation.py](file:///c:/Users/aswin/Desktop/Network%20Forences/probe_mitigation.py).

### Core Components:
- **`ActiveDefenseEngine.inject_tcp_rst(target_ip, target_port, source_ip, source_port, seq_num, ack_num)`**: Forges TCP RST packets for both directions of the intercepted stream using Scapy and injects them onto the wire.
- **`ActiveDefenseEngine.generate_firewall_rule(malicious_ip, protocol, port)`**: Returns a validated, shell-safe string to drop incoming traffic.
- **`ActiveDefenseEngine.process_alert(alert_dict)`**: Extracts fields from structural threat alarms and invokes the corresponding active mitigation strategy.

## 3. Phase 2 Verification & Walkthrough
To verify Phase 2, we executed the unit test suite [test_probe_mitigation.py](file:///C:/Users/aswin/.gemini/antigravity-ide/brain/3c014cc1-86d5-4631-8b48-457ed7b16815/scratch/test_probe_mitigation.py):

### Test Execution Logs:
```
...2026-07-16 10:06:13,558 [INFO] PROBE.Mitigation: Generated firewall command: sudo iptables -A INPUT -s 192.168.1.100 -j DROP
.2026-07-16 10:06:13,558 [INFO] PROBE.Mitigation: Generated firewall command: sudo ip6tables -A INPUT -s 2001:db8::1 -p tcp --dport 443 -j DROP
..2026-07-16 10:06:13,559 [INFO] PROBE.Mitigation: Processing alert TEST-TCP-001 for mitigation targeting actor 192.168.1.200
2026-07-16 10:06:13,559 [INFO] PROBE.Mitigation: Initiating bi-directional TCP RST injection between 192.168.1.200:5000 and 10.0.0.1:80
2026-07-16 10:06:13,559 [INFO] PROBE.Mitigation: Bi-directional TCP RST packets successfully injected.
.2026-07-16 10:06:13,559 [INFO] PROBE.Mitigation: Processing alert TEST-UDP-001 for mitigation targeting actor 192.168.1.200
.2026-07-16 10:06:13,560 [INFO] PROBE.Mitigation: Initiating bi-directional TCP RST injection between 192.168.1.100:44500 and 10.0.0.5:80
2026-07-16 10:06:13,560 [INFO] PROBE.Mitigation: Bi-directional TCP RST packets successfully injected.
.
----------------------------------------------------------------------
Ran 9 tests in 0.002s

OK
```
All safety constraints, command-injection prevention assertions, and packet header structures successfully validated.
