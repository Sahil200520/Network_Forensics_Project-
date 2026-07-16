# PROBE: Passive Network Ingestion & Mitigation Engine (Industrial Edition)

PROBE is a modular, high-performance Network Detection and Response (NDR) mini-ecosystem designed for industrial network monitoring and active incident response. Built on top of the Scapy framework, the project enables layer-by-layer network traffic ingestion, Deep Packet Inspection (DPI) up to Layer 7, and automated bi-directional TCP Reset (RST) injection for rapid threat mitigation.

---

##  Why I Built This Project (Motivation & Use Case)

Traditional firewalls and static intrusion detection systems often lack the speed required to stop active threats—such as data exfiltration or Command-and-Control (C2) communication—in real time. 

I developed **PROBE** to act as a hands-on, defensive security blueprint that demonstrates how modern **Network Detection and Response (NDR)** tools work under the hood. The core goals of this project are:
1. **Bridge the Visibility Gap:** Moving past basic port analysis to perform deep Layer 7 parsing (extracting DNS queries, HTTP hosts, and TLS SNI strings) to find hidden indicators of compromise (IoCs).
2. **Implement Active Defensive Playbooks:** Moving away from passive logging by creating an automated engine that can actively kick threat actors off the network using sub-second packet manipulation.
3. **SIEM Readiness:** Normalizing raw, messy network payloads into structured JSON schemas that are immediately ready for ingestion into a SIEM (like Splunk or Elastic Stack) or an analytical pipeline.

---

##  System Architecture & Workflow

Here is how data flows sequentially through the PROBE ecosystem:

```text
[ Raw Network Data ] ---> ( Live Sniffing / Offline PCAP Ingestion )
                                        │
                                        ▼
                         [ Deep Packet Inspection (DPI) ]
                   Parses L2 (MAC), L3 (IP), L4 (Ports), L7 (Data)
                                        │
                                        ▼
                         [ Schema Normalization Engine ]
                   Transforms messy byte streams into structured JSON
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
     [ SIEM / File Ingestion ]                 [ Threat Detection Alert ]
   Logs committed to analytical files                       │
                                                            ▼
                                              [ Active Mitigation Playbook ]
                                            Injects Bi-directional TCP RST
                                            to kill the rogue session instantly
```

---

##  Key Features

- **Multi-Mode Ingestion:** Seamlessly toggles between live network interface capturing and offline forensics mode using `.pcap` files.
- **Deep Packet Inspection (DPI):** Extracts and structures L2 (MAC), L3 (IP), L4 (TCP/UDP/ARP), and L7 metadata (including DNS queries, HTTP hosts, and TLS SNI strings).
- **Schema Normalization:** Standardizes raw network packet information into clean, actionable JSON schemas ready for SIEM ingestion.
- **Active Threat Mitigation:** Real-time simulation of bi-directional TCP RST burst injections to forcefully disrupt unauthorized sessions between threat actors and internal assets.

---

##  Project Structure

```text
├── probe_sniffer.py        # Core Traffic Ingestion & L7 Parsing Engine
├── probe_mitigation.py     # Automated TCP RST Injection Playbook Demo
├── test_sniffer.py         # Mock Traffic Generator & Validation Script
├── test_mitigation.py      # Automated Verification for Defense Actions
└── requirements.txt        # Python Dependency Configurations
```

---

##  Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Sahil200520/Network_Forensics_Project-.git
cd Network_Forensics_Project-
```

### 2. Configure Virtual Environment & Dependencies
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment (Linux/macOS)
source venv/bin/activate
# On Windows PowerShell use: .\\venv\\Scripts\\Activate.ps1

# Install required packages
pip install -r requirements.txt
```
*Note: For live sniffing capabilities on Windows, ensure that Npcap is installed.*

---

##  Step-by-Step Usage Guide

Follow these sequential phases to run the entire forensics and mitigation pipeline:

### Phase 1: Generate Mock Forensic Network Traffic
Before running the main scripts, you need network packet data. Run the validation suite to instantly construct a mock industrial network architecture PCAP containing multi-layered anomalies (such as malicious DNS queries):
```bash
python test_sniffer.py
```
*This will create a file named `mock_capture_industrial.pcap` in your directory.*

### Phase 2: Execute Offline Forensics Mode (Parser)
Analyze the generated `.pcap` capture file without requiring administrative execution privileges, saving structured JSON logs to a dedicated file:
```bash
python probe_sniffer.py -f mock_capture_industrial.pcap -o parsed_network_logs.json
```
*Open `parsed_network_logs.json` in your editor to view the clean, structured Layer 2 to Layer 7 JSON outputs.*

### Phase 3: Live Traffic Sniffing (Optional - Requires Root / Admin Privileges)
To perform live network packet sniffing across active interface adapters in real time:

**On Linux / macOS:**
```bash
sudo ./venv/bin/python3 probe_sniffer.py -i eth0 -o live_network_logs.json
```

**On Windows:**
Open PowerShell as an Administrator and execute:
```powershell
python probe_sniffer.py -i <interface_name> -o live_network_logs.json
```

### Phase 4: Run the Active Defensive Mitigation Engine
Execute the active defense playbook to observe how the engine intercepts threats and drops unauthorized TCP sessions using custom-crafted packet injection:
```bash
python probe_mitigation.py
```
*This prints out the log operations for the **Bi-directional TCP RST Burst Injection** and generates a SIEM event audit trail inside `probe_mitigation_events.json`.*

---

##  Normalized Log Schema Example

PROBE structures raw binary payloads into clean, queryable JSON fields optimal for analytical alerting pipelines and SIEM ingestion rules:

```json
{
  "timestamp": "2026-07-16 10:59:19.737815",
  "network_interface": "mock_capture_industrial.pcap",
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
  "layer7": {
    "dns_query": "threat-actor-command.ru",
    "tls_sni": null,
    "http_host": null
  },
  "packet_size_bytes": 83
}
```
