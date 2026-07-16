#!/usr/bin/env python3
"""
PROBE: Passive Network Forensics & IP Activity Discovery Tool
Industrial-Grade Ingestion & Parsing Engine

This module provides a production-grade, thread-safe network sniffing and packet parsing engine
incorporating BPF filtering and Layer 7 passive metadata extraction (DNS, TLS SNI, HTTP Host).

Author: Antigravity Team
Date: July 2026
"""

import sys
import os
import ctypes
import queue
import threading
import time
import json
import logging
from datetime import datetime

# Initialize logging to stderr to prevent pollution of stdout
logger = logging.getLogger("PROBE.Sniffer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr
)

# Attempt to import Scapy
try:
    from scapy.all import sniff, AsyncSniffer, Raw
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS
except ImportError as e:
    logger.critical("Scapy is not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)


def is_admin() -> bool:
    """
    Checks if the script is running with administrative (Windows) or root (Unix) privileges.
    """
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.getuid() == 0
        except AttributeError:
            return False


def check_privileges():
    """
    Enforces that administrative/root privileges are present.
    """
    if not is_admin():
        raise PermissionError(
            "Elevated/Administrative privileges (root/sudo/Administrator) are required to capture live packets."
        )


def parse_tls_sni(payload: bytes) -> str:
    """
    Parses the Server Name Indication (SNI) from a raw TLS Client Hello byte payload.
    Uses robust byte offset navigation to prevent dependency on heavy external TLS parsers.

    Args:
        payload (bytes): The raw Layer 4 payload bytes.

    Returns:
        str: The extracted hostname, or None if SNI is not found or payload is malformed.
    """
    try:
        # Check for TLS Handshake Record (0x16), Version (0x03 0x01, 0x03 0x02, or 0x03 0x03)
        if len(payload) < 44 or payload[0] != 0x16 or payload[1] != 0x03:
            return None

        # Handshake Type must be Client Hello (0x01)
        if payload[5] != 0x01:
            return None

        # Session ID length offset
        session_id_len_offset = 38 + 5
        if len(payload) <= session_id_len_offset:
            return None
        session_id_len = payload[session_id_len_offset]

        # Cipher Suite length offset
        cipher_len_offset = session_id_len_offset + 1 + session_id_len
        if len(payload) <= cipher_len_offset + 1:
            return None
        cipher_len = int.from_bytes(payload[cipher_len_offset:cipher_len_offset + 2], "big")

        # Compression Methods offset
        comp_len_offset = cipher_len_offset + 2 + cipher_len
        if len(payload) <= comp_len_offset:
            return None
        comp_len = payload[comp_len_offset]

        # Extensions offset
        extensions_len_offset = comp_len_offset + 1 + comp_len
        if len(payload) <= extensions_len_offset + 1:
            return None
        extensions_len = int.from_bytes(payload[extensions_len_offset:extensions_len_offset + 2], "big")

        # Start parsing extensions
        ptr = extensions_len_offset + 2
        end = ptr + extensions_len

        while ptr + 4 <= end and ptr + 4 <= len(payload):
            ext_type = int.from_bytes(payload[ptr:ptr+2], "big")
            ext_len = int.from_bytes(payload[ptr+2:ptr+4], "big")
            ptr += 4

            # Server Name Extension (0x0000)
            if ext_type == 0x0000:
                if ptr + ext_len > len(payload):
                    return None
                
                # Length of Server Name List (2 bytes)
                list_len = int.from_bytes(payload[ptr:ptr+2], "big")
                name_ptr = ptr + 2
                
                while name_ptr + 3 <= ptr + ext_len:
                    name_type = payload[name_ptr]
                    name_len = int.from_bytes(payload[name_ptr+1:name_ptr+3], "big")
                    name_ptr += 3
                    
                    # Host Name Type (0x00)
                    if name_type == 0x00:
                        if name_ptr + name_len > len(payload):
                            return None
                        sni_host = payload[name_ptr:name_ptr+name_len].decode("utf-8", errors="ignore")
                        return sni_host
                    name_ptr += name_len
            ptr += ext_len

    except Exception:
        pass
    return None


def parse_http_host(payload: bytes) -> str:
    """
    Parses HTTP Host header value from TCP segments.
    """
    try:
        content = payload.decode("utf-8", errors="ignore")
        if content.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
            for line in content.split("\r\n"):
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def parse_packet(packet, interface_name: str) -> dict:
    """
    Normalizes a Scapy Packet into the standardized Phase 3 JSON-compatible schema.
    """
    data = {
        "timestamp": None,
        "network_interface": interface_name,
        "layer2": {
            "src_mac": None,
            "dst_mac": None
        },
        "layer3": {
            "ip_version": None,
            "src_ip": None,
            "dst_ip": None
        },
        "layer4": {
            "protocol": None,
            "src_port": None,
            "dst_port": None
        },
        "layer7": {
            "dns_query": None,
            "tls_sni": None,
            "http_host": None
        },
        "packet_size_bytes": 0
    }

    try:
        data["packet_size_bytes"] = len(packet)
        pkt_time = float(packet.time) if getattr(packet, "time", None) is not None else time.time()
        data["timestamp"] = datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f")

        # --- Layer 2: Data Link ---
        if packet.haslayer(Ether):
            data["layer2"]["src_mac"] = packet[Ether].src
            data["layer2"]["dst_mac"] = packet[Ether].dst
        elif packet.haslayer("Dot3"):
            data["layer2"]["src_mac"] = packet["Dot3"].src
            data["layer2"]["dst_mac"] = packet["Dot3"].dst

        # --- Layer 3: Network ---
        if packet.haslayer(IP):
            data["layer3"]["ip_version"] = 4
            data["layer3"]["src_ip"] = packet[IP].src
            data["layer3"]["dst_ip"] = packet[IP].dst
        elif packet.haslayer(IPv6):
            data["layer3"]["ip_version"] = 6
            data["layer3"]["src_ip"] = packet[IPv6].src
            data["layer3"]["dst_ip"] = packet[IPv6].dst
        elif packet.haslayer(ARP):
            data["layer3"]["ip_version"] = 4
            data["layer3"]["src_ip"] = packet[ARP].psrc
            data["layer3"]["dst_ip"] = packet[ARP].pdst

        # --- Layer 4: Transport ---
        if packet.haslayer(TCP):
            data["layer4"]["protocol"] = "TCP"
            data["layer4"]["src_port"] = int(packet[TCP].sport)
            data["layer4"]["dst_port"] = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            data["layer4"]["protocol"] = "UDP"
            data["layer4"]["src_port"] = int(packet[UDP].sport)
            data["layer4"]["dst_port"] = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            data["layer4"]["protocol"] = "ICMP"
        elif packet.haslayer(ARP):
            data["layer4"]["protocol"] = "ARP"
        else:
            is_icmpv6 = False
            for layer in packet.layers():
                if "ICMPv6" in layer.__name__:
                    is_icmpv6 = True
                    break
            if is_icmpv6:
                data["layer4"]["protocol"] = "ICMP"
            elif packet.haslayer(IP) or packet.haslayer(IPv6):
                data["layer4"]["protocol"] = "OTHER"

        # --- Layer 7: Passive Application Parsing ---
        # 1. DNS parsing
        if packet.haslayer(DNS) and packet[DNS].qd:
            qname = packet[DNS].qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            # Remove trailing dot from DNS query
            data["layer7"]["dns_query"] = qname.rstrip(".")

        # 2. TLS SNI & HTTP Host parsing from TCP payloads
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            payload_bytes = bytes(packet[Raw].load)
            
            # Check for TLS Client Hello (matches port 443 often, but checking byte content is safer)
            sni = parse_tls_sni(payload_bytes)
            if sni:
                data["layer7"]["tls_sni"] = sni
            else:
                # Check for HTTP Host
                host = parse_http_host(payload_bytes)
                if host:
                    data["layer7"]["http_host"] = host

    except Exception as e:
        logger.warning(f"Error parsing packet: {e}", exc_info=True)

    return data


class ProbeSniffer:
    """
    A thread-safe network packet sniffer that manages capturing (Producer) and parsing (Consumer)
    in isolated threads with kernel-level BPF filtering support.
    """

    def __init__(self, interface=None, pcap_file=None, bpf_filter=None, packet_handler=None, queue_size=50000):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.packet_handler = packet_handler
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.sniffer = None
        self.sniffer_thread = None

    def start(self):
        if not self.pcap_file:
            check_privileges()

        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, name="PROBE-ParserWorker", daemon=True)
        self.worker_thread.start()

        def queue_packet_callback(packet):
            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                logger.warning("PROBE parser queue is full! Packet dropped to preserve performance.")

        if self.pcap_file:
            logger.info(f"Opening offline PCAP file for analysis: {self.pcap_file}")
            self.sniffer_thread = threading.Thread(
                target=self._run_pcap_read,
                args=(queue_packet_callback,),
                name="PROBE-PcapReader",
                daemon=True
            )
            self.sniffer_thread.start()
        else:
            iface_desc = self.interface if self.interface else "default interface"
            filter_desc = f" [Filter: {self.bpf_filter}]" if self.bpf_filter else ""
            logger.info(f"Starting live network capture on: {iface_desc}{filter_desc}")
            try:
                # Supply BPF filter to Scapy AsyncSniffer
                self.sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=queue_packet_callback,
                    store=False
                )
                self.sniffer.start()
            except Exception as e:
                if self.bpf_filter:
                    logger.warning(f"Failed to start live capture with BPF filter: {e}. Falling back to unfiltered capture.")
                    try:
                        self.sniffer = AsyncSniffer(
                            iface=self.interface,
                            prn=queue_packet_callback,
                            store=False
                        )
                        self.sniffer.start()
                    except Exception as fallback_err:
                        logger.critical(f"Failed to start live capture on fallback: {fallback_err}")
                        self.stop()
                        raise fallback_err
                else:
                    logger.critical(f"Failed to start live capture on {iface_desc}: {e}")
                    logger.critical("Note: On Windows, make sure Npcap/WinPcap is installed and running.")
                    self.stop()
                    raise e

    def _run_pcap_read(self, callback):
        try:
            try:
                sniff(offline=self.pcap_file, filter=self.bpf_filter, prn=callback, store=False)
            except Exception as e:
                if self.bpf_filter and ("tcpdump" in str(e) or "filter" in str(e).lower()):
                    logger.warning(f"Offline BPF filtering failed ({e}). Falling back to unfiltered PCAP analysis.")
                    sniff(offline=self.pcap_file, prn=callback, store=False)
                else:
                    raise e
            logger.info("Finished reading all packets from PCAP file.")
        except Exception as e:
            logger.error(f"Error reading offline PCAP file {self.pcap_file}: {e}")
        finally:
            self.packet_queue.put(None)

    def _worker_loop(self):
        src_label = self.pcap_file if self.pcap_file else (self.interface or "live-interface")
        while not self.stop_event.is_set() or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if packet is None:
                self.packet_queue.task_done()
                break

            try:
                parsed_data = parse_packet(packet, src_label)
                if self.packet_handler:
                    self.packet_handler(parsed_data)
            except Exception as e:
                logger.error(f"Error parsing packet in worker loop: {e}", exc_info=True)
            finally:
                self.packet_queue.task_done()

    def stop(self):
        logger.info("Stopping PROBE ingestion engine...")
        self.stop_event.set()

        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.warning(f"Error stopping Scapy AsyncSniffer: {e}")
            self.sniffer = None

        try:
            self.packet_queue.put(None)
        except Exception:
            pass

        if self.worker_thread:
            self.worker_thread.join(timeout=3.0)
            self.worker_thread = None

        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=3.0)
            self.sniffer_thread = None

        logger.info("PROBE ingestion engine stopped.")


def start_sniffer(interface=None, pcap_file=None, bpf_filter=None, packet_handler=None):
    """
    Primary API entrypoint. Starts live packet capture or offline PCAP parsing,
    processing packets asynchronously through a thread-safe queue with BPF filter support.
    """
    if pcap_file and not os.path.exists(pcap_file):
        raise FileNotFoundError(f"Offline PCAP file not found: {pcap_file}")

    if not packet_handler:
        def default_handler(data):
            try:
                print(json.dumps(data), flush=True)
            except Exception as e:
                logger.error(f"Failed to serialize packet data: {e}")
        packet_handler = default_handler

    sniffer_instance = ProbeSniffer(
        interface=interface,
        pcap_file=pcap_file,
        bpf_filter=bpf_filter,
        packet_handler=packet_handler
    )

    sniffer_instance.start()

    try:
        if pcap_file:
            while sniffer_instance.worker_thread and sniffer_instance.worker_thread.is_alive():
                time.sleep(0.1)
        else:
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Sniffer execution interrupted by user (Ctrl+C). Cleaning up...")
    finally:
        sniffer_instance.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PROBE: Passive Network Ingestion & Parsing Engine (Industrial Edition)"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i", "--interface",
        help="Name of the network interface to capture live traffic from."
    )
    group.add_argument(
        "-f", "--file",
        help="Path to an offline PCAP file for analysis."
    )
    parser.add_argument(
        "-o", "--output",
        help="Write parsed JSON records to the specified log file."
    )
    parser.add_argument(
        "--filter",
        help="BPF filter string to apply at kernel level (e.g., 'tcp port 443')."
    )
    parser.add_argument(
        "--validate-privileges",
        action="store_true",
        help="Explicitly validate elevated administrative/root privileges and exit."
    )

    args = parser.parse_args()

    if not args.interface and not args.file and not args.validate_privileges:
        parser.print_help()
        print("\n[ERROR] You must specify either a live network interface (-i/--interface) or an offline PCAP file (-f/--file).", file=sys.stderr)
        sys.exit(1)

    if args.validate_privileges:
        try:
            check_privileges()
            print("Privilege validation: SUCCESS. Running with elevated privileges.")
            sys.exit(0)
        except PermissionError as err:
            print(f"Privilege validation: FAILED. {err}", file=sys.stderr)
            sys.exit(1)

    output_file_handle = None
    if args.output:
        try:
            output_file_handle = open(args.output, "a", encoding="utf-8")
            logger.info(f"Writing parsed JSON logs to: {args.output}")
        except Exception as err:
            logger.critical(f"Failed to open output log file {args.output}: {err}")
            sys.exit(1)

    def custom_packet_handler(data):
        payload = json.dumps(data)
        if output_file_handle:
            output_file_handle.write(payload + "\n")
            output_file_handle.flush()
        else:
            print(payload, flush=True)

    try:
        start_sniffer(
            interface=args.interface,
            pcap_file=args.file,
            bpf_filter=args.filter,
            packet_handler=custom_packet_handler
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        logger.error(f"Fatal error in sniffer main loop: {exc}")
        sys.exit(1)
    finally:
        if output_file_handle:
            output_file_handle.close()
