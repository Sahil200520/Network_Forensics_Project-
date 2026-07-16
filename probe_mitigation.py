#!/usr/bin/env python3
"""
PROBE: Passive Network Forensics & IP Activity Discovery Tool
Industrial-Grade Mitigation & Active Defense Engine

This module provides the ActiveDefenseEngine class to execute real-time,
network-layer mitigations. It incorporates burst TCP RST injection,
automatic firewall command execution using secure shell-free subprocess runs,
and SIEM-compatible JSON event logging.

Author: Antigravity Team
Date: July 2026
"""

import sys
import os
import ctypes
import json
import logging
import ipaddress
import subprocess
from datetime import datetime

# Configure logging
logger = logging.getLogger("PROBE.Mitigation")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr
)

# Safe imports for Scapy
try:
    from scapy.all import send, IP, IPv6, TCP
except ImportError:
    logger.critical("Scapy is not installed. Please run 'pip install scapy' first.")
    sys.exit(1)


class ActiveDefenseEngine:
    """
    Active Defense Engine responsible for executing network-level countermeasures,
    including TCP RST burst injection, safe automated iptables execution, and event logging.
    """

    def __init__(self, enforce_privileges: bool = True, alert_log_path: str = "probe_mitigation_events.json"):
        """
        Initializes the Active Defense Engine and validates permissions.

        Args:
            enforce_privileges (bool): Whether to enforce root/admin validation on startup.
            alert_log_path (str): File path where SIEM events will be written.
        """
        self.enforce_privileges = enforce_privileges
        self.alert_log_path = alert_log_path
        if self.enforce_privileges:
            self.check_privileges()

    @staticmethod
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

    def check_privileges(self):
        """
        Validates that the running execution context has administrative/root scope.
        """
        if not self.is_admin():
            raise PermissionError(
                "ActiveDefenseEngine requires elevated administrative/root privileges to execute raw packet injections."
            )

    def log_mitigation_event(self, alert_id: str, threat_ip: str, action: str, details: str):
        """
        Logs mitigation actions to a local NDJSON (Newline Delimited JSON) file for SIEM ingestion.
        """
        log_data = {
            "alert_id": alert_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "threat_actor_ip": threat_ip,
            "action_executed": action,
            "mitigation_details": details
        }
        try:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_data) + "\n")
        except Exception as err:
            logger.error(f"Failed to log alert action to {self.alert_log_path}: {err}")

    def inject_tcp_rst(self, target_ip: str, target_port: int, source_ip: str, source_port: int, seq_num: int, ack_num: int, interface: str = None) -> bool:
        """
        Forges and injects a burst of spoofed TCP Reset (RST) packets onto the network interface.
        To guarantee high-reliability termination on fast or high-latency links:
        Sends 3 RST packets with offset sequence numbers in both directions (6 total).
        """
        # Validate IPs
        try:
            target_addr = ipaddress.ip_address(target_ip)
            source_addr = ipaddress.ip_address(source_ip)
        except ValueError as err:
            logger.error(f"IP validation error in TCP RST Injection: {err}")
            return False

        # Validate Port Ranges
        if not (1 <= target_port <= 65535) or not (1 <= source_port <= 65535):
            logger.error("Port out of range (must be between 1 and 65535)")
            return False

        ip_layer_type = IP if target_addr.version == 4 else IPv6

        logger.info(f"Initiating bi-directional TCP RST burst injection between {source_ip}:{source_port} and {target_ip}:{target_port}")

        try:
            # We send a burst of 3 packets with slight offsets to hit sliding receive windows
            offsets = [0, 512, 1024]
            send_args = {"verbose": False}
            if interface:
                send_args["iface"] = interface

            # Direction 1: Source -> Target
            for offset in offsets:
                pkt = ip_layer_type(src=source_ip, dst=target_ip) / TCP(
                    sport=source_port,
                    dport=target_port,
                    seq=seq_num + offset,
                    flags="R"
                )
                send(pkt, **send_args)

            # Direction 2: Target -> Source
            for offset in offsets:
                pkt = ip_layer_type(src=target_ip, dst=source_ip) / TCP(
                    sport=target_port,
                    dport=source_port,
                    seq=ack_num + offset,
                    flags="R"
                )
                send(pkt, **send_args)

            logger.info("Bi-directional TCP RST burst sequence successfully injected.")
            return True

        except Exception as exc:
            logger.error(f"Failed to inject TCP RST packet flow: {exc}", exc_info=True)
            return False

    def generate_firewall_rule(self, malicious_ip: str, protocol: str = None, port: int = None) -> str:
        """
        Generates the exact Linux iptables bash command required to block the malicious IP.
        """
        try:
            ip_obj = ipaddress.ip_address(malicious_ip)
            iptables_cmd = "iptables" if ip_obj.version == 4 else "ip6tables"
        except ValueError:
            raise ValueError(f"Invalid IP address format: {malicious_ip}")

        cmd = f"sudo {iptables_cmd} -A INPUT -s {malicious_ip}"

        if protocol:
            proto_lower = protocol.lower()
            if proto_lower not in ["tcp", "udp"]:
                raise ValueError("Protocol must be either 'TCP' or 'UDP'")
            cmd += f" -p {proto_lower}"

            if port is not None:
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    raise ValueError("Port must be an integer between 1 and 65535")
                cmd += f" --dport {port}"
        elif port is not None:
            raise ValueError("Protocol must be specified if a port filter is provided")

        cmd += " -j DROP"
        return cmd

    def apply_firewall_rule(self, command: str) -> bool:
        """
        Safely executes a generated firewall command rule locally.
        Splits tokens and invokes subprocess (shell=False) to eliminate injection.
        """
        # Block command chaining or redirection
        unsafe_chars = [";", "|", "&", "`", "$", "<", ">", "\n"]
        if any(char in command for char in unsafe_chars):
            logger.error(f"Firewall execution blocked: Unsafe characters detected in command: {command}")
            return False

        parts = command.split()
        if not parts or parts[0] != "sudo" or parts[1] not in ["iptables", "ip6tables"]:
            logger.error(f"Firewall execution blocked: Command does not match safe pattern: {command}")
            return False

        if self.enforce_privileges:
            try:
                self.check_privileges()
            except PermissionError as err:
                logger.error(f"Firewall execution blocked: {err}")
                return False

        try:
            logger.info(f"Applying firewall rule: {command}")
            # Use shell=False with token array to ensure parameter isolation
            result = subprocess.run(parts, shell=False, capture_output=True, text=True, check=True)
            logger.info(f"Firewall rule applied successfully. stdout: {result.stdout.strip()}")
            return True
        except Exception as exc:
            logger.error(f"Failed to execute firewall rule command: {exc}")
            return False

    def process_alert(self, alert: dict) -> bool:
        """
        Parses and processes a structured alert dictionary, performing corresponding
        active mitigation tasks based on the alert configuration.
        """
        required_fields = ["alert_id", "threat_actor_ip", "victim_ip", "protocol"]
        for field in required_fields:
            if field not in alert:
                logger.error(f"Alert parsing failed: missing required field '{field}'")
                return False

        alert_id = alert["alert_id"]
        threat_actor = alert["threat_actor_ip"]
        victim = alert["victim_ip"]
        protocol = alert["protocol"].upper()

        logger.info(f"Processing alert {alert_id} for mitigation targeting actor {threat_actor}")

        mitigation_success = False
        action_executed = "NONE"
        details = ""

        if protocol == "TCP":
            l4_details = alert.get("layer4_details", {})
            sport = l4_details.get("sport")
            dport = l4_details.get("dport")
            seq = l4_details.get("seq")
            ack = l4_details.get("ack")

            if None in (sport, dport, seq, ack):
                logger.warning(f"TCP Alert {alert_id} missing session offsets. Falling back to firewall block.")
                try:
                    cmd = self.generate_firewall_rule(threat_actor)
                    mitigation_success = self.apply_firewall_rule(cmd)
                    action_executed = "FIREWALL_DROP"
                    details = f"Applied rule: {cmd}"
                except ValueError as err:
                    logger.error(f"Firewall rule generation failed: {err}")
            else:
                mitigation_success = self.inject_tcp_rst(
                    target_ip=victim,
                    target_port=int(dport),
                    source_ip=threat_actor,
                    source_port=int(sport),
                    seq_num=int(seq),
                    ack_num=int(ack)
                )
                action_executed = "TCP_RST_BURST"
                details = f"Injected TCP RST burst to victim {victim}:{dport} and actor {threat_actor}:{sport}"
        elif protocol == "UDP":
            l4_details = alert.get("layer4_details", {})
            dport = l4_details.get("dport")
            try:
                cmd = self.generate_firewall_rule(threat_actor, protocol="UDP", port=dport)
                mitigation_success = self.apply_firewall_rule(cmd)
                action_executed = "FIREWALL_DROP"
                details = f"Applied rule: {cmd}"
            except ValueError as err:
                logger.error(f"Firewall rule generation failed: {err}")
        else:
            try:
                cmd = self.generate_firewall_rule(threat_actor)
                mitigation_success = self.apply_firewall_rule(cmd)
                action_executed = "FIREWALL_DROP"
                details = f"Applied rule: {cmd}"
            except ValueError as err:
                logger.error(f"Firewall rule generation failed: {err}")

        # SIEM Event log output
        self.log_mitigation_event(
            alert_id=alert_id,
            threat_ip=threat_actor,
            action=action_executed if mitigation_success else "FAILED_" + action_executed,
            details=details if mitigation_success else f"Attempt failed or blocked. Details: {details}"
        )

        return mitigation_success


if __name__ == "__main__":
    print("PROBE Industrial Mitigation Engine Demo")
    print("---------------------------------------")
    engine = ActiveDefenseEngine(enforce_privileges=False)
    
    # Process sample alerts
    tcp_alert = {
        "alert_id": "ALERT-IND-01",
        "timestamp": "2026-07-16 10:15:00.000000",
        "threat_actor_ip": "192.168.1.200",
        "victim_ip": "10.0.0.15",
        "protocol": "TCP",
        "layer4_details": {
            "sport": 58930,
            "dport": 80,
            "seq": 450000,
            "ack": 980000
        }
    }
    
    print("\n[Demo] Processing TCP Alert (Burst Inject):")
    engine.process_alert(tcp_alert)
    
    # Read generated SIEM JSON event
    print(f"\n[Demo] Reading SIEM event log ({engine.alert_log_path}):")
    if os.path.exists(engine.alert_log_path):
        with open(engine.alert_log_path, "r", encoding="utf-8") as f:
            print(f.read())
        os.remove(engine.alert_log_path) # Clean up demo log
