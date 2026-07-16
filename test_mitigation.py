import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock

import probe_mitigation
from probe_mitigation import ActiveDefenseEngine

class TestActiveDefenseEngine(unittest.TestCase):

    def setUp(self):
        # Initialize engine without privilege checks for testing
        self.engine = ActiveDefenseEngine(enforce_privileges=False, alert_log_path="test_events.json")

    def tearDown(self):
        if os.path.exists("test_events.json"):
            os.remove("test_events.json")

    def test_firewall_rule_generation_valid_ipv4(self):
        cmd = self.engine.generate_firewall_rule("192.168.1.100")
        self.assertEqual(cmd, "sudo iptables -A INPUT -s 192.168.1.100 -j DROP")

    def test_firewall_rule_generation_valid_ipv6(self):
        cmd = self.engine.generate_firewall_rule("2001:db8::1", protocol="TCP", port=443)
        self.assertEqual(cmd, "sudo ip6tables -A INPUT -s 2001:db8::1 -p tcp --dport 443 -j DROP")

    def test_firewall_rule_generation_invalid_ip_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.engine.generate_firewall_rule("192.168.1.100; rm -rf /")

    def test_firewall_rule_generation_invalid_protocol_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.engine.generate_firewall_rule("192.168.1.1", protocol="HTTP")

    @patch('subprocess.run')
    def test_apply_firewall_rule_safety_controls(self, mock_run):
        """Verify firewall rule execution invokes subprocess correctly and rejects unsafe scripts."""
        mock_run.return_value = MagicMock(stdout="success", stderr="", returncode=0)
        
        # Valid command execution
        cmd = "sudo iptables -A INPUT -s 192.168.1.10 -j DROP"
        success = self.engine.apply_firewall_rule(cmd)
        self.assertTrue(success)
        mock_run.assert_called_once_with(cmd.split(), shell=False, capture_output=True, text=True, check=True)
        
        # Blocked dangerous command execution
        mock_run.reset_mock()
        unsafe_cmd = "sudo iptables -A INPUT -s 192.168.1.10 -j DROP; cat /etc/passwd"
        success = self.engine.apply_firewall_rule(unsafe_cmd)
        self.assertFalse(success)
        mock_run.assert_not_called()

    @patch('probe_mitigation.send')
    def test_tcp_rst_burst_injection_packet_structures(self, mock_send):
        """Verify that the engine crafts and sends 6 TCP RST packets (3 offsets * 2 directions) for burst reliability."""
        success = self.engine.inject_tcp_rst(
            target_ip="10.0.0.5",
            target_port=80,
            source_ip="192.168.1.100",
            source_port=44500,
            seq_num=1000,
            ack_num=2000
        )
        self.assertTrue(success)
        self.assertEqual(mock_send.call_count, 6)
        
        sent_pkts = [call[0][0] for call in mock_send.call_args_list]
        
        # Verify first sequence (Source -> Target)
        self.assertEqual(sent_pkts[0].src, "192.168.1.100")
        self.assertEqual(sent_pkts[0].dst, "10.0.0.5")
        self.assertEqual(sent_pkts[0].payload.seq, 1000)
        self.assertEqual(sent_pkts[1].payload.seq, 1000 + 512)
        self.assertEqual(sent_pkts[2].payload.seq, 1000 + 1024)
        
        # Verify reverse sequence (Target -> Source)
        self.assertEqual(sent_pkts[3].src, "10.0.0.5")
        self.assertEqual(sent_pkts[3].dst, "192.168.1.100")
        self.assertEqual(sent_pkts[3].payload.seq, 2000)
        self.assertEqual(sent_pkts[4].payload.seq, 2000 + 512)
        self.assertEqual(sent_pkts[5].payload.seq, 2000 + 1024)

    @patch('probe_mitigation.send')
    @patch('subprocess.run')
    def test_process_alert_tcp_logging(self, mock_run, mock_send):
        """Verify that alert processing logs SIEM-compatible mitigation event data correctly."""
        alert = {
            "alert_id": "ALERT-TCP-LOG-TEST",
            "timestamp": "2026-07-16 10:00:00.000000",
            "threat_actor_ip": "192.168.1.200",
            "victim_ip": "10.0.0.1",
            "protocol": "TCP",
            "layer4_details": {
                "sport": 5000,
                "dport": 80,
                "seq": 999,
                "ack": 888
            }
        }
        success = self.engine.process_alert(alert)
        self.assertTrue(success)
        self.assertTrue(os.path.exists("test_events.json"))
        
        with open("test_events.json", "r", encoding="utf-8") as f:
            log_line = json.loads(f.readline())
            self.assertEqual(log_line["alert_id"], "ALERT-TCP-LOG-TEST")
            self.assertEqual(log_line["action_executed"], "TCP_RST_BURST")
            self.assertEqual(log_line["threat_actor_ip"], "192.168.1.200")


if __name__ == "__main__":
    unittest.main()
