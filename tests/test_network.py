import json
import os
import pwd
import select
import signal
import subprocess
import sys
import unittest
import uuid

from tests import support as runtime
from uu_vps_proxy.manager import config_for, guard_rules


def fixture_state():
    return {"uid": 65534, "mark": 0x0A550100, "interface": "testtun", "dns_port": 15353,
            "route_table": 48100, "priority": 15000, "address": "172.29.129.1/30",
            "bypass_ipv4": ["192.0.2.2"], "bypass_tcp_ports": [], "bypass_udp_ports": [40001]}


class UserTunConfigTests(unittest.TestCase):
    def test_user_tun_config_is_accepted_by_real_core(self):
        if not os.environ.get("UU_VPS_INTEGRATION"):
            self.skipTest("core validation runs in the integration job")
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core.json"
            path.write_text(json.dumps(config_for(fixture_state(), {"type": "socks", "server": "127.0.0.1", "server_port": 1080})))
            runtime.run_command(["sing-box", "check", "-c", str(path)])


@unittest.skipUnless(os.environ.get("UU_VPS_INTEGRATION") == "1" and os.geteuid() == 0,
                     "requires root and UU_VPS_INTEGRATION=1")
class UserTunGuardTests(unittest.TestCase):
    def setUp(self):
        self.namespace = "uuvps-guard-" + uuid.uuid4().hex[:8]
        self.state = fixture_state()
        self.state["uid"] = pwd.getpwnam("nobody").pw_uid
        runtime.run_command(["ip", "netns", "add", self.namespace])
        self.addCleanup(lambda: runtime.run_command(["ip", "netns", "delete", self.namespace]))
        runtime.run_command(["ip", "-n", self.namespace, "link", "set", "lo", "up"])
        runtime.run_command(["ip", "-n", self.namespace, "link", "add", "dummy0", "type", "dummy"])
        runtime.run_command(["ip", "-n", self.namespace, "address", "add", "192.0.2.1/24", "dev", "dummy0"])
        runtime.run_command(["ip", "-n", self.namespace, "link", "set", "dummy0", "up"])
        runtime.run_command(["ip", "netns", "exec", self.namespace, "nft", "-f", "-"], input=guard_rules(self.state, []))

    def send(self, port, user="nobody", destination_port=19302):
        code = f'''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('192.0.2.1',{port}))
try:
    print('sent',s.sendto(b'test',('192.0.2.2',{destination_port})))
except OSError as error:
    print('blocked',error.errno)
'''
        result = runtime.run_command(["ip", "netns", "exec", self.namespace,
                                      "runuser", "-u", user, "--", sys.executable, "-c", code])
        return result.strip()

    def test_other_users_keep_physical_egress(self):
        self.assertEqual(self.send(40002, user="root"), "sent 4")

    def test_user_has_no_physical_fallback_without_tun(self):
        self.assertTrue(self.send(40002).startswith("blocked"))

    def test_remote_control_udp_port_is_bypassed(self):
        self.assertEqual(self.send(40001), "sent 4")

    def test_browser_stun_is_not_bypassed_by_control_ip_whitelist(self):
        # Same server, different application socket: UDP remains blocked.
        self.assertTrue(self.send(40002).startswith("blocked"))

    def test_control_tcp_ip_whitelist_does_not_apply_to_udp_443(self):
        self.assertTrue(self.send(40002, destination_port=443).startswith("blocked"))

    def test_connection_mark_survives_socket_whitelist_refresh(self):
        code = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('192.0.2.1',40001))
print(s.sendto(b'first',('192.0.2.2',19302)),flush=True)
input()
print(s.sendto(b'second',('192.0.2.2',19302)),flush=True)
'''
        process = subprocess.Popen(["ip", "netns", "exec", self.namespace, "runuser", "-u", "nobody", "--",
                                    sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "5")
            runtime.run_command(["ip", "netns", "exec", self.namespace, "nft", "flush", "set", "inet",
                                 f"uuvps_uid_{self.state['uid']}", "control_udp_ports"])
            output, error = process.communicate("continue\n", timeout=5)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(output.strip(), "6")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


@unittest.skipUnless(os.environ.get("UU_VPS_INTEGRATION") == "1" and os.geteuid() == 0,
                     "requires root and UU_VPS_INTEGRATION=1")
class RemoteControlUDPTests(unittest.TestCase):
    def test_whitelisted_udp_needs_source_rewrite_after_tun_route_selection(self):
        # Two private namespaces, connected to each other only. No host route,
        # physical interface, residential credential or real UU session used.
        suffix = uuid.uuid4().hex[:8]
        actor, peer = "uuvps-udp-a-" + suffix, "uuvps-udp-p-" + suffix
        state = fixture_state()
        state["bypass_udp_ports"] = [41001, 41002, 41003]
        uid = pwd.getpwnam("nobody").pw_uid
        state["uid"] = uid
        echo = None
        def read_line(process):
            if not select.select([process.stdout], [], [], 3)[0]:
                self.fail("isolated UDP peer produced no response")
            return process.stdout.readline().strip()
        try:
            for namespace in (actor, peer):
                runtime.run_command(["ip", "netns", "add", namespace])
                runtime.run_command(["ip", "-n", namespace, "link", "set", "lo", "up"])
            runtime.run_command(["ip", "-n", actor, "link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", peer])
            for namespace, address in ((actor, "192.0.2.1/24"), (peer, "192.0.2.2/24")):
                runtime.run_command(["ip", "-n", namespace, "address", "add", address, "dev", "eth0"])
                runtime.run_command(["ip", "-n", namespace, "link", "set", "eth0", "up"])
            runtime.run_command(["ip", "-n", peer, "address", "add", "203.0.113.1/32", "dev", "lo"])
            for interface in ("all", "eth0"):
                runtime.run_command(["ip", "netns", "exec", peer, "sysctl", "-w", f"net.ipv4.conf.{interface}.rp_filter=0"])
            runtime.run_command(["ip", "-n", actor, "route", "add", "default", "via", "192.0.2.2"])
            runtime.run_command(["ip", "-n", actor, "link", "add", state["interface"], "type", "dummy"])
            runtime.run_command(["ip", "-n", actor, "address", "add", state["address"], "dev", state["interface"]])
            runtime.run_command(["ip", "-n", actor, "link", "set", state["interface"], "up"])
            runtime.run_command(["ip", "-n", actor, "route", "add", "default", "dev", state["interface"], "table", "1000"])
            runtime.run_command(["ip", "-n", actor, "rule", "add", "priority", "100", "fwmark", str(state["mark"]), "lookup", "main"])
            runtime.run_command(["ip", "-n", actor, "rule", "add", "priority", "200", "uidrange", f"{uid}-{uid}", "lookup", "1000"])
            rules = guard_rules(state, [])
            runtime.run_command(["ip", "netns", "exec", actor, "nft", "-f", "-"], input=rules)
            table = f"uuvps_uid_{uid}"
            runtime.run_command(["ip", "netns", "exec", actor, "nft", "flush", "chain", "inet", table, "source_fix"])
            server = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('203.0.113.1',5555))
print('ready',flush=True)
while True:
    data,address=s.recvfrom(1024)
    print(address[0],flush=True)
    try: s.sendto(b'pong',address)
    except OSError: pass
'''
            echo = subprocess.Popen(["ip", "netns", "exec", peer, sys.executable, "-c", server],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(read_line(echo), "ready")
            def probe(port):
                client = f'''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('0.0.0.0',{port}))
s.settimeout(1)
s.sendto(b'ping',('203.0.113.1',5555))
try: print(s.recvfrom(1024)[0].decode())
except socket.timeout: print('timeout')
'''
                return runtime.run_command(["ip", "netns", "exec", actor, "runuser", "-u", "nobody", "--", sys.executable, "-c", client]).strip()
            self.assertEqual(probe(41001), "timeout")
            self.assertEqual(read_line(echo), "172.29.129.1")
            runtime.run_command(["ip", "netns", "exec", actor, "nft", "-f", "-"],
                                input=f"delete table inet {table}\n" + rules)
            self.assertEqual(probe(41002), "pong")
            self.assertEqual(read_line(echo), "192.0.2.1")
            # A port policy installed BEFORE UID TUN capture preserves the
            # established desktop socket's source even without masquerading.
            runtime.run_command(["ip", "-n", actor, "rule", "add", "priority", "90", "uidrange", f"{uid}-{uid}",
                                 "ipproto", "udp", "sport", "41003", "lookup", "main"])
            runtime.run_command(["ip", "netns", "exec", actor, "nft", "flush", "chain", "inet", table, "source_fix"])
            self.assertEqual(probe(41003), "pong")
            self.assertEqual(read_line(echo), "192.0.2.1")
        finally:
            if echo is not None:
                echo.kill()
                echo.wait(timeout=5)
                echo.stdout.close()
                echo.stderr.close()
            for namespace in (actor, peer):
                subprocess.run(["ip", "netns", "delete", namespace], capture_output=True)


if __name__ == "__main__":
    unittest.main()
