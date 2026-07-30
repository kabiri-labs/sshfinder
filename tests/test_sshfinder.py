"""Unit tests for the pure, side-effect-free parts of sshfinder.

The suite is written against the standard library only, so it runs with
``python -m unittest discover -s tests`` on a bare interpreter. Tests that
need an optional dependency (Paramiko) skip themselves when it is absent.
"""

import contextlib
import io
import os
import signal
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sshfinder  # noqa: E402

try:  # Optional: only the deep-audit test needs it.
    import paramiko
except ImportError:  # pragma: no cover - exercised on minimal installs
    paramiko = None


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #
class LoopbackServer:
    """A tiny loopback TCP server running ``handler(conn)`` per connection.

    Binds an ephemeral port so tests never collide, and always closes the
    accepted socket so a failing handler cannot leak file descriptors.
    """

    def __init__(self, handler, backlog=5):
        self._handler = handler
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(backlog)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handler(conn)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


def _serve_ssh_banner(conn):
    conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
    conn.recv(64)


def _serve_http(conn):
    conn.recv(64)
    conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")


class SSHServerMixin:
    """Provides ``self.ssh_port``, an open port speaking an SSH banner."""

    def setUp(self):
        super().setUp()
        self._server = LoopbackServer(_serve_ssh_banner).start()
        self.addCleanup(self._server.stop)
        self.ssh_port = self._server.port


def _name_list(items):
    data = ",".join(items).encode("ascii")
    return struct.pack(">I", len(data)) + data


def build_kexinit_payload(kex, hostkey, ciphers, macs):
    """Construct a valid SSH_MSG_KEXINIT payload for tests."""
    payload = bytes([sshfinder.SSH_MSG_KEXINIT]) + os.urandom(16)
    payload += _name_list(kex)
    payload += _name_list(hostkey)
    payload += _name_list(ciphers)  # enc c2s
    payload += _name_list(ciphers)  # enc s2c
    payload += _name_list(macs)     # mac c2s
    payload += _name_list(macs)     # mac s2c
    payload += _name_list(["none"])
    payload += _name_list(["none"])
    payload += _name_list([])
    payload += _name_list([])
    payload += bytes([0]) + struct.pack(">I", 0)  # follows + reserved
    return payload


def packetize(payload):
    """Wrap a payload in the SSH Binary Packet Protocol (no MAC, pre-KEX)."""
    block = 8
    pad = block - ((4 + 1 + len(payload)) % block)
    if pad < 4:
        pad += block
    packet_length = 1 + len(payload) + pad
    return struct.pack(">I", packet_length) + bytes([pad]) + payload + b"\x00" * pad


# --------------------------------------------------------------------------- #
# Port parsing
# --------------------------------------------------------------------------- #
class ParsePortsTests(unittest.TestCase):
    def test_single(self):
        self.assertEqual(sshfinder.parse_ports("22"), [22])

    def test_range(self):
        self.assertEqual(sshfinder.parse_ports("20-23"), [20, 21, 22, 23])

    def test_mixed_and_dedup(self):
        self.assertEqual(sshfinder.parse_ports("22, 80, 79-81"), [22, 79, 80, 81])

    def test_whitespace_and_empty_chunks(self):
        self.assertEqual(sshfinder.parse_ports(" 22 , , 80 "), [22, 80])

    def test_invalid_specs_raise(self):
        for spec in ["", "abc", "0-10", "1-70000", "30-20", "-5"]:
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    sshfinder.parse_ports(spec)


# --------------------------------------------------------------------------- #
# Target expansion
# --------------------------------------------------------------------------- #
class ExpandTargetsTests(unittest.TestCase):
    def test_plain_ip(self):
        self.assertEqual(sshfinder.expand_targets(["10.0.0.1"]), ["10.0.0.1"])

    def test_hostname_passthrough(self):
        self.assertEqual(sshfinder.expand_targets(["example.com"]), ["example.com"])

    def test_cidr(self):
        hosts = sshfinder.expand_targets(["192.168.1.0/30"])
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_single_host_cidr(self):
        self.assertEqual(sshfinder.expand_targets(["192.168.1.5/32"]), ["192.168.1.5"])

    def test_dedup_and_order(self):
        hosts = sshfinder.expand_targets(["10.0.0.1", "10.0.0.1", "10.0.0.2"])
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2"])

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            sshfinder.expand_targets(["", "  "])

    def test_invalid_network_raises(self):
        with self.assertRaises(ValueError):
            sshfinder.expand_targets(["10.0.0.0/99"])


# --------------------------------------------------------------------------- #
# Target file reading
# --------------------------------------------------------------------------- #
class ReadTargetFileTests(unittest.TestCase):
    def test_strips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("10.0.0.1  10.0.0.2\n# a comment\n10.0.0.3 # inline\n\n")
            self.assertEqual(
                sshfinder.read_target_file(path),
                ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            )


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
class HostResultTests(unittest.TestCase):
    def test_as_dict_sorts(self):
        result = sshfinder.HostResult(
            host="h",
            open_ports=[80, 22],
            ssh_ports=[22],
            banners={22: "SSH-2.0-OpenSSH"},
        )
        d = result.as_dict()
        self.assertEqual(d["open_ports"], [22, 80])
        self.assertEqual(d["ssh_ports"], [22])
        self.assertEqual(d["ssh_sockets"], ["h:22"])
        self.assertEqual(d["banners"], {"22": "SSH-2.0-OpenSSH"})

    def test_responsive_flag(self):
        filtered_only = sshfinder.HostResult(host="h", filtered=5)
        self.assertIs(filtered_only.responsive, False)
        with_closed = sshfinder.HostResult(host="h", closed=3, filtered=5)
        self.assertIs(with_closed.responsive, True)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
class RenderTests(unittest.TestCase):
    def test_json_roundtrip(self):
        import json

        results = [sshfinder.HostResult(host="h", open_ports=[22], ssh_ports=[22])]
        parsed = json.loads(sshfinder.render_json(results))
        self.assertEqual(parsed[0]["host"], "h")

    def test_text_contains_summary(self):
        results = [sshfinder.HostResult(host="h", open_ports=[], ssh_ports=[])]
        text = sshfinder.render_text(results)
        self.assertIn("Scanned 1 host(s)", text)
        self.assertIn("no open ports", text)

    def test_text_shows_sockets_per_host(self):
        results = [
            sshfinder.HostResult(
                host="10.0.0.1",
                open_ports=[22],
                ssh_ports=[22],
                banners={22: "SSH-2.0-OpenSSH_9.0"},
            ),
            sshfinder.HostResult(
                host="10.0.0.2",
                open_ports=[2222],
                ssh_ports=[2222],
                banners={2222: "SSH-2.0-dropbear"},
            ),
        ]
        text = sshfinder.render_text(results)
        # Open ports and SSH services are shown as host:port sockets.
        self.assertIn("open: 10.0.0.1:22", text)
        self.assertIn("SSH  10.0.0.1:22", text)
        self.assertIn("SSH  10.0.0.2:2222", text)
        # Consolidated socket list makes multi-host results unambiguous.
        self.assertIn("SSH services found (2):", text)
        self.assertIn("  10.0.0.1:22", text)
        self.assertIn("  10.0.0.2:2222", text)

    def test_text_filtered_host_message(self):
        text = sshfinder.render_text([sshfinder.HostResult(host="h", filtered=100)])
        self.assertIn("firewalled or down", text)


# --------------------------------------------------------------------------- #
# Live loopback integration: connect scan + banner grab
# --------------------------------------------------------------------------- #
class ConnectScanTests(SSHServerMixin, unittest.TestCase):
    def test_finds_open_port(self):
        open_ports, _closed, filtered = sshfinder.connect_scan_host(
            "127.0.0.1", [self.ssh_port], timeout=1.0, workers=4, retries=0
        )
        self.assertEqual(open_ports, [self.ssh_port])
        self.assertEqual(filtered, 0)

    def test_grab_ssh_banner_detects_ssh(self):
        banner = sshfinder.grab_ssh_banner("127.0.0.1", self.ssh_port, timeout=1.0)
        self.assertIsNotNone(banner)
        self.assertTrue(banner.startswith("SSH-2.0-OpenSSH"))

    def test_scan_host_end_to_end(self):
        result = sshfinder.scan_host(
            "127.0.0.1",
            [self.ssh_port],
            scan_method="connect",
            validate="banner",
            timeout=1.0,
            workers=4,
            retries=0,
        )
        self.assertEqual(result.ssh_ports, [self.ssh_port])
        self.assertIsNone(result.error)


class ClosedPortTests(unittest.TestCase):
    def test_connect_scan_closed_port(self):
        # Port 1 on loopback is almost certainly closed and refuses fast.
        open_ports, closed, filtered = sshfinder.connect_scan_host(
            "127.0.0.1", [1], timeout=1.0, workers=1, retries=0
        )
        self.assertEqual(open_ports, [])
        self.assertEqual(closed + filtered, 1)

    def test_probe_port_stop_event_short_circuits(self):
        stop = threading.Event()
        stop.set()
        status = sshfinder._probe_port(
            "127.0.0.1", 1, timeout=1.0, retries=0, stop_event=stop
        )
        self.assertEqual(status, sshfinder.FILTERED)


# --------------------------------------------------------------------------- #
# Progress reporting
# --------------------------------------------------------------------------- #
class ProgressReporterTests(unittest.TestCase):
    def test_log_emits_socket(self):
        reporter = sshfinder.ProgressReporter(total=1, enabled=False, quiet=False)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            reporter.log("  [+] open   10.0.0.1:22")
        self.assertIn("10.0.0.1:22", stderr.getvalue())

    def test_disabled_is_noop(self):
        reporter = sshfinder.ProgressReporter(total=10, enabled=False)
        reporter.tick(5, opened=1)
        reporter.finish()  # Must not write or raise when disabled.
        self.assertEqual(reporter.done, 0)


# --------------------------------------------------------------------------- #
# Interrupt handling
# --------------------------------------------------------------------------- #
class ScanInterruptTests(unittest.TestCase):
    def test_scan_targets_stops_on_signal(self):
        """A SIGINT mid-scan must stop promptly and return partial results."""
        real_signal = signal.signal
        captured_handler = {}

        def fake_signal(signum, handler):
            # Capture only the scan's handler, not its later restoration.
            if (
                signum == signal.SIGINT
                and callable(handler)
                and "fn" not in captured_handler
            ):
                captured_handler["fn"] = handler
            return real_signal(signum, handler)

        # Many hosts, all the closed loopback port, so the scan would run a while.
        hosts = ["127.0.0.{}".format(i) for i in range(1, 40)]

        def fire_interrupt():
            time.sleep(0.2)
            handler = captured_handler.get("fn")
            if handler:
                handler(signal.SIGINT, None)

        firer = threading.Thread(target=fire_interrupt, daemon=True)
        with mock.patch.object(signal, "signal", fake_signal):
            firer.start()
            start = time.monotonic()
            results = sshfinder.scan_targets(
                hosts,
                [1],
                scan_method="connect",
                validate="none",
                timeout=2.0,
                workers=10,
                retries=0,
                host_concurrency=4,
            )
            elapsed = time.monotonic() - start
        firer.join(timeout=2)
        # Stopped well before a full sequential run and returned a list.
        self.assertLess(elapsed, 5.0)
        self.assertIsInstance(results, list)


# --------------------------------------------------------------------------- #
# SSH audit: KEXINIT parsing, weakness flagging, Terrapin, correlation
# --------------------------------------------------------------------------- #
class ParseKexinitTests(unittest.TestCase):
    def test_roundtrip(self):
        payload = build_kexinit_payload(
            kex=["curve25519-sha256", "diffie-hellman-group14-sha1"],
            hostkey=["ssh-ed25519", "ssh-rsa"],
            ciphers=["aes256-gcm@openssh.com", "aes128-cbc"],
            macs=["hmac-sha2-256", "hmac-sha1"],
        )
        parsed = sshfinder.parse_kexinit(payload)
        self.assertEqual(parsed["kex"][0], "curve25519-sha256")
        self.assertIn("ssh-rsa", parsed["server_host_key"])
        self.assertIn("aes128-cbc", parsed["enc_s2c"])

    def test_rejects_non_kexinit(self):
        self.assertIsNone(sshfinder.parse_kexinit(b"\x05garbage"))
        self.assertIsNone(sshfinder.parse_kexinit(b""))


class AssessWeaknessesTests(unittest.TestCase):
    def test_flags_legacy_algorithms(self):
        kex = sshfinder.parse_kexinit(
            build_kexinit_payload(
                kex=["diffie-hellman-group1-sha1", "curve25519-sha256"],
                hostkey=["ssh-rsa", "ssh-ed25519"],
                ciphers=["aes128-cbc", "aes256-gcm@openssh.com", "arcfour"],
                macs=["hmac-md5", "hmac-sha2-256", "hmac-sha1-96"],
            )
        )
        findings = " ".join(sshfinder.assess_weaknesses(kex))
        self.assertIn("key exchange", findings)
        self.assertIn("host key", findings)
        self.assertIn("aes128-cbc", findings)
        self.assertIn("arcfour", findings)
        self.assertIn("MAC", findings)

    def test_clean_when_modern(self):
        kex = sshfinder.parse_kexinit(
            build_kexinit_payload(
                kex=["curve25519-sha256"],
                hostkey=["ssh-ed25519"],
                ciphers=["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
                macs=["hmac-sha2-256-etm@openssh.com"],
            )
        )
        self.assertEqual(sshfinder.assess_weaknesses(kex), [])


class TerrapinTests(unittest.TestCase):
    def test_vulnerable_with_chacha_and_no_strict_kex(self):
        kex = sshfinder.parse_kexinit(
            build_kexinit_payload(
                kex=["curve25519-sha256"],
                hostkey=["ssh-ed25519"],
                ciphers=["chacha20-poly1305@openssh.com"],
                macs=["hmac-sha2-256"],
            )
        )
        self.assertIs(sshfinder.is_terrapin_vulnerable(kex), True)

    def test_safe_when_strict_kex_advertised(self):
        kex = sshfinder.parse_kexinit(
            build_kexinit_payload(
                kex=["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                hostkey=["ssh-ed25519"],
                ciphers=["chacha20-poly1305@openssh.com"],
                macs=["hmac-sha2-256"],
            )
        )
        self.assertIs(sshfinder.is_terrapin_vulnerable(kex), False)

    def test_cbc_etm_combination(self):
        kex = sshfinder.parse_kexinit(
            build_kexinit_payload(
                kex=["curve25519-sha256"],
                hostkey=["ssh-ed25519"],
                ciphers=["aes128-cbc"],
                macs=["hmac-sha2-256-etm@openssh.com"],
            )
        )
        self.assertIs(sshfinder.is_terrapin_vulnerable(kex), True)


class AuditModelTests(unittest.TestCase):
    def test_correlate_host_keys_groups_shared_fingerprints(self):
        a = sshfinder.SSHAudit(host="10.0.0.1", port=22,
                               host_key_fingerprint="SHA256:AAA")
        b = sshfinder.SSHAudit(host="10.0.0.2", port=22,
                               host_key_fingerprint="SHA256:AAA")
        c = sshfinder.SSHAudit(host="10.0.0.3", port=22,
                               host_key_fingerprint="SHA256:BBB")
        results = [
            sshfinder.HostResult(host="10.0.0.1", ssh_ports=[22], audits={22: a}),
            sshfinder.HostResult(host="10.0.0.2", ssh_ports=[22], audits={22: b}),
            sshfinder.HostResult(host="10.0.0.3", ssh_ports=[22], audits={22: c}),
        ]
        shared = sshfinder.correlate_host_keys(results)
        self.assertEqual(shared, {"SHA256:AAA": ["10.0.0.1:22", "10.0.0.2:22"]})

    def test_password_auth_property(self):
        self.assertIs(
            sshfinder.SSHAudit(host="h", port=22,
                               auth_methods=["publickey"]).password_auth,
            False,
        )
        self.assertTrue(
            sshfinder.SSHAudit(host="h", port=22,
                               auth_methods=["publickey", "password"]).password_auth
        )

    def test_render_audit_block_shows_findings(self):
        audit = sshfinder.SSHAudit(
            host="10.0.0.1",
            port=22,
            host_key_type="ssh-ed25519",
            host_key_fingerprint="SHA256:XYZ",
            auth_methods=["publickey", "password"],
            terrapin_vulnerable=True,
            weaknesses=["weak ciphers: aes128-cbc"],
        )
        result = sshfinder.HostResult(
            host="10.0.0.1", open_ports=[22], ssh_ports=[22], audits={22: audit}
        )
        text = sshfinder.render_text([result])
        self.assertIn("host key: ssh-ed25519 SHA256:XYZ", text)
        self.assertIn("password auth enabled", text)
        self.assertIn("Terrapin (CVE-2023-48795): VULNERABLE", text)
        self.assertIn("aes128-cbc", text)


class LiveKexinitTests(unittest.TestCase):
    def test_read_server_kexinit_live(self):
        """End-to-end raw KEXINIT read against a fake server."""
        payload = build_kexinit_payload(
            kex=["curve25519-sha256"],
            hostkey=["ssh-ed25519"],
            ciphers=["chacha20-poly1305@openssh.com"],
            macs=["hmac-sha2-256"],
        )

        def serve(conn):
            conn.sendall(b"SSH-2.0-FakeServer_1.0\r\n")
            conn.sendall(packetize(payload))
            conn.recv(64)

        with LoopbackServer(serve, backlog=1) as server:
            kex = sshfinder.read_server_kexinit("127.0.0.1", server.port, timeout=2.0)

        self.assertIsNotNone(kex)
        self.assertEqual(kex["banner"], "SSH-2.0-FakeServer_1.0")
        self.assertEqual(kex["kex"], ["curve25519-sha256"])
        self.assertIs(sshfinder.is_terrapin_vulnerable(kex), True)


@unittest.skipIf(paramiko is None, "paramiko is not installed")
class ParamikoAuditTests(unittest.TestCase):
    def test_audit_enumerates_auth_methods(self):
        """Deep audit: host key fingerprint and accepted auth methods.

        Runs a real Paramiko server so the partial handshake and the
        unauthenticated 'none' auth probe are exercised end to end.
        """
        host_key = paramiko.RSAKey.generate(2048)

        class _Server(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "publickey,password"

            def check_auth_password(self, username, password):
                return paramiko.AUTH_FAILED

            def check_auth_publickey(self, username, key):
                return paramiko.AUTH_FAILED

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=_Server())
                time.sleep(1.0)
            except Exception:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            key_type, fingerprint, methods = sshfinder._audit_with_paramiko(
                "127.0.0.1", port, timeout=5.0
            )
        finally:
            srv.close()
            thread.join(timeout=2)

        self.assertTrue(key_type.startswith("ssh-rsa"))
        self.assertTrue(fingerprint.startswith("SHA256:"))
        self.assertEqual(set(methods), {"publickey", "password"})


# --------------------------------------------------------------------------- #
# Pipelined service identification and open-port annotation
# --------------------------------------------------------------------------- #
class ServiceIdentificationTests(unittest.TestCase):
    def test_scan_host_classifies_non_ssh_open_port(self):
        with LoopbackServer(_serve_http) as server:
            result = sshfinder.scan_host(
                "127.0.0.1",
                [server.port],
                scan_method="connect",
                validate="banner",
                timeout=1.0,
                workers=4,
                retries=0,
            )
            self.assertEqual(result.open_ports, [server.port])
            self.assertEqual(result.ssh_ports, [])   # open but not SSH
            self.assertIs(result.service_checked, True)

    def test_render_text_annotates_service_type(self):
        result = sshfinder.HostResult(
            host="10.0.0.1",
            open_ports=[22, 8080],
            ssh_ports=[22],
            banners={22: "SSH-2.0-OpenSSH_9.0"},
            service_checked=True,
        )
        text = sshfinder.render_text([result])
        self.assertIn("10.0.0.1:22 [SSH]", text)
        self.assertIn("10.0.0.1:8080 [not ssh]", text)

    def test_render_text_marks_unknown_when_not_validated(self):
        result = sshfinder.HostResult(
            host="10.0.0.1", open_ports=[1234], service_checked=False
        )
        text = sshfinder.render_text([result])
        self.assertIn("10.0.0.1:1234 [service unknown]", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
