"""Unit tests for the pure, side-effect-free parts of sshfinder.

The suite is written against the standard library only, so it runs with
``python -m unittest discover -s tests`` on a bare interpreter. Tests that
need an optional dependency (Paramiko) skip themselves when it is absent.
"""

import contextlib
import io
import json
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


def _serve_ssh_with_preamble(conn):
    """RFC 4253 4.2 lets a server precede its identification with free text."""
    conn.sendall(b"*** Authorized access only ***\r\n")
    conn.sendall(b"Contact ops@example.com\r\n")
    conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
    conn.recv(64)


def _serve_ssh_client_first(conn):
    """A server that withholds its banner until the client identifies."""
    conn.recv(64)
    conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")


def _serve_ssh_fragmented(conn):
    """A banner split across TCP segments, as a slow link would deliver it."""
    conn.sendall(b"SS")
    time.sleep(0.15)
    conn.sendall(b"H-2.0-OpenSSH_9.0\r\n")
    conn.recv(64)


def _serve_http(conn):
    conn.recv(64)
    conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")


class BlackholePort:
    """A loopback port that silently drops connection attempts.

    Saturating a listen backlog makes the kernel discard further SYNs instead
    of answering them, which is a deterministic stand-in for a firewalled port
    -- no network, no fixtures, no waiting on a real unreachable host. Not
    every platform overflows this way, so call :meth:`drops_syns` and skip
    when it does not.
    """

    def __init__(self, saturation=20, settle=0.3):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)  # Tiny queue, never accepted from.
        self.port = self._sock.getsockname()[1]
        self._held = []
        for _ in range(saturation):
            filler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            filler.setblocking(False)
            filler.connect_ex(("127.0.0.1", self.port))
            self._held.append(filler)
        time.sleep(settle)

    def drops_syns(self, timeout=0.5):
        """True if a connection attempt really does hang rather than answer."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(timeout)
        try:
            probe.connect(("127.0.0.1", self.port))
            return False
        except socket.timeout:
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def close(self):
        for filler in self._held:
            try:
                filler.close()
            except OSError:
                pass
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


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

    def test_sweep_stops_on_stop_event(self):
        stop = threading.Event()
        stop.set()
        outcome = sshfinder._connect_sweep(
            "127.0.0.1", [1, 2, 3], timeout=1.0, max_inflight=4, stop_event=stop
        )
        self.assertEqual(outcome.probed, 0)
        self.assertEqual(outcome.open_ports, [])


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


# --------------------------------------------------------------------------- #
# Post-quantum readiness
# --------------------------------------------------------------------------- #
# The standardised hybrid a current OpenSSH client prefers.
MLKEM = "mlkem768x25519-sha256"


def _kex_offering(*algorithms):
    """A parsed KEXINIT whose server offers exactly ``algorithms``."""
    return sshfinder.parse_kexinit(
        build_kexinit_payload(
            kex=list(algorithms),
            hostkey=["ssh-ed25519"],
            ciphers=["aes256-gcm@openssh.com"],
            macs=["hmac-sha2-256-etm@openssh.com"],
        )
    )


class AssessPostQuantumTests(unittest.TestCase):
    def test_mlkem_is_ready(self):
        status, algorithms = sshfinder.assess_post_quantum(
            _kex_offering("mlkem768x25519-sha256", "curve25519-sha256")
        )
        self.assertEqual(status, sshfinder.PQ_READY)
        self.assertEqual(algorithms, ["mlkem768x25519-sha256"])

    def test_sntrup761_is_ready(self):
        status, _ = sshfinder.assess_post_quantum(
            _kex_offering("sntrup761x25519-sha512", "curve25519-sha256")
        )
        self.assertEqual(status, sshfinder.PQ_READY)

    def test_openssh_suffixed_spellings_are_ready(self):
        for name in (
            "sntrup761x25519-sha512@openssh.com",
            "mlkem768x25519-sha256@openssh.com",
        ):
            with self.subTest(algorithm=name):
                status, _ = sshfinder.assess_post_quantum(_kex_offering(name))
                self.assertEqual(status, sshfinder.PQ_READY)

    def test_withdrawn_tinyssh_parameter_set_is_legacy(self):
        """Looks post-quantum in a dump; a current client gets none."""
        status, algorithms = sshfinder.assess_post_quantum(
            _kex_offering(
                "sntrup4591761x25519-sha512@tinyssh.org", "curve25519-sha256"
            )
        )
        self.assertEqual(status, sshfinder.PQ_LEGACY)
        self.assertEqual(algorithms, ["sntrup4591761x25519-sha512@tinyssh.org"])

    def test_kyber_drafts_are_legacy(self):
        for name in (
            "x25519-kyber-512r3-sha256-d00@amazon.com",
            "ecdh-nistp256-kyber-512r3-sha256-d00",
        ):
            with self.subTest(algorithm=name):
                status, _ = sshfinder.assess_post_quantum(_kex_offering(name))
                self.assertEqual(status, sshfinder.PQ_LEGACY)

    def test_standard_alongside_draft_is_ready(self):
        """One usable hybrid is enough, whatever else is on offer."""
        status, algorithms = sshfinder.assess_post_quantum(
            _kex_offering(
                "sntrup4591761x25519-sha512@tinyssh.org",
                "mlkem768x25519-sha256",
            )
        )
        self.assertEqual(status, sshfinder.PQ_READY)
        self.assertEqual(len(algorithms), 2)

    def test_classical_only_is_absent(self):
        status, algorithms = sshfinder.assess_post_quantum(
            _kex_offering("curve25519-sha256", "ecdh-sha2-nistp256")
        )
        self.assertEqual(status, sshfinder.PQ_ABSENT)
        self.assertEqual(algorithms, [])

    def test_unknown_vendor_hybrid_is_not_reported_as_absent(self):
        """A future spelling must not be mistaken for having no PQ at all."""
        status, _ = sshfinder.assess_post_quantum(
            _kex_offering("mlkem1024nistp384-sha384", "curve25519-sha256")
        )
        self.assertEqual(status, sshfinder.PQ_LEGACY)

    def test_case_is_ignored(self):
        status, _ = sshfinder.assess_post_quantum(
            _kex_offering("ECDH-NISTP256-KYBER-512R3-SHA256-D00")
        )
        self.assertEqual(status, sshfinder.PQ_LEGACY)

    def test_unreadable_kexinit_claims_nothing(self):
        for kex in (None, {}, {"kex": []}):
            with self.subTest(kex=kex):
                status, algorithms = sshfinder.assess_post_quantum(kex)
                self.assertEqual(status, sshfinder.PQ_UNKNOWN)
                self.assertEqual(algorithms, [])


class PostQuantumAuditTests(unittest.TestCase):
    """End to end: KEXINIT on the wire through to the audit verdict."""

    def _audit_offering(self, algorithms):
        payload = build_kexinit_payload(
            kex=algorithms,
            hostkey=["ssh-ed25519"],
            ciphers=["aes256-gcm@openssh.com"],
            macs=["hmac-sha2-256-etm@openssh.com"],
        )

        def serve(conn):
            conn.sendall(b"SSH-2.0-FakeServer_1.0\r\n")
            conn.sendall(packetize(payload))
            conn.recv(64)

        with LoopbackServer(serve) as server:
            return sshfinder.audit_ssh_service(
                "127.0.0.1", server.port, 2.0, deep=False
            )

    def test_ready_server(self):
        audit = self._audit_offering(
            ["mlkem768x25519-sha256", "curve25519-sha256"]
        )
        self.assertEqual(audit.pq_status, sshfinder.PQ_READY)
        self.assertEqual(audit.pq_kex, ["mlkem768x25519-sha256"])

    def test_absent_server(self):
        audit = self._audit_offering(["curve25519-sha256"])
        self.assertEqual(audit.pq_status, sshfinder.PQ_ABSENT)

    def test_shallow_audit_needs_no_paramiko(self):
        """The PQ verdict comes from the KEXINIT, so no dependency is needed."""
        audit = self._audit_offering(["mlkem768x25519-sha256"])
        self.assertEqual(audit.pq_status, sshfinder.PQ_READY)
        self.assertEqual(audit.host_key_fingerprint, "")  # Deep probe skipped.
        self.assertEqual(audit.notes, [])

    def test_unreachable_service_stays_unknown(self):
        audit = sshfinder.audit_ssh_service("127.0.0.1", 1, 0.5, deep=False)
        self.assertEqual(audit.pq_status, sshfinder.PQ_UNKNOWN)

    def test_audit_dict_carries_the_verdict(self):
        audit = self._audit_offering(["mlkem768x25519-sha256"])
        payload = audit.as_dict()
        self.assertEqual(payload["pq_status"], sshfinder.PQ_READY)
        self.assertEqual(payload["pq_kex"], ["mlkem768x25519-sha256"])


class PostQuantumRenderTests(unittest.TestCase):
    def _result(self, host, port, status, algorithms=()):
        audit = sshfinder.SSHAudit(
            host=host, port=port, pq_status=status, pq_kex=list(algorithms)
        )
        return sshfinder.HostResult(
            host=host, open_ports=[port], ssh_ports=[port], audits={port: audit}
        )

    def test_service_line_states_readiness(self):
        text = sshfinder.render_text([
            self._result("10.0.0.1", 22, sshfinder.PQ_READY,
                         ["mlkem768x25519-sha256"])
        ])
        self.assertIn("post-quantum: ready", text)
        self.assertIn("mlkem768x25519-sha256", text)

    def test_service_line_flags_absence(self):
        text = sshfinder.render_text([
            self._result("10.0.0.1", 22, sshfinder.PQ_ABSENT)
        ])
        self.assertIn("no PQ key exchange offered", text)
        self.assertIn("store-now-decrypt-later", text)

    def test_service_line_explains_pre_standard(self):
        text = sshfinder.render_text([
            self._result("10.0.0.1", 22, sshfinder.PQ_LEGACY,
                         ["sntrup4591761x25519-sha512@tinyssh.org"])
        ])
        self.assertIn("pre-standard only", text)
        self.assertIn("negotiates classical crypto", text)

    def test_unknown_verdict_claims_nothing_per_service(self):
        audit = sshfinder.SSHAudit(
            host="10.0.0.1", port=22, pq_status=sshfinder.PQ_UNKNOWN
        )
        self.assertEqual(sshfinder._render_pq(audit), [])

    def test_posture_groups_every_service(self):
        posture = sshfinder.collect_pq_posture([
            self._result("10.0.0.1", 22, sshfinder.PQ_READY, [MLKEM]),
            self._result("10.0.0.2", 22, sshfinder.PQ_ABSENT),
            self._result("10.0.0.3", 2222, sshfinder.PQ_LEGACY, ["draft"]),
        ])
        self.assertEqual(posture[sshfinder.PQ_READY], ["10.0.0.1:22"])
        self.assertEqual(posture[sshfinder.PQ_ABSENT], ["10.0.0.2:22"])
        self.assertEqual(posture[sshfinder.PQ_LEGACY], ["10.0.0.3:2222"])

    def test_fleet_report_counts_and_lists_the_exposed(self):
        report = sshfinder.render_pq_report([
            self._result("10.0.0.1", 22, sshfinder.PQ_READY, [MLKEM]),
            self._result("10.0.0.2", 22, sshfinder.PQ_ABSENT),
            self._result("10.0.0.3", 22, sshfinder.PQ_LEGACY, ["kyber-draft"]),
        ])
        self.assertIn("1/3 service(s) negotiate post-quantum", report)
        self.assertIn("10.0.0.2:22", report)
        self.assertIn("10.0.0.3:22", report)
        # Exposed counts the absent and the pre-standard together.
        self.assertIn("2 service(s) exposed", report)

    def test_fleet_report_is_quiet_when_all_ready(self):
        report = sshfinder.render_pq_report([
            self._result("10.0.0.1", 22, sshfinder.PQ_READY, [MLKEM])
        ])
        self.assertIn("1/1", report)
        self.assertNotIn("exposed", report)

    def test_fleet_report_without_audits(self):
        report = sshfinder.render_pq_report([sshfinder.HostResult(host="h")])
        self.assertIn("no SSH services were audited", report)

    def test_unaudited_scan_shows_no_pq_block(self):
        text = sshfinder.render_text([
            sshfinder.HostResult(host="h", open_ports=[22], ssh_ports=[22])
        ])
        self.assertNotIn("Post-quantum readiness", text)


class PostQuantumCLITests(unittest.TestCase):
    def _serve_pq(self, algorithms):
        payload = build_kexinit_payload(
            kex=algorithms,
            hostkey=["ssh-ed25519"],
            ciphers=["aes256-gcm@openssh.com"],
            macs=["hmac-sha2-256-etm@openssh.com"],
        )

        def serve(conn):
            conn.sendall(b"SSH-2.0-FakeServer_1.0\r\n")
            conn.sendall(packetize(payload))
            conn.recv(64)

        return serve

    def test_flag_defaults_off(self):
        args = sshfinder.build_parser().parse_args(["10.0.0.1"])
        self.assertFalse(args.pq_report)

    def test_pq_report_prints_only_the_readiness_view(self):
        with LoopbackServer(self._serve_pq(["curve25519-sha256"])) as server:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = sshfinder.run(
                    ["127.0.0.1", "-p", str(server.port), "--pq-report", "-q"]
                )
        self.assertEqual(exit_code, 0)
        report = stdout.getvalue()
        self.assertIn("Post-quantum readiness:", report)
        self.assertIn("no PQ key exchange offered", report)
        # The full per-host listing would bury the answer across an estate.
        self.assertNotIn("=== 127.0.0.1 ===", report)

    def test_pq_report_json_carries_the_verdict(self):
        with LoopbackServer(self._serve_pq([MLKEM])) as server:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                sshfinder.run(
                    ["127.0.0.1", "-p", str(server.port), "--pq-report",
                     "--json", "-q"]
                )
            parsed = json.loads(stdout.getvalue())
        audit = parsed[0]["audit"][str(server.port)]
        self.assertEqual(audit["pq_status"], sshfinder.PQ_READY)

    def test_pq_report_forces_validation_on(self):
        """--validate none would leave nothing to audit."""
        with LoopbackServer(self._serve_pq([MLKEM])) as server:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                sshfinder.run(
                    ["127.0.0.1", "-p", str(server.port), "--pq-report",
                     "--validate", "none", "-q"]
                )
        self.assertIn("1/1", stdout.getvalue())


# --------------------------------------------------------------------------- #
# Policy engine
# --------------------------------------------------------------------------- #
def _policy_file(case, document):
    """Write a policy document to a temporary path scoped to ``case``."""
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    path = os.path.join(tmp.name, "policy.json")
    with open(path, "w", encoding="utf-8") as handle:
        if isinstance(document, str):
            handle.write(document)
        else:
            json.dump(document, handle)
    return path


class LoadPolicyTests(unittest.TestCase):
    def test_builtin_policies_load(self):
        for name in sshfinder.BUILTIN_POLICIES:
            with self.subTest(policy=name):
                policy = sshfinder.load_policy(name)
                self.assertEqual(policy.name, name)
                self.assertTrue(policy.rules)

    def test_only_auth_rules_need_the_deep_probe(self):
        self.assertTrue(sshfinder.load_policy("baseline").needs_auth_methods)
        self.assertFalse(sshfinder.load_policy("pq").needs_auth_methods)

    def test_policy_document_from_a_path(self):
        path = _policy_file(self, {
            "name": "house",
            "description": "house rules",
            "rules": [{"check": "terrapin", "severity": "warn"}],
        })
        policy = sshfinder.load_policy(path)
        self.assertEqual(policy.name, "house")
        self.assertEqual(policy.description, "house rules")
        self.assertEqual(policy.rules[0]["severity"], "warn")

    def test_severity_defaults_to_fail(self):
        path = _policy_file(self, {"rules": [{"check": "terrapin"}]})
        policy = sshfinder.load_policy(path)
        self.assertEqual(policy.rules[0]["severity"], sshfinder.SEVERITY_FAIL)

    def test_unknown_check_is_rejected(self):
        """A typo must never quietly turn a failing estate green."""
        path = _policy_file(self, {"rules": [{"check": "pasword_auth"}]})
        with self.assertRaises(sshfinder.PolicyError) as ctx:
            sshfinder.load_policy(path)
        self.assertIn("pasword_auth", str(ctx.exception))
        self.assertIn("known:", str(ctx.exception))

    def test_unknown_severity_is_rejected(self):
        path = _policy_file(self, {
            "rules": [{"check": "terrapin", "severity": "critical"}]
        })
        with self.assertRaises(sshfinder.PolicyError):
            sshfinder.load_policy(path)

    def test_unknown_field_is_rejected(self):
        path = _policy_file(self, {
            "rules": [{"check": "forbid", "field": "cyphers",
                       "algorithms": ["3des-cbc"]}]
        })
        with self.assertRaises(sshfinder.PolicyError) as ctx:
            sshfinder.load_policy(path)
        self.assertIn("cyphers", str(ctx.exception))

    def test_unknown_pq_requirement_is_rejected(self):
        path = _policy_file(self, {
            "rules": [{"check": "post_quantum", "require": "quantum-proof"}]
        })
        with self.assertRaises(sshfinder.PolicyError):
            sshfinder.load_policy(path)

    def test_empty_algorithm_list_is_rejected(self):
        for algorithms in ([], "3des-cbc", [42]):
            with self.subTest(algorithms=algorithms):
                path = _policy_file(self, {
                    "rules": [{"check": "forbid", "field": "ciphers",
                               "algorithms": algorithms}]
                })
                with self.assertRaises(sshfinder.PolicyError):
                    sshfinder.load_policy(path)

    def test_policy_without_rules_is_rejected(self):
        for document in ({"rules": []}, {"name": "x"}, []):
            with self.subTest(document=document):
                path = _policy_file(self, document)
                with self.assertRaises(sshfinder.PolicyError):
                    sshfinder.load_policy(path)

    def test_malformed_json_is_rejected(self):
        path = _policy_file(self, "{not json")
        with self.assertRaises(sshfinder.PolicyError) as ctx:
            sshfinder.load_policy(path)
        self.assertIn("not valid JSON", str(ctx.exception))

    def test_missing_file_names_the_builtins(self):
        with self.assertRaises(sshfinder.PolicyError) as ctx:
            sshfinder.load_policy("/no/such/policy.json")
        self.assertIn("baseline", str(ctx.exception))

    def test_rule_must_be_an_object(self):
        path = _policy_file(self, {"rules": ["terrapin"]})
        with self.assertRaises(sshfinder.PolicyError):
            sshfinder.load_policy(path)


class EvaluatePolicyTests(unittest.TestCase):
    def _policy(self, *rules):
        return sshfinder.load_policy(_policy_file(self, {"rules": list(rules)}))

    def _checks(self, policy, audit):
        return [v.check for v in sshfinder.evaluate_policy(policy, audit)]

    def test_password_auth_rule(self):
        policy = self._policy({"check": "password_auth"})
        offender = sshfinder.SSHAudit(
            host="h", port=22, auth_methods=["publickey", "password"]
        )
        clean = sshfinder.SSHAudit(
            host="h", port=22, auth_methods=["publickey"]
        )
        self.assertEqual(self._checks(policy, offender), ["password_auth"])
        self.assertEqual(self._checks(policy, clean), [])

    def test_terrapin_rule(self):
        policy = self._policy({"check": "terrapin"})
        vulnerable = sshfinder.SSHAudit(
            host="h", port=22, terrapin_vulnerable=True
        )
        safe = sshfinder.SSHAudit(host="h", port=22, terrapin_vulnerable=False)
        self.assertEqual(self._checks(policy, vulnerable), ["terrapin"])
        self.assertEqual(self._checks(policy, safe), [])

    def test_weak_algorithms_rule(self):
        policy = self._policy({"check": "weak_algorithms"})
        audit = sshfinder.SSHAudit(
            host="h", port=22, weaknesses=["weak ciphers: aes128-cbc"]
        )
        violations = sshfinder.evaluate_policy(policy, audit)
        self.assertEqual(len(violations), 1)
        self.assertIn("aes128-cbc", violations[0].detail)

    def test_post_quantum_rule_ranks_verdicts(self):
        policy = self._policy({"check": "post_quantum", "require": "ready"})
        for status, expected in (
            (sshfinder.PQ_READY, []),
            (sshfinder.PQ_LEGACY, ["post_quantum"]),
            (sshfinder.PQ_ABSENT, ["post_quantum"]),
            (sshfinder.PQ_UNKNOWN, ["post_quantum"]),
        ):
            with self.subTest(status=status):
                audit = sshfinder.SSHAudit(host="h", port=22, pq_status=status)
                self.assertEqual(self._checks(policy, audit), expected)

    def test_post_quantum_rule_accepts_a_lower_bar(self):
        """Requiring only 'legacy' passes a pre-standard server."""
        policy = self._policy({"check": "post_quantum", "require": "legacy"})
        audit = sshfinder.SSHAudit(
            host="h", port=22, pq_status=sshfinder.PQ_LEGACY
        )
        self.assertEqual(self._checks(policy, audit), [])

    def test_forbid_rule(self):
        policy = self._policy({
            "check": "forbid", "field": "ciphers",
            "algorithms": ["3des-cbc", "arcfour"],
        })
        audit = sshfinder.SSHAudit(
            host="h", port=22, ciphers=["aes256-gcm@openssh.com", "3des-cbc"]
        )
        violations = sshfinder.evaluate_policy(policy, audit)
        self.assertEqual(len(violations), 1)
        self.assertIn("3des-cbc", violations[0].detail)
        self.assertNotIn("arcfour", violations[0].detail)

    def test_require_rule(self):
        policy = self._policy({
            "check": "require", "field": "kex_algorithms",
            "algorithms": ["curve25519-sha256", "mlkem768x25519-sha256"],
        })
        audit = sshfinder.SSHAudit(
            host="h", port=22, kex_algorithms=["curve25519-sha256"]
        )
        violations = sshfinder.evaluate_policy(policy, audit)
        self.assertEqual(len(violations), 1)
        self.assertIn("mlkem768x25519-sha256", violations[0].detail)

    def test_clean_service_has_no_violations(self):
        policy = sshfinder.load_policy("strict")
        audit = sshfinder.SSHAudit(
            host="h", port=22,
            auth_methods=["publickey"],
            terrapin_vulnerable=False,
            pq_status=sshfinder.PQ_READY,
            host_key_algorithms=["ssh-ed25519"],
        )
        self.assertEqual(sshfinder.evaluate_policy(policy, audit), [])

    def test_severity_is_carried_through(self):
        policy = self._policy(
            {"check": "terrapin", "severity": "warn"},
            {"check": "weak_algorithms", "severity": "fail"},
        )
        audit = sshfinder.SSHAudit(
            host="h", port=22, terrapin_vulnerable=True, weaknesses=["bad"]
        )
        found = sshfinder.evaluate_policy(policy, audit)
        severities = {v.check: v.severity for v in found}
        self.assertEqual(severities["terrapin"], sshfinder.SEVERITY_WARN)
        self.assertEqual(severities["weak_algorithms"], sshfinder.SEVERITY_FAIL)


def _audited(host, port, **audit_kwargs):
    """A HostResult carrying one audited SSH service."""
    audit = sshfinder.SSHAudit(host=host, port=port, **audit_kwargs)
    return sshfinder.HostResult(
        host=host, open_ports=[port], ssh_ports=[port], audits={port: audit}
    )


def _sample_estate():
    """Three services: one compliant, one warning-only, one failing."""
    return [
        _audited("10.0.0.1", 22, auth_methods=["publickey"],
                 terrapin_vulnerable=False, pq_status=sshfinder.PQ_READY),
        _audited("10.0.0.2", 22, auth_methods=["publickey"],
                 terrapin_vulnerable=False, pq_status=sshfinder.PQ_ABSENT),
        _audited("10.0.0.3", 22, auth_methods=["password"],
                 terrapin_vulnerable=True, pq_status=sshfinder.PQ_ABSENT),
    ]


class ApplyPolicyTests(unittest.TestCase):
    def test_offenders_bucket_by_worst_severity(self):
        results = _sample_estate()
        offenders = sshfinder.apply_policy(
            sshfinder.load_policy("baseline"), results
        )
        self.assertEqual(offenders[sshfinder.SEVERITY_FAIL], ["10.0.0.3:22"])
        self.assertEqual(offenders[sshfinder.SEVERITY_WARN], ["10.0.0.2:22"])

    def test_violations_are_recorded_on_the_audit(self):
        results = _sample_estate()
        sshfinder.apply_policy(sshfinder.load_policy("baseline"), results)
        clean = results[0].audits[22]
        offender = results[2].audits[22]
        self.assertEqual(clean.violations, [])
        self.assertIn("password_auth", [v.check for v in offender.violations])
        self.assertIn("violations", offender.as_dict())
        self.assertEqual(
            offender.as_dict()["violations"][0]["severity"],
            sshfinder.SEVERITY_FAIL,
        )

    def test_reevaluation_replaces_rather_than_accumulates(self):
        results = _sample_estate()
        policy = sshfinder.load_policy("baseline")
        sshfinder.apply_policy(policy, results)
        first = len(results[2].audits[22].violations)
        sshfinder.apply_policy(policy, results)
        self.assertEqual(len(results[2].audits[22].violations), first)


class PolicyExitCodeTests(unittest.TestCase):
    def test_clean_estate_passes(self):
        self.assertEqual(sshfinder.policy_exit_code({}, "fail"), 0)

    def test_failure_gates_by_default(self):
        offenders = {sshfinder.SEVERITY_FAIL: ["10.0.0.1:22"]}
        self.assertEqual(
            sshfinder.policy_exit_code(offenders, "fail"),
            sshfinder.EXIT_POLICY_VIOLATION,
        )

    def test_warnings_do_not_gate_by_default(self):
        offenders = {sshfinder.SEVERITY_WARN: ["10.0.0.1:22"]}
        self.assertEqual(sshfinder.policy_exit_code(offenders, "fail"), 0)

    def test_fail_on_warn_escalates(self):
        offenders = {sshfinder.SEVERITY_WARN: ["10.0.0.1:22"]}
        self.assertEqual(
            sshfinder.policy_exit_code(offenders, "warn"),
            sshfinder.EXIT_POLICY_VIOLATION,
        )

    def test_fail_on_never_reports_without_gating(self):
        offenders = {sshfinder.SEVERITY_FAIL: ["10.0.0.1:22"]}
        self.assertEqual(sshfinder.policy_exit_code(offenders, "never"), 0)


class PolicyRenderTests(unittest.TestCase):
    def _estate_report(self, policy_name="baseline"):
        results = _sample_estate()
        policy = sshfinder.load_policy(policy_name)
        offenders = sshfinder.apply_policy(policy, results)
        return sshfinder.render_policy_report(policy, offenders, results)

    def test_report_counts_and_names_offenders(self):
        report = self._estate_report()
        self.assertIn("Policy 'baseline'", report)
        self.assertIn("1/3 service(s) pass", report)
        self.assertIn("10.0.0.3:22", report)
        self.assertIn("password_auth", report)

    def test_listed_service_shows_all_its_violations(self):
        """A service in the FAIL bucket still needs its warnings fixed."""
        report = self._estate_report()
        self.assertIn("terrapin", report)
        self.assertIn("post_quantum (warn)", report)

    def test_report_without_audits(self):
        policy = sshfinder.load_policy("pq")
        report = sshfinder.render_policy_report(
            policy, {}, [sshfinder.HostResult(host="h")]
        )
        self.assertIn("no SSH services were audited", report)

    def test_service_block_marks_severity(self):
        audit = sshfinder.SSHAudit(
            host="10.0.0.1", port=22,
            violations=[
                sshfinder.Violation(
                    "terrapin", sshfinder.SEVERITY_FAIL, "boom"
                ),
                sshfinder.Violation("post_quantum", sshfinder.SEVERITY_WARN,
                                    "no PQ"),
            ],
        )
        result = sshfinder.HostResult(
            host="10.0.0.1", open_ports=[22], ssh_ports=[22], audits={22: audit}
        )
        text = sshfinder.render_text([result])
        self.assertIn("[FAIL] policy/terrapin", text)
        self.assertIn("[warn] policy/post_quantum", text)


class PolicyCLITests(unittest.TestCase):
    def _serve_kex(self, kex, ciphers=("aes256-gcm@openssh.com",),
                   macs=("hmac-sha2-256-etm@openssh.com",)):
        payload = build_kexinit_payload(
            kex=list(kex), hostkey=["ssh-ed25519"],
            ciphers=list(ciphers), macs=list(macs),
        )

        def serve(conn):
            conn.sendall(b"SSH-2.0-FakeServer_1.0\r\n")
            conn.sendall(packetize(payload))
            conn.recv(64)

        return serve

    def _run(self, port, *extra):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = sshfinder.run(["127.0.0.1", "-p", str(port), "-q", *extra])
        return code, stdout.getvalue()

    def test_defaults(self):
        args = sshfinder.build_parser().parse_args(["10.0.0.1"])
        self.assertIsNone(args.policy)
        self.assertEqual(args.fail_on, sshfinder.SEVERITY_FAIL)

    def test_compliant_service_exits_zero(self):
        with LoopbackServer(self._serve_kex([MLKEM])) as server:
            code, report = self._run(server.port, "--policy", "pq")
        self.assertEqual(code, 0)
        self.assertIn("1/1 service(s) pass", report)

    def test_violating_service_gates_the_run(self):
        with LoopbackServer(self._serve_kex(["curve25519-sha256"])) as server:
            code, report = self._run(server.port, "--policy", "pq")
        self.assertEqual(code, sshfinder.EXIT_POLICY_VIOLATION)
        self.assertIn("[FAIL]", report)

    def test_fail_on_never_reports_without_gating(self):
        with LoopbackServer(self._serve_kex(["curve25519-sha256"])) as server:
            code, report = self._run(
                server.port, "--policy", "pq", "--fail-on", "never"
            )
        self.assertEqual(code, 0)
        self.assertIn("[FAIL]", report)  # Still reported, just not gated.

    def test_fail_on_warn_escalates_a_warning(self):
        path = _policy_file(self, {
            "rules": [{"check": "post_quantum", "require": "ready",
                       "severity": "warn"}]
        })
        with LoopbackServer(self._serve_kex(["curve25519-sha256"])) as server:
            lenient, _ = self._run(server.port, "--policy", path)
            strict, _ = self._run(
                server.port, "--policy", path, "--fail-on", "warn"
            )
        self.assertEqual(lenient, 0)
        self.assertEqual(strict, sshfinder.EXIT_POLICY_VIOLATION)

    def test_bad_policy_exits_before_scanning(self):
        path = _policy_file(self, {"rules": [{"check": "nonsense"}]})
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(io.StringIO()):
                sshfinder.run(["127.0.0.1", "-p", "22", "--policy", path])
        self.assertEqual(ctx.exception.code, 2)

    def test_json_output_carries_violations(self):
        with LoopbackServer(self._serve_kex(["curve25519-sha256"])) as server:
            code, out = self._run(server.port, "--policy", "pq", "--json")
        self.assertEqual(code, sshfinder.EXIT_POLICY_VIOLATION)
        audit = json.loads(out)[0]["audit"][str(server.port)]
        self.assertEqual(audit["violations"][0]["check"], "post_quantum")

    def test_crypto_only_policy_needs_no_paramiko(self):
        """--policy pq must run shallow, so a bare interpreter can gate."""
        self.assertFalse(sshfinder.load_policy("pq").needs_auth_methods)
        with LoopbackServer(self._serve_kex([MLKEM])) as server:
            code, _ = self._run(server.port, "--policy", "pq")
        self.assertEqual(code, 0)

    def test_audit_report_appends_the_verdict(self):
        with LoopbackServer(self._serve_kex(["curve25519-sha256"])) as server:
            code, report = self._run(server.port, "--policy", "pq", "--audit")
        self.assertEqual(code, sshfinder.EXIT_POLICY_VIOLATION)
        self.assertIn("=== 127.0.0.1 ===", report)   # Full report, and
        self.assertIn("Policy 'pq'", report)         # the verdict after it.


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


# --------------------------------------------------------------------------- #
# Port ordering and target-expansion limits
# --------------------------------------------------------------------------- #
class OrderPortsTests(unittest.TestCase):
    def test_ssh_ports_come_first(self):
        ordered = sshfinder.order_ports(range(1, 100))
        self.assertEqual(ordered[0], 22)
        self.assertEqual(ordered[1], 1)  # Then plain ascending order.

    def test_all_priority_ports_promoted(self):
        ordered = sshfinder.order_ports([80, 443, 2222, 22, 8022])
        self.assertEqual(ordered[:3], [22, 2222, 8022])
        self.assertEqual(ordered[3:], [80, 443])

    def test_deduplicates_and_preserves_every_port(self):
        ordered = sshfinder.order_ports([22, 22, 80, 80, 443])
        self.assertEqual(sorted(ordered), [22, 80, 443])
        self.assertEqual(len(ordered), 3)

    def test_empty_input(self):
        self.assertEqual(sshfinder.order_ports([]), [])


class ExpandTargetsLimitTests(unittest.TestCase):
    def test_oversized_ipv4_network_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            sshfinder.expand_targets(["10.0.0.0/8"])
        self.assertIn("max-targets", str(ctx.exception))

    def test_oversized_ipv6_network_rejected(self):
        # A /64 is 2**64 addresses; materialising it would never return.
        with self.assertRaises(ValueError):
            sshfinder.expand_targets(["2001:db8::/64"])

    def test_limit_is_configurable(self):
        hosts = sshfinder.expand_targets(["192.168.1.0/24"], max_targets=254)
        self.assertEqual(len(hosts), 254)
        with self.assertRaises(ValueError):
            sshfinder.expand_targets(["192.168.1.0/24"], max_targets=10)

    def test_accumulated_tokens_respect_limit(self):
        with self.assertRaises(ValueError):
            sshfinder.expand_targets(["10.0.0.1", "10.0.0.2"], max_targets=1)

    def test_invalid_limit_rejected(self):
        with self.assertRaises(ValueError):
            sshfinder.expand_targets(["10.0.0.1"], max_targets=0)


# --------------------------------------------------------------------------- #
# Endpoint resolution and the socket budget
# --------------------------------------------------------------------------- #
class ResolveEndpointTests(unittest.TestCase):
    def test_ipv4_literal(self):
        endpoint = sshfinder.resolve_endpoint("127.0.0.1")
        self.assertEqual(endpoint.family, socket.AF_INET)
        self.assertEqual(endpoint.address, "127.0.0.1")
        self.assertEqual(endpoint.sockaddr(22), ("127.0.0.1", 22))

    def test_ipv6_literal_keeps_scope_fields(self):
        try:
            endpoint = sshfinder.resolve_endpoint("::1")
        except OSError:  # pragma: no cover - host without IPv6 support
            self.skipTest("no IPv6 resolver support")
        self.assertEqual(endpoint.family, socket.AF_INET6)
        self.assertEqual(len(endpoint.sockaddr(22)), 4)

    def test_unresolvable_name_raises(self):
        with self.assertRaises(OSError):
            sshfinder.resolve_endpoint("no-such-host.invalid")


class SocketBudgetTests(unittest.TestCase):
    def test_capacity_is_enforced(self):
        budget = sshfinder.SocketBudget(2)
        self.assertTrue(budget.acquire())
        self.assertTrue(budget.acquire())
        self.assertFalse(budget.acquire())
        budget.release()
        self.assertTrue(budget.acquire())

    def test_release_never_goes_negative(self):
        budget = sshfinder.SocketBudget(1)
        budget.release(5)
        self.assertEqual(budget.in_use, 0)

    def test_shrink_halves_to_a_floor(self):
        budget = sshfinder.SocketBudget(100)
        self.assertEqual(budget.shrink(floor=32), 50)
        self.assertEqual(budget.shrink(floor=32), 32)
        self.assertEqual(budget.shrink(floor=32), 32)

    def test_capacity_is_at_least_one(self):
        self.assertEqual(sshfinder.SocketBudget(0).capacity, 1)

    def test_default_budget_is_sane(self):
        self.assertGreaterEqual(sshfinder.default_socket_budget(), 64)
        self.assertLessEqual(
            sshfinder.default_socket_budget(), sshfinder.MAX_SOCKET_BUDGET
        )

    def test_configure_overrides_shared_budget(self):
        original = sshfinder.shared_socket_budget().capacity
        self.addCleanup(sshfinder.configure_socket_budget, original)
        self.assertEqual(sshfinder.configure_socket_budget(7).capacity, 7)
        self.assertEqual(sshfinder.shared_socket_budget().capacity, 7)


# --------------------------------------------------------------------------- #
# Adaptive probe timeout
# --------------------------------------------------------------------------- #
class AdaptiveTimeoutTests(unittest.TestCase):
    def test_starts_at_the_ceiling(self):
        timer = sshfinder.AdaptiveTimeout(2.0)
        self.assertEqual(timer.value(), 2.0)
        self.assertIsNone(timer.rtt)

    def test_first_sample_seeds_mean_and_deviation(self):
        timer = sshfinder.AdaptiveTimeout(2.0, floor=0.001)
        timer.observe(0.010)
        # RFC 6298: srtt = R, rttvar = R/2, so rto = R + 4*(R/2) = 3R.
        self.assertAlmostEqual(timer.value(), 0.030, places=6)
        self.assertAlmostEqual(timer.rtt, 0.010, places=6)

    def test_converges_towards_a_steady_round_trip(self):
        timer = sshfinder.AdaptiveTimeout(2.0, floor=0.001)
        for _ in range(60):
            timer.observe(0.020)
        self.assertAlmostEqual(timer.rtt, 0.020, places=3)
        # Deviation decays to nothing, so the timeout approaches the mean.
        self.assertLess(timer.value(), 0.025)
        self.assertGreater(timer.value(), 0.020)

    def test_jitter_widens_the_allowance(self):
        steady = sshfinder.AdaptiveTimeout(2.0, floor=0.001)
        jittery = sshfinder.AdaptiveTimeout(2.0, floor=0.001)
        for index in range(40):
            steady.observe(0.020)
            jittery.observe(0.005 if index % 2 else 0.035)
        self.assertGreater(jittery.value(), steady.value())

    def test_never_leaves_the_floor_ceiling_band(self):
        timer = sshfinder.AdaptiveTimeout(1.0, floor=0.25)
        timer.observe(0.0001)
        self.assertEqual(timer.value(), 0.25)
        for _ in range(20):
            timer.observe(5.0)  # Clamped to the ceiling on the way in.
        self.assertLessEqual(timer.value(), 1.0)

    def test_floor_is_capped_by_the_ceiling(self):
        timer = sshfinder.AdaptiveTimeout(0.05, floor=1.0)
        self.assertEqual(timer.floor, 0.05)

    def test_disabled_always_returns_the_ceiling(self):
        timer = sshfinder.AdaptiveTimeout(2.0, floor=0.01, enabled=False)
        timer.observe(0.001)
        self.assertEqual(timer.value(), 2.0)
        self.assertIsNotNone(timer.rtt)  # Still measured, just not applied.

    def test_derived_estimator_starts_from_the_pool(self):
        pool = sshfinder.AdaptiveTimeout(2.0, floor=0.001)
        pool.observe(0.010)
        derived = pool.derive()
        self.assertAlmostEqual(derived.rtt, 0.010, places=6)
        self.assertEqual(derived.ceiling, pool.ceiling)
        self.assertEqual(derived.floor, pool.floor)
        self.assertEqual(derived.enabled, pool.enabled)

    def test_derived_estimator_reports_back_to_the_pool(self):
        pool = sshfinder.AdaptiveTimeout(2.0, floor=0.001)
        pool.derive().observe(0.010)
        self.assertAlmostEqual(pool.rtt, 0.010, places=6)

    def test_pool_is_safe_under_concurrent_observation(self):
        pool = sshfinder.AdaptiveTimeout(2.0, floor=0.001)

        def hammer():
            for _ in range(500):
                pool.derive().observe(0.010)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertAlmostEqual(pool.rtt, 0.010, places=4)

    def test_an_unmeasured_pool_seeds_nothing(self):
        self.assertIsNone(sshfinder.AdaptiveTimeout(2.0).derive().rtt)


class AdaptiveSweepTests(SSHServerMixin, unittest.TestCase):
    def test_sweep_measures_the_round_trip(self):
        outcome = sshfinder._connect_sweep(
            "127.0.0.1", [self.ssh_port, 1], timeout=1.0, max_inflight=4
        )
        self.assertIsNotNone(outcome.rtt)
        self.assertGreaterEqual(outcome.rtt, 0.0)
        self.assertLess(outcome.rtt, 1.0)

    def test_host_result_carries_the_round_trip(self):
        result = sshfinder.scan_host(
            "127.0.0.1",
            [self.ssh_port],
            scan_method="connect",
            validate="banner",
            timeout=1.0,
            workers=4,
            retries=0,
            rtt_pool=sshfinder.AdaptiveTimeout(1.0),
        )
        self.assertIsNotNone(result.rtt_ms)
        self.assertIn("rtt_ms", result.as_dict())

    def test_scan_host_reports_into_the_shared_pool(self):
        pool = sshfinder.AdaptiveTimeout(1.0, floor=0.001)
        sshfinder.scan_host(
            "127.0.0.1",
            [self.ssh_port],
            scan_method="connect",
            validate="none",
            timeout=1.0,
            workers=4,
            retries=0,
            rtt_pool=pool,
        )
        self.assertIsNotNone(pool.rtt)


class DroppedProbeTests(unittest.TestCase):
    """Behaviour against a port that answers nothing at all."""

    def setUp(self):
        self.hole = BlackholePort()
        self.addCleanup(self.hole.close)
        if not self.hole.drops_syns():
            self.skipTest("platform answers instead of dropping on overflow")

    def test_timeouts_do_not_feed_the_estimate(self):
        """Only answers measure the path; silence must teach nothing."""
        timer = sshfinder.AdaptiveTimeout(0.3, floor=0.05)
        # A refused port is a real round trip, so it sets the estimate.
        sshfinder._connect_sweep(
            "127.0.0.1", [1], timeout=0.3, max_inflight=2, timer=timer
        )
        measured = timer.rtt
        self.assertIsNotNone(measured)
        # A sweep that only times out must leave the estimate exactly as it was.
        sshfinder._connect_sweep(
            "127.0.0.1", [self.hole.port], timeout=0.3, max_inflight=2,
            timer=timer,
        )
        self.assertEqual(timer.rtt, measured)

    def test_dropped_probe_is_reported_filtered(self):
        outcome = sshfinder._connect_sweep(
            "127.0.0.1", [self.hole.port], timeout=0.3, max_inflight=2,
            timer=sshfinder.AdaptiveTimeout(0.3, floor=0.05),
        )
        self.assertEqual(outcome.open_ports, [])
        self.assertEqual(outcome.filtered, 1)

    def test_adapting_shortens_a_sweep_that_waits_on_silence(self):
        """The whole point: fast answers must buy a shorter wait on silence."""
        ports = [self.hole.port] + list(range(1, 6))  # 1 silent, 5 refusing

        def elapsed(enabled):
            timer = sshfinder.AdaptiveTimeout(
                1.0, floor=0.05, enabled=enabled
            )
            start = time.monotonic()
            sshfinder._connect_sweep(
                "127.0.0.1", ports, timeout=1.0, max_inflight=16, timer=timer
            )
            return time.monotonic() - start

        fixed = elapsed(False)
        adaptive = elapsed(True)
        self.assertGreater(fixed, 0.8)      # Waited out the full ceiling.
        self.assertLess(adaptive, fixed / 2)


# --------------------------------------------------------------------------- #
# The unresponsive-host gate
# --------------------------------------------------------------------------- #
class UnresponsiveGateTests(unittest.TestCase):
    def test_trips_after_a_run_of_silence(self):
        gate = sshfinder._UnresponsiveGate(total_ports=5000, threshold=10)
        for _ in range(9):
            gate.record(sshfinder.FILTERED)
        self.assertFalse(gate.tripped())
        gate.record(sshfinder.FILTERED)
        self.assertTrue(gate.tripped())

    def test_any_answer_keeps_the_sweep_alive(self):
        gate = sshfinder._UnresponsiveGate(total_ports=5000, threshold=10)
        gate.record(sshfinder.CLOSED)
        for _ in range(50):
            gate.record(sshfinder.FILTERED)
        self.assertFalse(gate.tripped())

    def test_small_port_ranges_are_never_cut_short(self):
        gate = sshfinder._UnresponsiveGate(total_ports=10, threshold=2)
        for _ in range(10):
            gate.record(sshfinder.FILTERED)
        self.assertFalse(gate.tripped())


# --------------------------------------------------------------------------- #
# The connect-scan engine
# --------------------------------------------------------------------------- #
class ConnectSweepTests(SSHServerMixin, unittest.TestCase):
    def test_finds_open_and_closed_ports(self):
        outcome = sshfinder._connect_sweep(
            "127.0.0.1", [self.ssh_port, 1], timeout=1.0, max_inflight=8
        )
        self.assertEqual(outcome.open_ports, [self.ssh_port])
        self.assertEqual(outcome.probed, 2)
        self.assertEqual(outcome.closed + outcome.filtered, 1)

    def test_hands_the_discovery_socket_to_the_caller(self):
        adopted = {}

        def on_open(port, sock):
            adopted[port] = sock
            return True  # Claim ownership.

        sshfinder._connect_sweep(
            "127.0.0.1", [self.ssh_port], timeout=1.0, max_inflight=4,
            on_open=on_open,
        )
        self.assertIn(self.ssh_port, adopted)
        sock = adopted[self.ssh_port]
        self.assertIsNotNone(sock)
        self.assertGreaterEqual(sock.fileno(), 0)  # Still open for our use.
        sock.close()

    def test_unadopted_sockets_are_closed_by_the_engine(self):
        seen = []
        sshfinder._connect_sweep(
            "127.0.0.1", [self.ssh_port], timeout=1.0, max_inflight=4,
            on_open=lambda port, sock: seen.append(sock) or False,
        )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].fileno(), -1)

    def test_budget_bounds_sockets_in_flight(self):
        budget = sshfinder.SocketBudget(2)
        outcome = sshfinder._connect_sweep(
            "127.0.0.1", [self.ssh_port] + list(range(1, 20)),
            timeout=1.0, max_inflight=64, budget=budget,
        )
        self.assertIn(self.ssh_port, outcome.open_ports)
        self.assertEqual(outcome.probed, 20)
        self.assertEqual(budget.in_use, 0)  # Every slot handed back.

    def test_unresolvable_host_raises(self):
        with self.assertRaises(OSError):
            sshfinder._connect_sweep(
                "no-such-host.invalid", [22], timeout=1.0, max_inflight=4
            )

    def test_empty_port_list(self):
        outcome = sshfinder._connect_sweep(
            "127.0.0.1", [], timeout=1.0, max_inflight=4
        )
        self.assertEqual(outcome.probed, 0)


class SweepPassAbortTests(unittest.TestCase):
    def test_abort_leaves_remaining_ports_unresolved(self):
        endpoint = sshfinder.resolve_endpoint("127.0.0.1")
        budget = sshfinder.SocketBudget(4)
        _timed_out, unresolved = sshfinder._sweep_pass(
            endpoint,
            list(range(1, 200)),
            timer=sshfinder.AdaptiveTimeout(1.0, enabled=False),
            max_inflight=4,
            budget=budget,
            on_result=lambda port, status, sock: False,
            should_abort=lambda: True,
        )
        self.assertTrue(unresolved)
        self.assertEqual(budget.in_use, 0)


class ConnectScanCompatibilityTests(SSHServerMixin, unittest.TestCase):
    """connect_scan_host keeps its published signature and return shape."""

    def test_positional_signature_and_tuple_result(self):
        open_ports, closed, filtered = sshfinder.connect_scan_host(
            "127.0.0.1", [self.ssh_port], 1.0, 4, 0
        )
        self.assertEqual(open_ports, [self.ssh_port])
        self.assertEqual(filtered, 0)
        self.assertEqual(closed, 0)

    def test_on_open_receives_only_the_port(self):
        seen = []
        sshfinder.connect_scan_host(
            "127.0.0.1", [self.ssh_port], 1.0, 4, 0, on_open=seen.append
        )
        self.assertEqual(seen, [self.ssh_port])


class ReprobeSSHPortsTests(unittest.TestCase):
    def _reprobe(self, candidates, outcome):
        sshfinder._reprobe_ssh_ports(
            "127.0.0.1",
            sshfinder.resolve_endpoint("127.0.0.1"),
            candidates,
            outcome,
            timeout=1.0,
            budget=sshfinder.SocketBudget(8),
            stop_event=None,
            progress=None,
            on_open=None,
        )

    def test_recovers_a_priority_port_the_sweep_missed(self):
        server = LoopbackServer(_serve_ssh_banner).start()
        self.addCleanup(server.stop)
        outcome = sshfinder._SweepOutcome(filtered=1, probed=1,
                                          unresponsive=True)
        self._reprobe([server.port], outcome)
        self.assertEqual(outcome.open_ports, [server.port])
        self.assertEqual(outcome.filtered, 0)   # No longer counted filtered.
        self.assertFalse(outcome.unresponsive)  # A live port disproves it.

    def test_closed_port_moves_from_filtered_to_closed(self):
        outcome = sshfinder._SweepOutcome(filtered=1, probed=1)
        self._reprobe([1], outcome)  # Loopback port 1 refuses immediately.
        self.assertEqual(outcome.filtered, 0)
        self.assertEqual(outcome.closed, 1)
        self.assertEqual(outcome.open_ports, [])

    def test_no_candidates_is_a_noop(self):
        outcome = sshfinder._SweepOutcome(filtered=5)
        self._reprobe([], outcome)
        self.assertEqual(outcome.filtered, 5)

    def test_only_silent_priority_ports_become_candidates(self):
        """A port that answered is never re-probed, so tallies stay honest."""
        with LoopbackServer(_serve_ssh_banner) as server:
            with mock.patch.object(
                sshfinder, "SSH_PRIORITY_PORTS", (server.port, 1)
            ):
                outcome = sshfinder._connect_sweep(
                    "127.0.0.1", [server.port, 1], timeout=1.0, max_inflight=4
                )
        # One open, one closed, nothing filtered and nothing double-counted.
        self.assertEqual(outcome.open_ports, [server.port])
        self.assertEqual(outcome.closed, 1)
        self.assertEqual(outcome.filtered, 0)
        self.assertEqual(outcome.probed, 2)


class ChunkTests(unittest.TestCase):
    def test_splits_into_batches(self):
        self.assertEqual(
            list(sshfinder._chunk([1, 2, 3, 4, 5], 2)), [[1, 2], [3, 4], [5]]
        )

    def test_empty_input(self):
        self.assertEqual(list(sshfinder._chunk([], 4)), [])


# --------------------------------------------------------------------------- #
# Buffered reads and SSH identification
# --------------------------------------------------------------------------- #
class BufferedReaderTests(unittest.TestCase):
    def _pair(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def test_reads_lines_across_segment_boundaries(self):
        left, right = self._pair()
        right.sendall(b"first\r\nsec")
        right.sendall(b"ond\nthird\n")
        reader = sshfinder._BufferedReader(left, 2.0)
        self.assertEqual(reader.read_line(1024), b"first")
        self.assertEqual(reader.read_line(1024), b"second")
        self.assertEqual(reader.read_line(1024), b"third")

    def test_read_exact_follows_a_line_on_the_same_stream(self):
        left, right = self._pair()
        right.sendall(b"SSH-2.0-X\r\n" + b"\x00\x01\x02\x03binary")
        reader = sshfinder._BufferedReader(left, 2.0)
        self.assertEqual(reader.read_line(1024), b"SSH-2.0-X")
        self.assertEqual(reader.read_exact(4), b"\x00\x01\x02\x03")
        self.assertEqual(reader.read_exact(6), b"binary")

    def test_read_exact_raises_when_the_peer_closes(self):
        left, right = self._pair()
        right.sendall(b"short")
        right.close()
        reader = sshfinder._BufferedReader(left, 2.0)
        with self.assertRaises(OSError):
            reader.read_exact(64)

    def test_read_line_gives_up_on_a_non_line_protocol(self):
        left, right = self._pair()
        right.sendall(b"x" * 200)
        reader = sshfinder._BufferedReader(left, 2.0)
        self.assertIsNone(reader.read_line(64))

    def test_deadline_bounds_a_silent_peer(self):
        left, _right = self._pair()
        reader = sshfinder._BufferedReader(left, 0.2)
        start = time.monotonic()
        self.assertIsNone(reader.read_line(1024))
        self.assertLess(time.monotonic() - start, 2.0)


class ReadSSHIdentificationTests(unittest.TestCase):
    def _reader(self, payload):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        right.sendall(payload)
        right.close()
        return sshfinder._BufferedReader(left, 1.0)

    def test_skips_preamble_lines(self):
        reader = self._reader(
            b"legal notice\r\nmotd\r\nSSH-2.0-OpenSSH_9.6\r\n"
        )
        self.assertEqual(
            sshfinder.read_ssh_identification(reader), "SSH-2.0-OpenSSH_9.6"
        )

    def test_returns_none_without_an_identification(self):
        reader = self._reader(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        self.assertIsNone(sshfinder.read_ssh_identification(reader))

    def test_preamble_length_is_bounded(self):
        reader = self._reader(b"noise\n" * 50 + b"SSH-2.0-X\r\n")
        self.assertIsNone(
            sshfinder.read_ssh_identification(reader, max_lines=5)
        )


class GrabBannerTests(unittest.TestCase):
    """Server behaviours a lone recv() would misread as 'not SSH'."""

    def _banner_for(self, handler):
        with LoopbackServer(handler) as server:
            return sshfinder.grab_ssh_banner("127.0.0.1", server.port, 2.0)

    def test_plain_banner(self):
        self.assertEqual(
            self._banner_for(_serve_ssh_banner), "SSH-2.0-OpenSSH_9.0"
        )

    def test_banner_behind_a_preamble(self):
        self.assertEqual(
            self._banner_for(_serve_ssh_with_preamble), "SSH-2.0-OpenSSH_9.0"
        )

    def test_server_that_waits_for_the_client(self):
        self.assertEqual(
            self._banner_for(_serve_ssh_client_first), "SSH-2.0-OpenSSH_9.0"
        )

    def test_banner_split_across_segments(self):
        self.assertEqual(
            self._banner_for(_serve_ssh_fragmented), "SSH-2.0-OpenSSH_9.0"
        )

    def test_non_ssh_service_rejected(self):
        self.assertIsNone(self._banner_for(_serve_http))

    def test_adopted_socket_is_used_and_always_closed(self):
        with LoopbackServer(_serve_ssh_banner) as server:
            sock = socket.create_connection(
                ("127.0.0.1", server.port), timeout=2
            )
            banner = sshfinder.grab_ssh_banner(
                "127.0.0.1", server.port, 2.0, sock=sock
            )
        self.assertEqual(banner, "SSH-2.0-OpenSSH_9.0")
        self.assertEqual(sock.fileno(), -1)

    def test_adopted_socket_closed_even_when_the_peer_is_silent(self):
        left, right = socket.socketpair()
        self.addCleanup(right.close)
        self.assertIsNone(
            sshfinder.grab_ssh_banner("127.0.0.1", 22, 0.2, sock=left)
        )
        self.assertEqual(left.fileno(), -1)

    def test_unreachable_port_returns_none(self):
        self.assertIsNone(sshfinder.grab_ssh_banner("127.0.0.1", 1, 1.0))


class ValidateSSHPortsTests(SSHServerMixin, unittest.TestCase):
    def test_confirms_only_the_ssh_port(self):
        confirmed = sshfinder.validate_ssh_ports(
            "127.0.0.1", [self.ssh_port, 1], timeout=1.0, workers=4,
            method="banner",
        )
        self.assertEqual(list(confirmed), [self.ssh_port])

    def test_none_method_short_circuits(self):
        self.assertEqual(
            sshfinder.validate_ssh_ports(
                "127.0.0.1", [self.ssh_port], timeout=1.0, workers=4,
                method="none",
            ),
            {},
        )


# --------------------------------------------------------------------------- #
# Connection reuse end to end
# --------------------------------------------------------------------------- #
class ConnectionReuseTests(unittest.TestCase):
    def test_confirmed_ssh_service_costs_one_handshake(self):
        """Discovery and identification share a connection, not two."""
        accepted = []
        lock = threading.Lock()

        def counting_ssh(conn):
            with lock:
                accepted.append(1)
            conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
            conn.recv(64)

        with LoopbackServer(counting_ssh) as server:
            result = sshfinder.scan_host(
                "127.0.0.1",
                [server.port],
                scan_method="connect",
                validate="banner",
                timeout=1.0,
                workers=4,
                retries=0,
            )
            self.assertEqual(result.ssh_ports, [server.port])
            time.sleep(0.1)  # Let a stray second connection land, if any.
            with lock:
                self.assertEqual(sum(accepted), 1)


class ScanHostEarlyExitTests(SSHServerMixin, unittest.TestCase):
    def test_early_exit_flag_defaults_to_clear(self):
        result = sshfinder.scan_host(
            "127.0.0.1",
            [self.ssh_port],
            scan_method="connect",
            validate="banner",
            timeout=1.0,
            workers=4,
            retries=0,
        )
        self.assertFalse(result.early_exit)
        self.assertIn("early_exit", result.as_dict())

    def test_unresolvable_host_is_reported_as_an_error(self):
        result = sshfinder.scan_host(
            "no-such-host.invalid",
            [22],
            scan_method="connect",
            validate="banner",
            timeout=1.0,
            workers=4,
            retries=0,
        )
        self.assertIsNotNone(result.error)


class EarlyExitRenderTests(unittest.TestCase):
    def test_text_explains_the_early_exit(self):
        result = sshfinder.HostResult(host="h", filtered=65535, early_exit=True)
        text = sshfinder.render_text([result])
        self.assertIn("stopped", text)
        self.assertIn("--no-early-exit", text)


# --------------------------------------------------------------------------- #
# Streaming events
# --------------------------------------------------------------------------- #
class EventStreamTests(unittest.TestCase):
    def test_emits_one_json_object_per_line(self):
        buffer = io.StringIO()
        stream = sshfinder.EventStream(buffer)
        stream.emit("ssh", host="10.0.0.1", port=22)
        stream.emit("summary", ssh_services=1)
        lines = buffer.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["event"], "ssh")
        self.assertEqual(first["host"], "10.0.0.1")
        self.assertEqual(first["port"], 22)
        self.assertIn("elapsed", first)
        self.assertEqual(json.loads(lines[1])["event"], "summary")

    def test_disabled_stream_writes_nothing(self):
        buffer = io.StringIO()
        sshfinder.EventStream(buffer, enabled=False).emit("ssh", port=22)
        self.assertEqual(buffer.getvalue(), "")

    def test_a_broken_pipe_does_not_abort_the_scan(self):
        buffer = io.StringIO()
        buffer.close()
        stream = sshfinder.EventStream(buffer)
        stream.emit("ssh", port=22)  # Must not raise.
        self.assertFalse(stream.enabled)

    def test_scan_streams_the_service_before_the_summary(self):
        buffer = io.StringIO()
        stream = sshfinder.EventStream(buffer)
        with LoopbackServer(_serve_ssh_banner) as server:
            sshfinder.scan_targets(
                ["127.0.0.1"],
                [server.port],
                scan_method="connect",
                validate="banner",
                timeout=1.0,
                workers=4,
                retries=0,
                host_concurrency=1,
                stream=stream,
            )
        events = [json.loads(line) for line in
                  buffer.getvalue().strip().split("\n")]
        names = [e["event"] for e in events]
        self.assertEqual(names[0], "open")
        self.assertIn("ssh", names)
        self.assertEqual(names[-1], "summary")
        self.assertLess(names.index("ssh"), names.index("summary"))
        self.assertEqual(events[-1]["ssh_services"], 1)


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #
class CLITests(unittest.TestCase):
    def test_new_flags_are_accepted(self):
        args = sshfinder.build_parser().parse_args(
            ["10.0.0.1", "--stream", "--no-early-exit", "--max-sockets", "128",
             "--max-targets", "10", "--no-adaptive-timeout",
             "--min-timeout", "0.25"]
        )
        self.assertTrue(args.stream)
        self.assertTrue(args.no_early_exit)
        self.assertTrue(args.no_adaptive_timeout)
        self.assertEqual(args.max_sockets, 128)
        self.assertEqual(args.max_targets, 10)
        self.assertEqual(args.min_timeout, 0.25)

    def test_defaults(self):
        args = sshfinder.build_parser().parse_args(["10.0.0.1"])
        self.assertFalse(args.stream)
        self.assertFalse(args.no_early_exit)
        self.assertFalse(args.no_adaptive_timeout)
        self.assertEqual(args.max_targets, sshfinder.DEFAULT_MAX_TARGETS)
        self.assertEqual(args.min_timeout, sshfinder.DEFAULT_MIN_TIMEOUT)

    def test_negative_limits_are_rejected(self):
        for flag in ("--max-targets", "--max-sockets", "--min-timeout"):
            with self.subTest(flag=flag):
                with self.assertRaises(SystemExit):
                    with contextlib.redirect_stderr(io.StringIO()):
                        sshfinder.run(["10.0.0.1", flag, "-1"])

    def test_min_timeout_above_timeout_is_rejected(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                sshfinder.run(["10.0.0.1", "-t", "1", "--min-timeout", "5"])

    def test_stream_mode_emits_only_jsonl(self):
        with LoopbackServer(_serve_ssh_banner) as server:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = sshfinder.run(
                    ["127.0.0.1", "-p", str(server.port), "--stream", "-q"]
                )
        self.assertEqual(exit_code, 0)
        events = [json.loads(line) for line in
                  stdout.getvalue().strip().split("\n")]
        self.assertTrue(all("event" in e for e in events))
        self.assertEqual(events[-1]["event"], "summary")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
