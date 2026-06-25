"""Unit tests for the pure, side-effect-free parts of sshfinder."""

import os
import socket
import struct
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sshfinder  # noqa: E402


# --------------------------------------------------------------------------- #
# Port parsing
# --------------------------------------------------------------------------- #
def test_parse_ports_single():
    assert sshfinder.parse_ports("22") == [22]


def test_parse_ports_range():
    assert sshfinder.parse_ports("20-23") == [20, 21, 22, 23]


def test_parse_ports_mixed_and_dedup():
    assert sshfinder.parse_ports("22, 80, 79-81") == [22, 79, 80, 81]


def test_parse_ports_whitespace_and_empty_chunks():
    assert sshfinder.parse_ports(" 22 , , 80 ") == [22, 80]


@pytest.mark.parametrize("spec", ["", "abc", "0-10", "1-70000", "30-20", "-5"])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        sshfinder.parse_ports(spec)


# --------------------------------------------------------------------------- #
# Target expansion
# --------------------------------------------------------------------------- #
def test_expand_targets_plain_ip():
    assert sshfinder.expand_targets(["10.0.0.1"]) == ["10.0.0.1"]


def test_expand_targets_hostname_passthrough():
    assert sshfinder.expand_targets(["example.com"]) == ["example.com"]


def test_expand_targets_cidr():
    hosts = sshfinder.expand_targets(["192.168.1.0/30"])
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_expand_targets_single_host_cidr():
    assert sshfinder.expand_targets(["192.168.1.5/32"]) == ["192.168.1.5"]


def test_expand_targets_dedup_and_order():
    hosts = sshfinder.expand_targets(["10.0.0.1", "10.0.0.1", "10.0.0.2"])
    assert hosts == ["10.0.0.1", "10.0.0.2"]


def test_expand_targets_empty_raises():
    with pytest.raises(ValueError):
        sshfinder.expand_targets(["", "  "])


def test_expand_targets_invalid_network_raises():
    with pytest.raises(ValueError):
        sshfinder.expand_targets(["10.0.0.0/99"])


# --------------------------------------------------------------------------- #
# Target file reading
# --------------------------------------------------------------------------- #
def test_read_target_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.1  10.0.0.2\n# a comment\n10.0.0.3 # inline\n\n")
    assert sshfinder.read_target_file(str(f)) == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
def test_host_result_as_dict_sorts():
    result = sshfinder.HostResult(
        host="h",
        open_ports=[80, 22],
        ssh_ports=[22],
        banners={22: "SSH-2.0-OpenSSH"},
    )
    d = result.as_dict()
    assert d["open_ports"] == [22, 80]
    assert d["ssh_ports"] == [22]
    assert d["ssh_sockets"] == ["h:22"]
    assert d["banners"] == {"22": "SSH-2.0-OpenSSH"}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def test_render_json_roundtrip():
    import json

    results = [sshfinder.HostResult(host="h", open_ports=[22], ssh_ports=[22])]
    parsed = json.loads(sshfinder.render_json(results))
    assert parsed[0]["host"] == "h"


def test_render_text_contains_summary():
    results = [sshfinder.HostResult(host="h", open_ports=[], ssh_ports=[])]
    text = sshfinder.render_text(results)
    assert "Scanned 1 host(s)" in text
    assert "no open ports" in text


def test_render_text_shows_sockets_per_host():
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
    assert "open: 10.0.0.1:22" in text
    assert "SSH  10.0.0.1:22" in text
    assert "SSH  10.0.0.2:2222" in text
    # Consolidated socket list makes multi-host results unambiguous.
    assert "SSH services found (2):" in text
    assert "  10.0.0.1:22" in text
    assert "  10.0.0.2:2222" in text


# --------------------------------------------------------------------------- #
# Live loopback integration: connect scan + banner grab
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_ssh_server():
    """A tiny TCP server that emits an SSH banner, on an ephemeral port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
                conn.recv(64)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    srv.close()
    thread.join(timeout=2)


def test_connect_scan_finds_open_port(fake_ssh_server):
    open_ports, closed, filtered = sshfinder.connect_scan_host(
        "127.0.0.1", [fake_ssh_server], timeout=1.0, workers=4, retries=0
    )
    assert open_ports == [fake_ssh_server]
    assert filtered == 0


def test_grab_ssh_banner_detects_ssh(fake_ssh_server):
    banner = sshfinder.grab_ssh_banner("127.0.0.1", fake_ssh_server, timeout=1.0)
    assert banner is not None
    assert banner.startswith("SSH-2.0-OpenSSH")


def test_scan_host_end_to_end(fake_ssh_server):
    result = sshfinder.scan_host(
        "127.0.0.1",
        [fake_ssh_server],
        scan_method="connect",
        validate="banner",
        timeout=1.0,
        workers=4,
        retries=0,
    )
    assert result.ssh_ports == [fake_ssh_server]
    assert result.error is None


def test_progress_log_emits_socket(capsys):
    reporter = sshfinder.ProgressReporter(total=1, enabled=False, quiet=False)
    reporter.log("  [+] open   10.0.0.1:22")
    captured = capsys.readouterr()
    assert "10.0.0.1:22" in captured.err


def test_scan_targets_stops_on_signal(fake_ssh_server, monkeypatch):
    """A SIGINT mid-scan must stop promptly and return partial results."""
    import signal as _signal

    real_signal = _signal.signal
    captured_handler = {}

    def fake_signal(signum, handler):
        # Capture only the scan's handler, not its later restoration.
        if (
            signum == _signal.SIGINT
            and callable(handler)
            and "fn" not in captured_handler
        ):
            captured_handler["fn"] = handler
        return real_signal(signum, handler)

    monkeypatch.setattr(_signal, "signal", fake_signal)

    # Many hosts, all the closed loopback port, so the scan would run a while.
    hosts = [f"127.0.0.{i}" for i in range(1, 40)]

    def fire_interrupt():
        time.sleep(0.2)
        handler = captured_handler.get("fn")
        if handler:
            handler(_signal.SIGINT, None)

    firer = threading.Thread(target=fire_interrupt, daemon=True)
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
    assert elapsed < 5.0
    assert isinstance(results, list)


def test_connect_scan_closed_port():
    # Port 1 on loopback is almost certainly closed and refuses fast.
    open_ports, closed, filtered = sshfinder.connect_scan_host(
        "127.0.0.1", [1], timeout=1.0, workers=1, retries=0
    )
    assert open_ports == []
    assert closed + filtered == 1


def test_probe_port_stop_event_short_circuits():
    stop = threading.Event()
    stop.set()
    status = sshfinder._probe_port(
        "127.0.0.1", 1, timeout=1.0, retries=0, stop_event=stop
    )
    assert status == sshfinder.FILTERED


def test_progress_reporter_disabled_is_noop():
    reporter = sshfinder.ProgressReporter(total=10, enabled=False)
    reporter.tick(5, opened=1)
    reporter.finish()  # Must not write or raise when disabled.
    assert reporter.done == 0


def test_host_result_responsive_flag():
    filtered_only = sshfinder.HostResult(host="h", filtered=5)
    assert filtered_only.responsive is False
    with_closed = sshfinder.HostResult(host="h", closed=3, filtered=5)
    assert with_closed.responsive is True


def test_render_text_filtered_host_message():
    result = sshfinder.HostResult(host="h", filtered=100)
    text = sshfinder.render_text([result])
    assert "firewalled or down" in text


# --------------------------------------------------------------------------- #
# SSH audit: KEXINIT parsing, weakness flagging, Terrapin, correlation
# --------------------------------------------------------------------------- #
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


def test_parse_kexinit_roundtrip():
    payload = build_kexinit_payload(
        kex=["curve25519-sha256", "diffie-hellman-group14-sha1"],
        hostkey=["ssh-ed25519", "ssh-rsa"],
        ciphers=["aes256-gcm@openssh.com", "aes128-cbc"],
        macs=["hmac-sha2-256", "hmac-sha1"],
    )
    parsed = sshfinder.parse_kexinit(payload)
    assert parsed["kex"][0] == "curve25519-sha256"
    assert "ssh-rsa" in parsed["server_host_key"]
    assert "aes128-cbc" in parsed["enc_s2c"]


def test_parse_kexinit_rejects_non_kexinit():
    assert sshfinder.parse_kexinit(b"\x05garbage") is None
    assert sshfinder.parse_kexinit(b"") is None


def test_assess_weaknesses_flags_legacy_algorithms():
    kex = sshfinder.parse_kexinit(
        build_kexinit_payload(
            kex=["diffie-hellman-group1-sha1", "curve25519-sha256"],
            hostkey=["ssh-rsa", "ssh-ed25519"],
            ciphers=["aes128-cbc", "aes256-gcm@openssh.com", "arcfour"],
            macs=["hmac-md5", "hmac-sha2-256", "hmac-sha1-96"],
        )
    )
    findings = " ".join(sshfinder.assess_weaknesses(kex))
    assert "key exchange" in findings
    assert "host key" in findings
    assert "aes128-cbc" in findings
    assert "arcfour" in findings
    assert "MAC" in findings


def test_assess_weaknesses_clean_when_modern():
    kex = sshfinder.parse_kexinit(
        build_kexinit_payload(
            kex=["curve25519-sha256"],
            hostkey=["ssh-ed25519"],
            ciphers=["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
            macs=["hmac-sha2-256-etm@openssh.com"],
        )
    )
    assert sshfinder.assess_weaknesses(kex) == []


def test_terrapin_vulnerable_with_chacha_and_no_strict_kex():
    kex = sshfinder.parse_kexinit(
        build_kexinit_payload(
            kex=["curve25519-sha256"],
            hostkey=["ssh-ed25519"],
            ciphers=["chacha20-poly1305@openssh.com"],
            macs=["hmac-sha2-256"],
        )
    )
    assert sshfinder.is_terrapin_vulnerable(kex) is True


def test_terrapin_safe_when_strict_kex_advertised():
    kex = sshfinder.parse_kexinit(
        build_kexinit_payload(
            kex=["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
            hostkey=["ssh-ed25519"],
            ciphers=["chacha20-poly1305@openssh.com"],
            macs=["hmac-sha2-256"],
        )
    )
    assert sshfinder.is_terrapin_vulnerable(kex) is False


def test_terrapin_cbc_etm_combination():
    kex = sshfinder.parse_kexinit(
        build_kexinit_payload(
            kex=["curve25519-sha256"],
            hostkey=["ssh-ed25519"],
            ciphers=["aes128-cbc"],
            macs=["hmac-sha2-256-etm@openssh.com"],
        )
    )
    assert sshfinder.is_terrapin_vulnerable(kex) is True


def test_correlate_host_keys_groups_shared_fingerprints():
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
    assert shared == {"SHA256:AAA": ["10.0.0.1:22", "10.0.0.2:22"]}


def test_ssh_audit_password_auth_property():
    assert sshfinder.SSHAudit(host="h", port=22,
                              auth_methods=["publickey"]).password_auth is False
    assert sshfinder.SSHAudit(host="h", port=22,
                              auth_methods=["publickey", "password"]).password_auth


def test_render_audit_block_shows_findings():
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
    assert "host key: ssh-ed25519 SHA256:XYZ" in text
    assert "password auth enabled" in text
    assert "Terrapin (CVE-2023-48795): VULNERABLE" in text
    assert "aes128-cbc" in text


def test_read_server_kexinit_live():
    """End-to-end raw KEXINIT read against a fake server."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    payload = build_kexinit_payload(
        kex=["curve25519-sha256"],
        hostkey=["ssh-ed25519"],
        ciphers=["chacha20-poly1305@openssh.com"],
        macs=["hmac-sha2-256"],
    )

    def serve():
        srv.settimeout(2)
        conn, _ = srv.accept()
        try:
            conn.sendall(b"SSH-2.0-FakeServer_1.0\r\n")
            conn.sendall(packetize(payload))
            conn.recv(64)
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        kex = sshfinder.read_server_kexinit("127.0.0.1", port, timeout=2.0)
    finally:
        srv.close()
        thread.join(timeout=2)
    assert kex is not None
    assert kex["banner"] == "SSH-2.0-FakeServer_1.0"
    assert kex["kex"] == ["curve25519-sha256"]
    assert sshfinder.is_terrapin_vulnerable(kex) is True


def test_audit_with_paramiko_enumerates_auth_methods():
    """Deep audit: host key fingerprint and accepted auth methods.

    Runs a real Paramiko server so the partial handshake and the
    unauthenticated 'none' auth probe are exercised end to end.
    """
    paramiko = pytest.importorskip("paramiko")

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

    assert key_type.startswith("ssh-rsa")
    assert fingerprint.startswith("SHA256:")
    assert set(methods) == {"publickey", "password"}


# --------------------------------------------------------------------------- #
# Pipelined service identification and open-port annotation
# --------------------------------------------------------------------------- #
@pytest.fixture
def fake_non_ssh_server():
    """A TCP server that accepts connections but does not speak SSH."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.recv(64)
                conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    srv.close()
    thread.join(timeout=2)


def test_scan_host_classifies_non_ssh_open_port(fake_non_ssh_server):
    result = sshfinder.scan_host(
        "127.0.0.1",
        [fake_non_ssh_server],
        scan_method="connect",
        validate="banner",
        timeout=1.0,
        workers=4,
        retries=0,
    )
    assert result.open_ports == [fake_non_ssh_server]
    assert result.ssh_ports == []           # open but not SSH
    assert result.service_checked is True


def test_render_text_annotates_service_type():
    result = sshfinder.HostResult(
        host="10.0.0.1",
        open_ports=[22, 8080],
        ssh_ports=[22],
        banners={22: "SSH-2.0-OpenSSH_9.0"},
        service_checked=True,
    )
    text = sshfinder.render_text([result])
    assert "10.0.0.1:22 [SSH]" in text
    assert "10.0.0.1:8080 [not ssh]" in text


def test_render_text_marks_unknown_when_not_validated():
    result = sshfinder.HostResult(
        host="10.0.0.1", open_ports=[1234], service_checked=False
    )
    text = sshfinder.render_text([result])
    assert "10.0.0.1:1234 [service unknown]" in text
