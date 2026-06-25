"""Unit tests for the pure, side-effect-free parts of sshfinder."""

import os
import socket
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
