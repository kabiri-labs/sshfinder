#!/usr/bin/env python3
"""sshfinder - fast, reliable discovery of open SSH services.

The tool scans one or more targets (IP addresses, hostnames or CIDR
networks) for open TCP ports and confirms which of those ports are
actually serving SSH. Both the port scan and the SSH validation run
concurrently across all targets, which makes large scans dramatically
faster than a sequential approach.

Two scanning back-ends are available:

* ``connect`` - a portable TCP connect scan built on non-blocking
  sockets. It needs no special privileges and is the default.
* ``syn``     - a half-open SYN scan powered by Scapy. It is faster on
  large port ranges but requires raw-socket (root) privileges and the
  optional ``scapy`` dependency.

SSH validation reads the server identification banner (RFC 4253), which
is reliable and lightweight. When the optional ``paramiko`` dependency is
installed, ``--validate paramiko`` performs a full protocol handshake for
stricter confirmation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import (
    FIRST_COMPLETED,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

__version__ = "2.3.1"

LOGGER = logging.getLogger("sshfinder")

# Defaults chosen to be safe and reasonably fast on typical networks.
DEFAULT_PORTS = "1-65535"
DEFAULT_TIMEOUT = 2.0
DEFAULT_WORKERS = 200
DEFAULT_RETRIES = 0
DEFAULT_HOST_CONCURRENCY = 16
MAX_PORT = 65535
SSH_BANNER_PREFIX = b"SSH-"
# Identification string we present when probing, per RFC 4253.
CLIENT_BANNER = b"SSH-2.0-sshfinder\r\n"
# How often the main thread wakes to check for Ctrl+C while waiting on
# worker threads. A short interval keeps the program responsive on Windows,
# where an unbounded lock wait cannot be interrupted by a signal.
POLL_INTERVAL = 0.2

# Per-port probe outcomes.
OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"

# SSH binary protocol constants (RFC 4253).
SSH_MSG_KEXINIT = 20
# Username presented for the unauthenticated "none" auth probe used to
# enumerate the methods a server will accept. It is not expected to succeed.
AUTH_PROBE_USER = "sshfinder"

# Deprecated / weak host-key algorithms (SHA-1 signatures, DSA).
WEAK_HOST_KEYS = {
    "ssh-rsa",
    "ssh-dss",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
}


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class SSHAudit:
    """Security-relevant facts about a single SSH service.

    Gathered without authenticating: the cryptographic algorithms a server
    offers, its host key fingerprint, the authentication methods it accepts,
    and derived findings (weak algorithms, Terrapin exposure).
    """

    host: str
    port: int
    server_version: str = ""
    host_key_type: str = ""
    host_key_fingerprint: str = ""
    auth_methods: list[str] = field(default_factory=list)
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    terrapin_vulnerable: Optional[bool] = None
    notes: list[str] = field(default_factory=list)

    @property
    def password_auth(self) -> bool:
        """True if the server accepts a password-style login (brute-forceable)."""
        return any(
            m in ("password", "keyboard-interactive") for m in self.auth_methods
        )

    def as_dict(self) -> dict:
        return {
            "server_version": self.server_version,
            "host_key_type": self.host_key_type,
            "host_key_fingerprint": self.host_key_fingerprint,
            "auth_methods": self.auth_methods,
            "password_auth": self.password_auth,
            "kex_algorithms": self.kex_algorithms,
            "host_key_algorithms": self.host_key_algorithms,
            "ciphers": self.ciphers,
            "macs": self.macs,
            "weaknesses": self.weaknesses,
            "terrapin_vulnerable": self.terrapin_vulnerable,
            "notes": self.notes,
        }


@dataclass
class HostResult:
    """Outcome of scanning a single host."""

    host: str
    open_ports: list[int] = field(default_factory=list)
    ssh_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    audits: dict[int, SSHAudit] = field(default_factory=dict)
    closed: int = 0
    filtered: int = 0
    service_checked: bool = False
    error: Optional[str] = None

    @property
    def responsive(self) -> bool:
        """True if the host answered at least one probe (open or closed)."""
        return bool(self.open_ports) or self.closed > 0

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "open_ports": sorted(self.open_ports),
            "ssh_ports": sorted(self.ssh_ports),
            "ssh_sockets": [f"{self.host}:{p}" for p in sorted(self.ssh_ports)],
            "banners": {str(p): b for p, b in sorted(self.banners.items())},
            "audit": {
                str(p): self.audits[p].as_dict() for p in sorted(self.audits)
            },
            "closed": self.closed,
            "filtered": self.filtered,
            "service_checked": self.service_checked,
            "responsive": self.responsive,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# Live progress reporting
# --------------------------------------------------------------------------- #
class ProgressReporter:
    """Thread-safe progress indicator and discovery log written to stderr.

    :meth:`tick` updates a throttled, single-line progress bar. :meth:`log`
    prints a discovery line (e.g. an open socket) without clobbering the bar:
    it erases the bar, writes the message, and redraws. Both are safe to call
    from many worker threads at once.
    """

    def __init__(
        self, total: int, enabled: bool, quiet: bool = False, interval: float = 0.3
    ):
        self.total = max(0, total)
        self.enabled = enabled
        self.quiet = quiet
        self.interval = interval
        self.done = 0
        self.open = 0
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self._last = 0.0
        self._last_len = 0
        self._active = False

    def tick(self, n: int = 1, opened: int = 0) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.done += n
            self.open += opened
            now = time.monotonic()
            if now - self._last >= self.interval or self.done >= self.total:
                self._last = now
                self._render(now)

    def log(self, message: str) -> None:
        """Print a line above the live progress bar."""
        if self.quiet:
            return
        with self._lock:
            if self._active:
                # Erase the current progress line before writing the message.
                sys.stderr.write("\r" + " " * self._last_len + "\r")
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
            if self.enabled and self._active:
                self._render(time.monotonic())

    def _render(self, now: float) -> None:
        elapsed = now - self._start
        pct = (self.done / self.total * 100.0) if self.total else 100.0
        rate = self.done / elapsed if elapsed > 0 else 0.0
        eta = (self.total - self.done) / rate if rate > 0 else 0.0
        line = (
            f"  scanning {self.done}/{self.total} ({pct:5.1f}%) "
            f"| open: {self.open} | {rate:6.0f}/s | ETA {eta:5.0f}s"
        )
        pad = max(0, self._last_len - len(line))
        sys.stderr.write("\r" + line + " " * pad)
        sys.stderr.flush()
        self._last_len = len(line)
        self._active = True

    def finish(self) -> None:
        if self.enabled and self._active:
            sys.stderr.write("\n")
            sys.stderr.flush()


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def parse_ports(spec: str) -> list[int]:
    """Parse a port specification such as ``22,80,1000-2000`` into a sorted
    list of unique ports.

    Raises:
        ValueError: if the specification is malformed or out of range.
    """
    ports: set[int] = set()
    spec = spec.strip()
    if not spec:
        raise ValueError("empty port specification")

    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"invalid port range: {chunk!r}")
            if start > end:
                raise ValueError(f"range start greater than end: {chunk!r}")
            for port in range(start, end + 1):
                _validate_port(port)
                ports.add(port)
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"invalid port: {chunk!r}")
            _validate_port(port)
            ports.add(port)

    if not ports:
        raise ValueError("no ports parsed from specification")
    return sorted(ports)


def _validate_port(port: int) -> None:
    if not 1 <= port <= MAX_PORT:
        raise ValueError(f"port out of range (1-{MAX_PORT}): {port}")


def expand_targets(targets: Iterable[str]) -> list[str]:
    """Expand a collection of target tokens into a de-duplicated, ordered list
    of host strings.

    Each token may be an IP address, a hostname, or a CIDR network such as
    ``10.0.0.0/24`` (which is expanded into individual host addresses).
    """
    expanded: list[str] = []
    seen: set[str] = set()

    for token in targets:
        token = token.strip()
        if not token:
            continue
        for host in _expand_single_target(token):
            if host not in seen:
                seen.add(host)
                expanded.append(host)

    if not expanded:
        raise ValueError("no valid targets supplied")
    return expanded


def _expand_single_target(token: str) -> Iterator[str]:
    # CIDR network (e.g. 192.168.1.0/24 or 2001:db8::/120).
    if "/" in token:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise ValueError(f"invalid network: {token!r}")
        hosts = list(network.hosts())
        # A /32 or /128 yields no .hosts(); fall back to the address itself.
        if not hosts:
            yield str(network.network_address)
            return
        for addr in hosts:
            yield str(addr)
        return

    # Plain IP literal or hostname; leave hostnames for the OS resolver.
    yield token


def read_target_file(path: str) -> list[str]:
    """Read targets from a file, one per line; ``#`` comments are ignored."""
    tokens: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                tokens.extend(line.split())
    return tokens


# --------------------------------------------------------------------------- #
# Privilege / capability detection
# --------------------------------------------------------------------------- #
def has_raw_socket_privilege() -> bool:
    """Best-effort check for the privileges required by a SYN scan."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False  # Non-POSIX (e.g. Windows): assume no raw-socket access.


def resolve_scan_method(requested: str) -> str:
    """Resolve the ``auto`` scan method to a concrete back-end."""
    if requested != "auto":
        return requested
    if has_raw_socket_privilege() and _scapy_available():
        return "syn"
    return "connect"


def _scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------- #
# Port scanning back-ends
# --------------------------------------------------------------------------- #
def connect_scan_host(
    host: str,
    ports: list[int],
    timeout: float,
    workers: int,
    retries: int,
    stop_event: Optional[threading.Event] = None,
    progress: Optional[ProgressReporter] = None,
    on_open: Optional[Callable[[int], None]] = None,
) -> tuple[list[int], int, int]:
    """Concurrent TCP connect scan of a single host.

    Returns ``(open_ports, closed_count, filtered_count)``. Open sockets are
    reported live via ``progress`` as they are found, and ``on_open`` (if
    given) is invoked with each open port the instant it is discovered -- this
    lets the caller pipeline service identification while the rest of the port
    range is still being scanned. The scan unwinds promptly when ``stop_event``
    is set, cancelling any not-yet-started probes so a Ctrl+C does not block on
    a huge backlog of queued work.
    """
    open_ports: list[int] = []
    closed = 0
    filtered = 0
    if not ports:
        return open_ports, closed, filtered

    pool_size = max(1, min(workers, len(ports)))
    executor = ThreadPoolExecutor(max_workers=pool_size)
    futures = {
        executor.submit(_probe_port, host, port, timeout, retries, stop_event): port
        for port in ports
    }
    try:
        for future in as_completed(futures):
            if stop_event is not None and stop_event.is_set():
                break
            port = futures[future]
            try:
                status = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.debug("probe %s:%s failed: %s", host, port, exc)
                status = FILTERED
            if status == OPEN:
                open_ports.append(port)
                if progress is not None:
                    progress.log(f"  [+] open   {host}:{port}  (identifying...)")
                if on_open is not None:
                    on_open(port)
            elif status == CLOSED:
                closed += 1
            else:
                filtered += 1
            if progress is not None:
                progress.tick(1, opened=1 if status == OPEN else 0)
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False)
    return sorted(open_ports), closed, filtered


def _probe_port(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    stop_event: Optional[threading.Event] = None,
) -> str:
    """Probe a single TCP port and classify the outcome.

    Returns one of ``OPEN``, ``CLOSED`` or ``FILTERED``.
    """
    last_attempt = retries + 1
    for _ in range(last_attempt):
        if stop_event is not None and stop_event.is_set():
            return FILTERED
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return OPEN
        except ConnectionRefusedError:
            return CLOSED  # Reachable host, port closed (RST).
        except ConnectionResetError:
            return CLOSED
        except socket.timeout:
            continue  # No response; retry if budget remains.
        except OSError:
            # Network unreachable, DNS failure, etc. Treat as filtered.
            return FILTERED
    return FILTERED


def syn_scan_host(
    host: str, ports: list[int], timeout: float
) -> tuple[list[int], int, int]:
    """Half-open SYN scan of a single host using Scapy. Requires root.

    Returns ``(open_ports, closed_count, filtered_count)``.
    """
    from scapy.all import IP, TCP, sr, send, conf  # Imported lazily.

    conf.verb = 0
    if not ports:
        return [], 0, 0

    try:
        resolved = socket.gethostbyname(host)
    except OSError as exc:
        raise RuntimeError(f"cannot resolve {host}: {exc}") from exc

    open_ports: set[int] = set()
    closed = 0
    packets = IP(dst=resolved) / TCP(dport=ports, flags="S")
    answered, _ = sr(packets, timeout=timeout, verbose=0)
    for _, received in answered:
        tcp_layer = received.getlayer(TCP)
        if tcp_layer is None:
            continue
        if tcp_layer.flags == 0x12:  # SYN/ACK -> open
            open_ports.add(int(tcp_layer.sport))
            # Politely tear down the half-open connection with a RST.
            send(IP(dst=resolved) / TCP(dport=tcp_layer.sport, flags="R"),
                 verbose=0)
        elif tcp_layer.flags == 0x14:  # RST/ACK -> closed
            closed += 1
    filtered = max(0, len(ports) - len(answered))
    return sorted(open_ports), closed, filtered


# --------------------------------------------------------------------------- #
# SSH validation
# --------------------------------------------------------------------------- #
def grab_ssh_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Connect and read the SSH identification banner.

    Returns the banner string if the service speaks SSH, otherwise None.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
            if not data.startswith(SSH_BANNER_PREFIX):
                return None
            # Some servers wait for our identification before proceeding;
            # send it so the connection closes cleanly.
            try:
                sock.sendall(CLIENT_BANNER)
            except OSError:
                pass
            return data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    except OSError:
        return None


def validate_ssh_paramiko(host: str, port: int, timeout: float) -> Optional[str]:
    """Confirm SSH via a full Paramiko handshake. Returns the remote banner."""
    try:
        import paramiko
    except ImportError:
        LOGGER.warning("paramiko not installed; falling back to banner check")
        return grab_ssh_banner(host, port, timeout)

    transport = None
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        return transport.remote_version
    except Exception:
        return None
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass


def validate_ssh_ports(
    host: str,
    ports: list[int],
    timeout: float,
    workers: int,
    method: str,
    stop_event: Optional[threading.Event] = None,
) -> dict[int, str]:
    """Validate which of ``ports`` serve SSH, concurrently.

    Returns a mapping of port -> banner for confirmed SSH services.
    """
    if method == "none" or not ports:
        return {}

    validator = validate_ssh_paramiko if method == "paramiko" else grab_ssh_banner
    confirmed: dict[int, str] = {}
    pool_size = max(1, min(workers, len(ports)))
    executor = ThreadPoolExecutor(max_workers=pool_size)
    futures = {
        executor.submit(validator, host, port, timeout): port for port in ports
    }
    try:
        for future in as_completed(futures):
            if stop_event is not None and stop_event.is_set():
                break
            port = futures[future]
            banner = future.result()
            if banner:
                confirmed[port] = banner
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False)
    return confirmed


# --------------------------------------------------------------------------- #
# SSH security audit (algorithms, host key, auth methods, Terrapin)
# --------------------------------------------------------------------------- #
def audit_ssh_service(
    host: str, port: int, timeout: float, deep: bool = True
) -> SSHAudit:
    """Collect security-relevant facts about an SSH service without logging in.

    The algorithm inventory and Terrapin assessment are derived from the
    server's KEXINIT and need no third-party libraries. The host key
    fingerprint and accepted authentication methods require a partial
    handshake via Paramiko (``deep``); they are skipped gracefully if it is
    unavailable.
    """
    audit = SSHAudit(host=host, port=port)
    try:
        kex = read_server_kexinit(host, port, timeout)
    except OSError as exc:
        audit.notes.append(f"kexinit read failed: {exc}")
        kex = None

    if kex:
        audit.server_version = kex.get("banner", "")
        audit.kex_algorithms = kex.get("kex", [])
        audit.host_key_algorithms = kex.get("server_host_key", [])
        audit.ciphers = _unique(kex.get("enc_s2c", []), kex.get("enc_c2s", []))
        audit.macs = _unique(kex.get("mac_s2c", []), kex.get("mac_c2s", []))
        audit.weaknesses = assess_weaknesses(kex)
        audit.terrapin_vulnerable = is_terrapin_vulnerable(kex)

    if deep:
        try:
            key_type, fingerprint, methods = _audit_with_paramiko(
                host, port, timeout
            )
            audit.host_key_type = key_type
            audit.host_key_fingerprint = fingerprint
            audit.auth_methods = methods
        except _ParamikoUnavailable:
            audit.notes.append(
                "host key / auth methods need paramiko (pip install paramiko)"
            )
        except Exception as exc:  # pragma: no cover - network dependent
            audit.notes.append(f"deep audit failed: {exc}")
    return audit


def parse_kexinit(payload: bytes) -> Optional[dict]:
    """Parse an SSH_MSG_KEXINIT payload into its algorithm name-lists."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        return None
    offset = 1 + 16  # message type byte + 16-byte cookie
    fields = (
        "kex",
        "server_host_key",
        "enc_c2s",
        "enc_s2c",
        "mac_c2s",
        "mac_s2c",
        "comp_c2s",
        "comp_s2c",
        "lang_c2s",
        "lang_s2c",
    )
    result: dict[str, list[str]] = {}
    for name in fields:
        if offset + 4 > len(payload):
            return None
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        if offset + length > len(payload):
            return None
        raw = payload[offset:offset + length].decode("ascii", "replace")
        offset += length
        result[name] = raw.split(",") if raw else []
    return result


def read_server_kexinit(host: str, port: int, timeout: float) -> Optional[dict]:
    """Connect, exchange identification strings and read the server KEXINIT."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        banner = _read_ident_line(sock)
        if banner is None:
            return None
        sock.sendall(CLIENT_BANNER)
        # First binary packet from the server is its KEXINIT. Pre-key-exchange
        # packets are unencrypted and carry no MAC, so we can read them raw.
        (packet_len,) = struct.unpack(">I", _recv_exact(sock, 4))
        if not 2 <= packet_len <= 200_000:
            return None
        body = _recv_exact(sock, packet_len)
        padding_len = body[0]
        payload = body[1:packet_len - padding_len]
        parsed = parse_kexinit(payload)
        if parsed is None:
            return None
        parsed["banner"] = banner
        return parsed


def is_terrapin_vulnerable(kex: dict) -> bool:
    """Assess exposure to the Terrapin prefix-truncation attack (CVE-2023-48795).

    A server is exposed when it offers a vulnerable mode -- ChaCha20-Poly1305,
    or a CBC cipher paired with an Encrypt-then-MAC algorithm -- and does not
    advertise the strict key-exchange countermeasure.
    """
    if "kex-strict-s-v00@openssh.com" in kex.get("kex", []):
        return False
    ciphers = set(kex.get("enc_s2c", [])) | set(kex.get("enc_c2s", []))
    macs = set(kex.get("mac_s2c", [])) | set(kex.get("mac_c2s", []))
    if "chacha20-poly1305@openssh.com" in ciphers:
        return True
    has_cbc = any(c.endswith("-cbc") for c in ciphers)
    has_etm = any(m.endswith("-etm@openssh.com") for m in macs)
    return has_cbc and has_etm


def assess_weaknesses(kex: dict) -> list[str]:
    """Return human-readable findings for deprecated/weak algorithms offered."""
    findings: list[str] = []
    weak_kex = [k for k in kex.get("kex", []) if _is_weak_kex(k)]
    weak_hostkey = [k for k in kex.get("server_host_key", []) if k in WEAK_HOST_KEYS]
    ciphers = _unique(kex.get("enc_s2c", []), kex.get("enc_c2s", []))
    weak_ciphers = [c for c in ciphers if _is_weak_cipher(c)]
    macs = _unique(kex.get("mac_s2c", []), kex.get("mac_c2s", []))
    weak_macs = [m for m in macs if _is_weak_mac(m)]
    if weak_kex:
        findings.append("weak key exchange: " + ", ".join(weak_kex))
    if weak_hostkey:
        findings.append("weak host key alg: " + ", ".join(weak_hostkey))
    if weak_ciphers:
        findings.append("weak ciphers: " + ", ".join(weak_ciphers))
    if weak_macs:
        findings.append("weak MACs: " + ", ".join(weak_macs))
    return findings


def _is_weak_kex(name: str) -> bool:
    return "sha1" in name or name.startswith("diffie-hellman-group1-")


def _is_weak_cipher(name: str) -> bool:
    return (
        name == "none"
        or name.endswith("-cbc")
        or name.startswith("arcfour")
        or name.startswith("des")
        or name.startswith("blowfish")
        or name.startswith("cast128")
    )


def _is_weak_mac(name: str) -> bool:
    return (
        name == "none"
        or "md5" in name
        or "sha1" in name
        or name.endswith("-96")
        or name.startswith("umac-64")
    )


def _unique(*lists: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for items in lists:
        for item in items:
            seen.setdefault(item, None)
    return list(seen)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            raise OSError("connection closed mid-packet")
        buffer += chunk
    return buffer


def _read_ident_line(sock: socket.socket, max_lines: int = 20) -> Optional[str]:
    """Read the server identification line (the one starting with 'SSH-').

    Reads a byte at a time so the following binary KEXINIT packet is left
    untouched in the socket buffer.
    """
    for _ in range(max_lines):
        line = b""
        while not line.endswith(b"\n"):
            char = sock.recv(1)
            if not char:
                return None
            line += char
            if len(line) > 1024:
                break
        text = line.rstrip(b"\r\n")
        if text.startswith(SSH_BANNER_PREFIX):
            return text.decode("latin-1", "replace")
    return None


class _ParamikoUnavailable(Exception):
    """Raised when the optional Paramiko dependency is not installed."""


def _audit_with_paramiko(
    host: str, port: int, timeout: float
) -> tuple[str, str, list[str]]:
    """Return ``(host_key_type, fingerprint, auth_methods)`` via Paramiko."""
    try:
        import paramiko
    except ImportError:
        raise _ParamikoUnavailable

    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        digest = hashlib.sha256(key.asbytes()).digest()
        fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
        key_type = key.get_name()

        auth_methods: list[str] = []
        try:
            transport.auth_none(AUTH_PROBE_USER)
            # Unauthenticated login accepted (very rare / misconfigured).
            auth_methods = ["none"]
        except paramiko.BadAuthenticationType as exc:
            auth_methods = list(exc.allowed_types)
        except paramiko.AuthenticationException:
            auth_methods = []
        return key_type, fingerprint, auth_methods
    finally:
        try:
            transport.close()
        except Exception:
            pass


def correlate_host_keys(results: list["HostResult"]) -> dict[str, list[str]]:
    """Group sockets by shared SSH host-key fingerprint.

    A fingerprint reused across multiple hosts often reveals cloned VMs,
    shared/load-balanced backends or poor key management.
    """
    by_fingerprint: dict[str, list[str]] = defaultdict(list)
    for result in results:
        for port, audit in result.audits.items():
            if audit.host_key_fingerprint:
                by_fingerprint[audit.host_key_fingerprint].append(
                    f"{result.host}:{port}"
                )
    return {
        fingerprint: sorted(sockets)
        for fingerprint, sockets in by_fingerprint.items()
        if len(sockets) > 1
    }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
@dataclass
class _Assessment:
    """Result of identifying and auditing the service behind one open port."""

    port: int
    banner: Optional[str] = None
    audit: Optional[SSHAudit] = None


def scan_host(
    host: str,
    ports: list[int],
    *,
    scan_method: str,
    validate: str,
    timeout: float,
    workers: int,
    retries: int,
    audit: bool = False,
    stop_event: Optional[threading.Event] = None,
    progress: Optional[ProgressReporter] = None,
) -> HostResult:
    """Scan a single host, identifying the service behind each open port as
    soon as it is discovered.

    Port discovery and service assessment (SSH validation plus optional audit)
    run as a pipeline on two thread pools: the moment a port is found open it
    is handed to the assessment pool, so SSH services are confirmed while the
    rest of the port range is still being scanned -- the user no longer waits
    for the whole sweep to finish before learning what is SSH.
    """
    result = HostResult(host=host)
    result.service_checked = validate != "none"

    assess_pool: Optional[ThreadPoolExecutor] = None
    assess_futures: dict = {}
    if result.service_checked:
        assess_pool = ThreadPoolExecutor(max_workers=_assess_pool_size(workers))

    def schedule_assessment(port: int) -> None:
        if assess_pool is None:
            return
        if stop_event is not None and stop_event.is_set():
            return
        future = assess_pool.submit(
            _assess_service, host, port, timeout, validate, audit,
            stop_event, progress,
        )
        assess_futures[future] = port

    try:
        if scan_method == "syn":
            open_ports, closed, filtered = syn_scan_host(host, ports, timeout)
            if progress is not None:
                progress.tick(len(ports), opened=len(open_ports))
            for port in open_ports:
                if progress is not None:
                    progress.log(f"  [+] open   {host}:{port}  (identifying...)")
                schedule_assessment(port)
        else:
            open_ports, closed, filtered = connect_scan_host(
                host, ports, timeout, workers, retries, stop_event, progress,
                on_open=schedule_assessment,
            )
        result.open_ports = open_ports
        result.closed = closed
        result.filtered = filtered
    except Exception as exc:
        result.error = str(exc)
        LOGGER.debug("scan of %s failed: %s", host, exc)
        if assess_pool is not None:
            assess_pool.shutdown(wait=False)
        return result

    # The assessments were already running concurrently with the port sweep;
    # collect them now that discovery is done.
    for future in as_completed(assess_futures):
        if stop_event is not None and stop_event.is_set():
            break
        port = assess_futures[future]
        try:
            assessment = future.result()
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.debug("assessment %s:%s failed: %s", host, port, exc)
            continue
        if assessment.banner:
            result.banners[port] = assessment.banner
            result.ssh_ports.append(port)
        if assessment.audit is not None:
            result.audits[port] = assessment.audit
    result.ssh_ports.sort()
    if assess_pool is not None:
        for future in assess_futures:
            future.cancel()
        assess_pool.shutdown(wait=False)
    return result


def _assess_pool_size(workers: int) -> int:
    """Bound the per-host assessment pool; open ports are usually few."""
    return max(4, min(workers, 32))


def _assess_service(
    host: str,
    port: int,
    timeout: float,
    validate: str,
    audit: bool,
    stop_event: Optional[threading.Event],
    progress: Optional[ProgressReporter],
) -> _Assessment:
    """Identify (and optionally audit) the service behind a single open port."""
    assessment = _Assessment(port=port)
    if stop_event is not None and stop_event.is_set():
        return assessment

    validator = (
        validate_ssh_paramiko if validate == "paramiko" else grab_ssh_banner
    )
    banner = validator(host, port, timeout)
    if not banner:
        return assessment

    assessment.banner = banner
    message = f"  [SSH] {host}:{port}" + (f"  {banner}" if banner else "")
    if progress is not None:
        progress.log(message)
    else:
        LOGGER.info("SSH on %s:%s", host, port)

    if audit and not (stop_event is not None and stop_event.is_set()):
        info = audit_ssh_service(host, port, timeout)
        assessment.audit = info
        _report_audit(progress, info)
    return assessment


def _report_audit(
    progress: Optional[ProgressReporter], audit: SSHAudit
) -> None:
    """Surface the most actionable audit findings live."""
    alerts: list[str] = []
    if audit.password_auth:
        alerts.append("password-auth")
    if audit.terrapin_vulnerable:
        alerts.append("Terrapin-VULNERABLE")
    if audit.weaknesses:
        alerts.append("weak-crypto")
    if not alerts:
        return
    message = f"  [audit] {audit.host}:{audit.port}  " + ", ".join(alerts)
    if progress is not None:
        progress.log(message)
    else:
        LOGGER.info("audit %s:%s %s", audit.host, audit.port, ", ".join(alerts))


def scan_targets(
    hosts: list[str],
    ports: list[int],
    *,
    scan_method: str,
    validate: str,
    timeout: float,
    workers: int,
    retries: int,
    host_concurrency: int,
    audit: bool = False,
    progress: Optional[ProgressReporter] = None,
) -> list[HostResult]:
    """Scan many hosts concurrently and return their results.

    Ctrl+C is handled robustly even on Windows: the main thread waits on
    worker threads in short, interruptible slices rather than one unbounded
    lock acquisition, and a dedicated SIGINT handler flips a shared stop flag
    that every worker observes. A first Ctrl+C stops gracefully and returns
    partial results; a second forces an immediate exit.
    """
    stop_event = threading.Event()
    interrupt_state = {"count": 0}

    def _handle_sigint(signum, frame):  # noqa: ANN001 - signal handler
        interrupt_state["count"] += 1
        stop_event.set()
        if interrupt_state["count"] >= 2:
            # Second press: let the default behaviour tear things down now.
            raise KeyboardInterrupt

    can_handle = threading.current_thread() is threading.main_thread()
    previous_handler = None
    if can_handle:
        try:
            previous_handler = signal.signal(signal.SIGINT, _handle_sigint)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            can_handle = False

    results_map: dict[str, HostResult] = {}
    pool_size = max(1, min(host_concurrency, len(hosts)))
    executor = ThreadPoolExecutor(max_workers=pool_size)
    futures = {
        executor.submit(
            scan_host,
            host,
            ports,
            scan_method=scan_method,
            validate=validate,
            timeout=timeout,
            workers=workers,
            retries=retries,
            audit=audit,
            stop_event=stop_event,
            progress=progress,
        ): host
        for host in hosts
    }

    def _collect(done_futures) -> None:
        for future in done_futures:
            host = futures[future]
            if host in results_map:
                continue
            try:
                results_map[host] = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.error("unexpected error scanning %s: %s", host, exc)
                results_map[host] = HostResult(host=host, error=str(exc))

    pending = set(futures)
    try:
        # Poll in short slices so the main thread regularly returns to the
        # interpreter and any pending Ctrl+C is delivered (critical on Windows).
        while pending:
            done, pending = wait(
                pending, timeout=POLL_INTERVAL, return_when=FIRST_COMPLETED
            )
            _collect(done)
            if stop_event.is_set():
                break
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False)
        if can_handle:
            signal.signal(
                signal.SIGINT,
                previous_handler if previous_handler is not None else signal.SIG_DFL,
            )

    if stop_event.is_set():
        force = interrupt_state["count"] >= 2
        _note(progress, "Interrupt received - stopping scan...")
        if not force:
            # Give in-flight host scans a brief moment to wind down and report
            # whatever they already found.
            grace = wait(list(futures), timeout=timeout + 1.0)
            _collect(grace.done)

    results = [results_map[h] for h in hosts if h in results_map]
    if len(results) < len(hosts):
        LOGGER.warning(
            "Partial results: %d of %d host(s) completed before stopping",
            len(results),
            len(hosts),
        )
    return results


def _note(progress: Optional[ProgressReporter], message: str) -> None:
    if progress is not None:
        progress.log(message)
    else:
        LOGGER.warning(message)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def render_text(results: list[HostResult]) -> str:
    lines: list[str] = []
    ssh_sockets: list[str] = []
    for result in results:
        lines.append(f"=== {result.host} ===")
        if result.error:
            lines.append(f"  error: {result.error}")
            continue
        if not result.open_ports:
            if result.filtered and not result.responsive:
                lines.append(
                    "  no open ports - host did not respond "
                    f"({result.filtered} filtered); likely firewalled or down"
                )
            elif result.filtered:
                lines.append(
                    f"  no open ports ({result.closed} closed, "
                    f"{result.filtered} filtered)"
                )
            else:
                lines.append("  no open ports (host reachable, all closed)")
            continue
        annotated = []
        for port in result.open_ports:
            if port in result.ssh_ports:
                tag = "SSH"
            elif result.service_checked:
                tag = "not ssh"
            else:
                tag = "service unknown"
            annotated.append(f"{result.host}:{port} [{tag}]")
        lines.append(f"  open: {', '.join(annotated)}")
        if result.ssh_ports:
            for port in result.ssh_ports:
                socket_str = f"{result.host}:{port}"
                ssh_sockets.append(socket_str)
                banner = result.banners.get(port, "")
                suffix = f"  ({banner})" if banner else ""
                lines.append(f"  SSH  {socket_str}{suffix}")
                lines.extend(_render_audit(result.audits.get(port)))
        else:
            lines.append("  no SSH services confirmed")

    lines.append("")
    shared_keys = correlate_host_keys(results)
    if shared_keys:
        lines.append("Shared SSH host keys (possible shared/cloned hosts):")
        for fingerprint, sockets in sorted(shared_keys.items()):
            lines.append(f"  {fingerprint}")
            lines.append(f"    -> {', '.join(sockets)}")
        lines.append("")
    if ssh_sockets:
        lines.append(f"SSH services found ({len(ssh_sockets)}):")
        lines.extend(f"  {sock}" for sock in ssh_sockets)
    lines.append(
        f"Scanned {len(results)} host(s); "
        f"confirmed {len(ssh_sockets)} SSH service(s)."
    )
    return "\n".join(lines)


def _render_audit(audit: Optional[SSHAudit]) -> list[str]:
    """Render the indented audit detail block for a single SSH service."""
    if audit is None:
        return []
    lines: list[str] = []
    if audit.host_key_fingerprint:
        key_type = audit.host_key_type or "host key"
        lines.append(f"       host key: {key_type} {audit.host_key_fingerprint}")
    if audit.auth_methods:
        flag = "  [!] password auth enabled" if audit.password_auth else ""
        lines.append(f"       auth: {', '.join(audit.auth_methods)}{flag}")
    if audit.terrapin_vulnerable:
        lines.append("       [!] Terrapin (CVE-2023-48795): VULNERABLE")
    for finding in audit.weaknesses:
        lines.append(f"       [!] {finding}")
    for note in audit.notes:
        lines.append(f"       note: {note}")
    return lines


def render_json(results: list[HostResult]) -> str:
    return json.dumps([r.as_dict() for r in results], indent=2)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sshfinder",
        description="Fast, reliable discovery of open SSH services.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more targets: IP, hostname or CIDR (e.g. 10.0.0.0/24).",
    )
    parser.add_argument(
        "-iL",
        "--target-file",
        dest="target_file",
        help="Read targets from a file, one per line ('#' comments allowed).",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_PORTS,
        help=f"Ports to scan, e.g. '22,80,1000-2000' (default: {DEFAULT_PORTS}).",
    )
    parser.add_argument(
        "--scan-method",
        choices=("auto", "connect", "syn"),
        default="auto",
        help="Port scan back-end (default: auto).",
    )
    parser.add_argument(
        "--validate",
        choices=("banner", "paramiko", "none"),
        default="banner",
        help="SSH validation strategy (default: banner).",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Audit each SSH service: algorithms, host key, auth methods, "
        "Terrapin (CVE-2023-48795) and shared-host-key correlation.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-connection timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent probes per host (default: {DEFAULT_WORKERS}).",
    )
    parser.add_argument(
        "--host-concurrency",
        type=int,
        default=DEFAULT_HOST_CONCURRENCY,
        help=f"Hosts scanned in parallel (default: {DEFAULT_HOST_CONCURRENCY}).",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Retries for timed-out probes (default: {DEFAULT_RETRIES}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write results to a file instead of stdout.",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the live progress indicator.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (debug logging).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress and informational logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def configure_logging(verbose: int, quiet: bool) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose >= 1:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(message)s",
    )


def run(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose, args.quiet)

    # Gather targets from positional args and/or a file.
    tokens = list(args.targets)
    if args.target_file:
        try:
            tokens.extend(read_target_file(args.target_file))
        except OSError as exc:
            parser.error(f"cannot read target file: {exc}")
    if not tokens:
        parser.error("no targets supplied (provide targets or --target-file)")

    try:
        hosts = expand_targets(tokens)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    if args.workers < 1 or args.host_concurrency < 1:
        parser.error("workers and host-concurrency must be >= 1")
    if args.retries < 0:
        parser.error("retries must be >= 0")
    if args.timeout <= 0:
        parser.error("timeout must be positive")

    scan_method = resolve_scan_method(args.scan_method)
    if scan_method == "syn" and not has_raw_socket_privilege():
        parser.error("syn scan requires root privileges")
    if args.scan_method == "syn" and not _scapy_available():
        parser.error("syn scan requires the optional 'scapy' dependency")

    validate = args.validate
    if args.audit and validate == "none":
        # Auditing needs confirmed SSH services to act on.
        validate = "banner"
        LOGGER.info("--audit requires SSH validation; using 'banner'")

    LOGGER.info(
        "Scanning %d host(s) x %d port(s) using %s scan "
        "(timeout=%.1fs, workers=%d). Press Ctrl+C to stop.",
        len(hosts),
        len(ports),
        scan_method,
        args.timeout,
        args.workers,
    )
    if scan_method == "connect" and len(ports) * len(hosts) > 5000:
        LOGGER.info(
            "Large scan: unresponsive/firewalled hosts make this take a "
            "while. Narrow it with -p (e.g. -p 22,2222) to go faster."
        )

    progress_enabled = (
        not args.quiet and not args.no_progress and sys.stderr.isatty()
    )
    reporter = ProgressReporter(
        total=len(hosts) * len(ports),
        enabled=progress_enabled,
        quiet=args.quiet,
    )

    try:
        results = scan_targets(
            hosts,
            ports,
            scan_method=scan_method,
            validate=validate,
            timeout=args.timeout,
            workers=args.workers,
            retries=args.retries,
            host_concurrency=args.host_concurrency,
            audit=args.audit,
            progress=reporter,
        )
    finally:
        reporter.finish()

    output = render_json(results) if args.json else render_text(results)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            LOGGER.error("cannot write output file: %s", exc)
            return 1
        LOGGER.info("results written to %s", args.output)
    else:
        print(output)

    # Exit non-zero only on hard errors, not on "nothing found".
    if results and all(r.error for r in results):
        return 1
    return 0


def main() -> None:
    try:
        sys.exit(run())
    except KeyboardInterrupt:
        print("\nScan aborted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
