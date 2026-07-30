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
import errno
import hashlib
import ipaddress
import json
import logging
import os
import selectors
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import (
    FIRST_COMPLETED,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

__version__ = "2.6.0"

LOGGER = logging.getLogger("sshfinder")

# Defaults chosen to be safe and reasonably fast on typical networks.
DEFAULT_PORTS = "1-65535"
DEFAULT_TIMEOUT = 2.0
DEFAULT_MIN_TIMEOUT = 0.1
DEFAULT_WORKERS = 512
DEFAULT_RETRIES = 0
DEFAULT_HOST_CONCURRENCY = 16
DEFAULT_MAX_TARGETS = 65536
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

# Ports SSH actually tends to live on. Probing these first means a service is
# usually confirmed within milliseconds even when the sweep covers all 65535.
SSH_PRIORITY_PORTS = (22, 2222, 22222, 2022, 2200, 22022, 8022, 830)

# Ceiling on probe sockets held open at once. The real limit is the process
# file-descriptor allowance; this bounds it on systems with a generous one.
MAX_SOCKET_BUDGET = 8192
# File descriptors left for stdio, DNS, and the assessment stage.
SOCKET_BUDGET_HEADROOM = 128
# Windows select() is bounded by FD_SETSIZE (512); stay clear of it.
WINDOWS_SOCKET_BUDGET = 400

# A host that answers nothing at all across this many probes of a large port
# range is firewalled or down, and sweeping the rest buys nothing.
EARLY_EXIT_MIN_PORTS = 1024
EARLY_EXIT_PROBES = 256

# Smoothed round-trip estimator constants, per RFC 6298 (Jacobson-Karels):
# alpha and beta weight each new sample into the mean and the deviation, and
# the timeout allows K deviations of slack above the mean.
RTT_ALPHA = 0.125
RTT_BETA = 0.25
RTT_VARIANCE_FACTOR = 4

# SSH binary protocol constants (RFC 4253).
SSH_MSG_KEXINIT = 20
# RFC 4253 section 4.2 lets a server send arbitrary lines before its
# identification string; bound how much of that preamble we will read.
MAX_PREAMBLE_LINES = 20
MAX_IDENT_LINE = 1024
MAX_SSH_PACKET = 200_000
# Ports per Scapy send/receive batch, so a SYN scan stays interruptible.
SYN_CHUNK_SIZE = 1024
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

# Post-quantum key exchange readiness.
#
# The standardised hybrids, and the only ones a current OpenSSH client will
# actually pick: ML-KEM (FIPS 203) and Streamlined NTRU Prime, each combined
# with X25519 so the result is no weaker than classical ECDH. OpenSSH has
# offered sntrup761 since 9.0 and ML-KEM since 9.9, and made
# mlkem768x25519-sha256 the default in 10.0.
PQ_KEX_STANDARD = frozenset({
    "mlkem768x25519-sha256",
    "mlkem768x25519-sha256@openssh.com",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
})
# Substrings that identify a post-quantum hybrid of any vintage, including
# pre-standard vendor drafts such as sntrup4591761x25519-sha512@tinyssh.org
# and x25519-kyber-512r3-sha256-d00@amazon.com. Matching on the family rather
# than enumerating every draft name keeps unknown spellings out of the
# "no post-quantum support at all" bucket, where they would read as a
# finding the server does not deserve.
PQ_KEX_MARKERS = ("mlkem", "sntrup", "kyber")

# Post-quantum readiness verdicts.
PQ_READY = "ready"
PQ_LEGACY = "legacy"
PQ_ABSENT = "absent"
PQ_UNKNOWN = "unknown"


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
    pq_status: str = PQ_UNKNOWN
    pq_kex: list[str] = field(default_factory=list)
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
            "pq_status": self.pq_status,
            "pq_kex": self.pq_kex,
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
    early_exit: bool = False
    rtt_ms: Optional[float] = None
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
            "early_exit": self.early_exit,
            "rtt_ms": self.rtt_ms,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# Streaming events
# --------------------------------------------------------------------------- #
class EventStream:
    """Newline-delimited JSON events, flushed the instant something is found.

    A long sweep otherwise produces nothing machine-readable until it ends.
    Streaming lets a pipeline act on the first confirmed SSH service while the
    rest of the scan is still running.
    """

    def __init__(self, stream, enabled: bool = True):
        self._stream = stream
        self.enabled = enabled
        self._lock = threading.Lock()
        self._start = time.monotonic()

    def emit(self, event: str, **fields) -> None:
        if not self.enabled:
            return
        record = {
            "event": event,
            "elapsed": round(time.monotonic() - self._start, 3),
        }
        record.update(fields)
        line = json.dumps(record)
        with self._lock:
            try:
                self._stream.write(line + "\n")
                self._stream.flush()
            except (OSError, ValueError):
                # A closed or broken pipe must not abort an in-flight scan.
                self.enabled = False


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


def expand_targets(
    targets: Iterable[str], max_targets: int = DEFAULT_MAX_TARGETS
) -> list[str]:
    """Expand a collection of target tokens into a de-duplicated, ordered list
    of host strings.

    Each token may be an IP address, a hostname, or a CIDR network such as
    ``10.0.0.0/24`` (which is expanded into individual host addresses).

    ``max_targets`` bounds the expansion. Without it a stray ``/8`` -- or any
    IPv6 prefix wider than a ``/112`` -- would try to materialise millions of
    addresses and exhaust memory before a single packet was sent.

    Raises:
        ValueError: on a malformed token, an empty result, or an expansion
            that would exceed ``max_targets``.
    """
    if max_targets < 1:
        raise ValueError("max_targets must be >= 1")

    expanded: list[str] = []
    seen: set[str] = set()

    for token in targets:
        token = token.strip()
        if not token:
            continue
        for host in _expand_single_target(token, max_targets):
            if host in seen:
                continue
            if len(expanded) >= max_targets:
                raise ValueError(
                    f"target list exceeds {max_targets} hosts; narrow the "
                    "range or raise --max-targets"
                )
            seen.add(host)
            expanded.append(host)

    if not expanded:
        raise ValueError("no valid targets supplied")
    return expanded


def _expand_single_target(token: str, max_targets: int) -> Iterator[str]:
    # CIDR network (e.g. 192.168.1.0/24 or 2001:db8::/120).
    if "/" in token:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise ValueError(f"invalid network: {token!r}")
        # Check the size before materialising: a /8 is 16.7M addresses and an
        # IPv6 /64 is 2**64, either of which would hang the process.
        if network.num_addresses > max_targets + 2:
            raise ValueError(
                f"network {token} expands to {network.num_addresses} "
                f"addresses, above the {max_targets} limit; narrow the range "
                "or raise --max-targets"
            )
        empty = True
        for addr in network.hosts():
            empty = False
            yield str(addr)
        # A /32 or /128 yields no .hosts(); fall back to the address itself.
        if empty:
            yield str(network.network_address)
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
# Connect-scan engine: non-blocking sockets driven by one selector
# --------------------------------------------------------------------------- #
def _errnos(*names: str) -> frozenset:
    """Collect the errno values that exist on this platform."""
    return frozenset(
        value
        for value in (getattr(errno, name, None) for name in names)
        if value is not None
    )


# connect() on a non-blocking socket signals "not finished yet" through these.
_INPROGRESS_ERRNOS = _errnos(
    "EINPROGRESS", "EWOULDBLOCK", "EAGAIN", "EALREADY",
    "WSAEWOULDBLOCK", "WSAEINPROGRESS", "WSAEALREADY",
)
# A refusal or reset proves the host is up and the port is shut.
_CLOSED_ERRNOS = _errnos(
    "ECONNREFUSED", "ECONNRESET", "WSAECONNREFUSED", "WSAECONNRESET",
)
# Running out of descriptors is a local resource problem, never a port verdict.
_EXHAUSTED_ERRNOS = _errnos("EMFILE", "ENFILE", "ENOBUFS", "WSAEMFILE")


@dataclass(frozen=True)
class _Endpoint:
    """A resolved target: the address family and numeric address to dial."""

    family: int
    address: str
    scope: tuple = ()

    def sockaddr(self, port: int) -> tuple:
        return (self.address, port) + self.scope


def resolve_endpoint(host: str) -> _Endpoint:
    """Resolve ``host`` once, so a whole port sweep shares a single lookup.

    Resolving inside the probe turns a 65535-port sweep into 65535 resolver
    calls. Doing it once is both far faster and considerably kinder to the
    resolver.

    Raises:
        OSError: if the name cannot be resolved.
    """
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not infos:  # pragma: no cover - getaddrinfo raises instead
        raise OSError(f"cannot resolve {host}")
    family, _, _, _, sockaddr = infos[0]
    if family == socket.AF_INET6:
        return _Endpoint(family, sockaddr[0], tuple(sockaddr[2:4]))
    return _Endpoint(family, sockaddr[0])


class SocketBudget:
    """Process-wide cap on probe sockets held open simultaneously.

    Every connect in flight costs a file descriptor. Past the process limit
    socket creation fails, and a scanner that mistakes those failures for port
    verdicts silently reports live services as filtered -- so the ceiling is
    enforced here instead of being discovered the hard way. The budget is
    shared across hosts: one host may use the whole allowance, while sixteen
    parallel hosts divide it between them.
    """

    def __init__(self, capacity: int):
        self.capacity = max(1, capacity)
        self._used = 0
        self._lock = threading.Lock()

    @property
    def in_use(self) -> int:
        with self._lock:
            return self._used

    def acquire(self) -> bool:
        """Claim one slot. Returns False when the budget is exhausted."""
        with self._lock:
            if self._used >= self.capacity:
                return False
            self._used += 1
            return True

    def release(self, count: int = 1) -> None:
        with self._lock:
            self._used = max(0, self._used - count)

    def shrink(self, floor: int = 32) -> int:
        """Halve the ceiling after descriptor exhaustion.

        Returns the new capacity.
        """
        with self._lock:
            self.capacity = max(floor, self.capacity // 2)
            LOGGER.debug("socket budget reduced to %d", self.capacity)
            return self.capacity


def default_socket_budget() -> int:
    """Probe sockets this process can comfortably keep open at once."""
    if sys.platform == "win32":  # pragma: no cover - platform specific
        return WINDOWS_SOCKET_BUDGET
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX without win32
        return 256
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        # Raising the soft limit toward the hard one needs no privileges.
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard
        except (ValueError, OSError):  # pragma: no cover - policy dependent
            pass
    if soft == resource.RLIM_INFINITY:
        soft = MAX_SOCKET_BUDGET + SOCKET_BUDGET_HEADROOM
    return max(64, min(soft - SOCKET_BUDGET_HEADROOM, MAX_SOCKET_BUDGET))


_BUDGET_LOCK = threading.Lock()
_SHARED_BUDGET: Optional[SocketBudget] = None


def shared_socket_budget() -> SocketBudget:
    """The process-wide budget, created on first use."""
    global _SHARED_BUDGET
    with _BUDGET_LOCK:
        if _SHARED_BUDGET is None:
            _SHARED_BUDGET = SocketBudget(default_socket_budget())
        return _SHARED_BUDGET


def configure_socket_budget(capacity: int) -> SocketBudget:
    """Override the process-wide socket ceiling (see ``--max-sockets``)."""
    global _SHARED_BUDGET
    with _BUDGET_LOCK:
        _SHARED_BUDGET = SocketBudget(capacity)
        return _SHARED_BUDGET


class AdaptiveTimeout:
    """Probe timeout derived from the round trips a path actually shows.

    A fixed two-second timeout is wrong in both directions: wasteful on a LAN
    where every answer lands in under a millisecond, and too tight over a slow
    link. This tracks the smoothed round-trip time and its variance with the
    estimator from RFC 6298 -- the one TCP itself uses to set retransmission
    timeouts -- and allows ``srtt + 4 * rttvar`` before giving up on a probe.

    Only a definite answer, a SYN/ACK or a RST, measures anything. A timeout
    teaches nothing about the path and is deliberately never fed back in,
    which is what keeps the estimate from ratcheting itself upward.

    ``--timeout`` remains the ceiling, so no probe ever waits longer than the
    user asked for, and ``floor`` keeps a fast local path from tightening the
    timeout to the point where ordinary scheduling jitter looks like loss.

    Estimators are per-host, since round-trip time is a property of the path.
    ``pool`` links one to the estimate shared by the whole scan, which is what
    lets short per-host sweeps -- ``-p 22`` across a subnet, where no single
    host ever collects enough answers to tune itself -- converge at all: every
    host starts from what the others have already measured.
    """

    def __init__(
        self,
        ceiling: float,
        floor: float = DEFAULT_MIN_TIMEOUT,
        enabled: bool = True,
        pool: Optional["AdaptiveTimeout"] = None,
    ):
        self.ceiling = max(0.001, ceiling)
        self.floor = min(max(0.001, floor), self.ceiling)
        self.enabled = enabled
        self._pool = pool
        self._lock = threading.Lock()
        self._srtt: Optional[float] = None
        self._rttvar = 0.0
        if pool is not None:
            seed = pool.snapshot()
            if seed is not None:
                self._srtt, self._rttvar = seed

    def derive(self) -> "AdaptiveTimeout":
        """A per-host estimator seeded from, and reporting back to, this one."""
        return AdaptiveTimeout(
            self.ceiling, floor=self.floor, enabled=self.enabled, pool=self
        )

    def snapshot(self) -> Optional[tuple]:
        """``(srtt, rttvar)`` so far, or None if nothing has been measured."""
        with self._lock:
            if self._srtt is None:
                return None
            return self._srtt, self._rttvar

    @property
    def rtt(self) -> Optional[float]:
        """Smoothed round-trip time in seconds, or None if never measured."""
        with self._lock:
            return self._srtt

    def observe(self, rtt: float) -> None:
        """Fold one measured round trip into the estimate."""
        rtt = min(max(rtt, 0.0), self.ceiling)
        with self._lock:
            if self._srtt is None:
                self._srtt = rtt
                self._rttvar = rtt / 2.0
            else:
                self._rttvar = (
                    (1 - RTT_BETA) * self._rttvar
                    + RTT_BETA * abs(self._srtt - rtt)
                )
                self._srtt = (1 - RTT_ALPHA) * self._srtt + RTT_ALPHA * rtt
        if self._pool is not None:
            self._pool.observe(rtt)

    def value(self) -> float:
        """How long the next probe should wait for an answer."""
        if not self.enabled:
            return self.ceiling
        with self._lock:
            if self._srtt is None:
                return self.ceiling
            estimate = self._srtt + RTT_VARIANCE_FACTOR * self._rttvar
        return min(self.ceiling, max(self.floor, estimate))


def order_ports(ports: Iterable[int]) -> list[int]:
    """Order a port list so SSH's usual homes are probed first.

    Scanning ascending reaches port 22222 only at the very end of a full
    sweep. Front-loading the handful of ports SSH actually uses costs nothing
    and is what makes the first useful result appear almost immediately.
    """
    unique = sorted(set(ports))
    available = set(unique)
    priority = [p for p in SSH_PRIORITY_PORTS if p in available]
    promoted = set(priority)
    return priority + [p for p in unique if p not in promoted]


def _classify_connect_errno(code: int) -> str:
    """Map a failed connect() error to a port verdict."""
    if code in _CLOSED_ERRNOS:
        return CLOSED
    return FILTERED


@dataclass
class _Probe:
    """One connect() in flight.

    Only the issue time is recorded, never a fixed deadline: the timeout is
    re-read from the estimator on every check, so a probe issued while the
    estimate was pessimistic stops waiting as soon as the path proves fast.
    """

    port: int
    fd: int
    sock: socket.socket
    start: float
    done: bool = False


@dataclass
class _SweepOutcome:
    """Aggregate verdicts from sweeping one host."""

    open_ports: list[int] = field(default_factory=list)
    closed: int = 0
    filtered: int = 0
    probed: int = 0
    unresponsive: bool = False
    rtt: Optional[float] = None


class _UnresponsiveGate:
    """Decides when a large sweep of a silent host should be abandoned.

    A host that returns neither a SYN/ACK nor a RST across the first few
    hundred probes is firewalled or down. Continuing costs one timeout per
    remaining port -- eleven minutes for a full range at the default two
    seconds -- and yields nothing. Because SSH's usual ports are probed first,
    a reachable SSH service is always seen before this can trip.
    """

    def __init__(
        self,
        total_ports: int,
        threshold: int = EARLY_EXIT_PROBES,
        min_ports: int = EARLY_EXIT_MIN_PORTS,
    ):
        self.enabled = total_ports > min_ports
        self.threshold = threshold
        self.probed = 0
        self.answered = 0

    def record(self, status: str) -> None:
        self.probed += 1
        if status != FILTERED:
            self.answered += 1

    def tripped(self) -> bool:
        return (
            self.enabled
            and self.answered == 0
            and self.probed >= self.threshold
        )


def _sweep_pass(
    endpoint: _Endpoint,
    ports: list[int],
    *,
    timer: AdaptiveTimeout,
    max_inflight: int,
    budget: SocketBudget,
    on_result: Callable[[int, str, Optional[socket.socket]], bool],
    on_timeout: Optional[Callable[[int], None]] = None,
    stop_event: Optional[threading.Event] = None,
    should_abort: Optional[Callable[[], bool]] = None,
) -> tuple[list[int], list[int]]:
    """Probe every port in ``ports`` once, driving all sockets from one thread.

    ``timer`` supplies how long to wait for an answer and is fed every round
    trip that produced one, so the sweep tightens itself as it learns the
    path. Because all in-flight probes share whatever the current estimate is,
    issue order stays deadline order and expiry remains a queue walk.

    ``on_result`` receives ``(port, status, socket_or_None)`` and returns True
    if it has taken ownership of a connected socket -- which lets the caller
    read the SSH banner over the very connection that proved the port open,
    halving the handshakes an SSH service costs.

    Returns ``(timed_out, unresolved)``: ports that answered nothing, and ports
    left without a verdict because the sweep stopped early.
    """
    selector = selectors.DefaultSelector()
    live: dict[int, _Probe] = {}
    expiry: deque = deque()  # Probes in deadline order (all share one timeout).
    timed_out: list[int] = []
    unresolved: list[int] = []
    index = 0
    aborted = False

    def retire(probe: _Probe) -> None:
        probe.done = True
        live.pop(probe.fd, None)
        try:
            selector.unregister(probe.sock)
        except (KeyError, ValueError):  # pragma: no cover - defensive
            pass

    try:
        while not aborted:
            if stop_event is not None and stop_event.is_set():
                break

            # 1. Top up the in-flight set.
            while index < len(ports) and len(live) < max_inflight:
                if not budget.acquire():
                    break
                port = ports[index]
                try:
                    sock = socket.socket(endpoint.family, socket.SOCK_STREAM)
                except OSError as exc:
                    budget.release()
                    if exc.errno in _EXHAUSTED_ERRNOS and live:
                        # Drain what is already in flight, then try again with
                        # a lower ceiling rather than misreport this port.
                        max_inflight = max(
                            1, min(max_inflight, budget.shrink())
                        )
                        break
                    index += 1
                    on_result(port, FILTERED, None)
                    continue
                index += 1
                sock.setblocking(False)
                try:
                    code = sock.connect_ex(endpoint.sockaddr(port))
                except OSError as exc:  # pragma: no cover - platform dependent
                    code = exc.errno or 0
                if code == 0:
                    # Connected without blocking (typical on loopback).
                    if not on_result(port, OPEN, sock):
                        sock.close()
                    budget.release()
                    continue
                if code in _INPROGRESS_ERRNOS:
                    probe = _Probe(port, sock.fileno(), sock, time.monotonic())
                    live[probe.fd] = probe
                    expiry.append(probe)
                    selector.register(sock, selectors.EVENT_WRITE, probe)
                    continue
                sock.close()
                budget.release()
                on_result(port, _classify_connect_errno(code), None)

            if not live:
                if index >= len(ports):
                    break
                # Budget momentarily held by other hosts; yield briefly.
                time.sleep(0.005)
                continue

            # 2. Wait for completions, but never past the nearest deadline.
            while expiry and expiry[0].done:
                expiry.popleft()
            wait_for = POLL_INTERVAL
            if expiry:
                oldest = expiry[0].start + timer.value()
                wait_for = min(
                    POLL_INTERVAL, max(0.0, oldest - time.monotonic())
                )
            for key, _ in selector.select(timeout=wait_for):
                probe = key.data
                retire(probe)
                try:
                    code = probe.sock.getsockopt(
                        socket.SOL_SOCKET, socket.SO_ERROR
                    )
                except OSError as exc:  # pragma: no cover - defensive
                    code = exc.errno or 0
                if code == 0 or code in _CLOSED_ERRNOS:
                    # A SYN/ACK or a RST is a completed round trip, and the
                    # only kind of answer that says anything about the path.
                    timer.observe(time.monotonic() - probe.start)
                if code == 0:
                    if not on_result(probe.port, OPEN, probe.sock):
                        probe.sock.close()
                else:
                    probe.sock.close()
                    on_result(probe.port, _classify_connect_errno(code), None)
                budget.release()

            # 3. Expire probes that have waited out the current estimate.
            now = time.monotonic()
            limit = timer.value()
            while expiry and (expiry[0].done or expiry[0].start + limit <= now):
                probe = expiry.popleft()
                if probe.done:
                    continue
                retire(probe)
                probe.sock.close()
                budget.release()
                timed_out.append(probe.port)
                if on_timeout is not None:
                    on_timeout(probe.port)

            if should_abort is not None and should_abort():
                aborted = True
    finally:
        # Anything still in flight never reached a verdict; report it as such
        # rather than letting the caller assume the range was fully covered.
        for probe in list(live.values()):
            retire(probe)
            probe.sock.close()
            budget.release()
            unresolved.append(probe.port)
        selector.close()

    unresolved.extend(ports[index:])
    return timed_out, unresolved


def _connect_sweep(
    host: str,
    ports: list[int],
    *,
    timeout: float,
    max_inflight: int,
    retries: int = 0,
    stop_event: Optional[threading.Event] = None,
    progress: Optional[ProgressReporter] = None,
    on_open: Optional[Callable[[int, Optional[socket.socket]], bool]] = None,
    budget: Optional[SocketBudget] = None,
    early_exit: bool = True,
    timer: Optional[AdaptiveTimeout] = None,
) -> _SweepOutcome:
    """Sweep one host's ports, reporting each verdict as it lands.

    ``timeout`` is the ceiling; ``timer`` decides how much of it each probe
    actually waits. Without one, a fresh per-host estimator is used.
    """
    outcome = _SweepOutcome()
    if not ports:
        return outcome

    endpoint = resolve_endpoint(host)
    budget = budget if budget is not None else shared_socket_budget()
    timer = timer if timer is not None else AdaptiveTimeout(timeout)
    queue = order_ports(ports)
    priority = {p for p in SSH_PRIORITY_PORTS if p in set(queue)}
    # Priority ports that answered nothing -- the only ones worth a retry.
    silent_priority: set = set()
    gate = _UnresponsiveGate(len(queue)) if early_exit else None

    def record(port: int, status: str, sock: Optional[socket.socket]) -> bool:
        taken = False
        if status == OPEN:
            outcome.open_ports.append(port)
            silent_priority.discard(port)
            if progress is not None:
                progress.log(f"  [+] open   {host}:{port}  (identifying...)")
            if on_open is not None:
                taken = bool(on_open(port, sock))
        elif status == CLOSED:
            outcome.closed += 1
            silent_priority.discard(port)
        else:
            outcome.filtered += 1
            if port in priority:
                silent_priority.add(port)
        outcome.probed += 1
        if gate is not None:
            gate.record(status)
        if progress is not None:
            progress.tick(1, opened=1 if status == OPEN else 0)
        return taken

    attempt = 0
    while queue:
        final = attempt >= retries
        timed_out, unresolved = _sweep_pass(
            endpoint,
            queue,
            timer=timer,
            max_inflight=max_inflight,
            budget=budget,
            on_result=record,
            on_timeout=(lambda p: record(p, FILTERED, None)) if final else None,
            stop_event=stop_event,
            should_abort=gate.tripped if gate is not None else None,
        )
        if unresolved:
            if gate is not None and gate.tripped():
                outcome.unresponsive = True
                outcome.filtered += len(unresolved)
                if progress is not None:
                    progress.tick(len(unresolved))
            break
        if final or not timed_out:
            break
        queue = timed_out
        attempt += 1

    _reprobe_ssh_ports(
        host,
        endpoint,
        sorted(silent_priority),
        outcome,
        timeout=timeout,
        budget=budget,
        stop_event=stop_event,
        progress=progress,
        on_open=on_open,
    )
    outcome.open_ports.sort()
    outcome.rtt = timer.rtt
    return outcome


def _reprobe_ssh_ports(
    host: str,
    endpoint: _Endpoint,
    candidates: list[int],
    outcome: _SweepOutcome,
    *,
    timeout: float,
    budget: SocketBudget,
    stop_event: Optional[threading.Event],
    progress: Optional[ProgressReporter],
    on_open: Optional[Callable[[int, Optional[socket.socket]], bool]],
) -> None:
    """Give SSH's usual ports a second chance before calling them filtered.

    ``candidates`` are the priority ports that answered nothing at all. A
    dropped SYN is the one packet loss that actually costs this tool a
    finding, and at high concurrency it does happen. Re-probing this handful
    is bounded by a single timeout, so the accuracy is close to free -- unlike
    a blanket ``--retries``, which doubles the cost of the whole sweep.

    This last chance deliberately waits out the full ``--timeout`` rather than
    the tightened estimate: an adaptive timeout is a throughput optimisation,
    and the one place not to spend accuracy on throughput is the final look at
    the ports the tool exists to find.
    """
    if not candidates or (stop_event is not None and stop_event.is_set()):
        return

    def record(port: int, status: str, sock: Optional[socket.socket]) -> bool:
        if status == FILTERED:
            return False
        # Every candidate was counted as filtered by the main sweep, so a
        # verdict here replaces that tally rather than adding to it.
        outcome.filtered = max(0, outcome.filtered - 1)
        outcome.unresponsive = False  # The host answered after all.
        if status == CLOSED:
            outcome.closed += 1
            return False
        outcome.open_ports.append(port)
        if progress is not None:
            progress.log(f"  [+] open   {host}:{port}  (identifying...)")
        return bool(on_open(port, sock)) if on_open is not None else False

    _sweep_pass(
        endpoint,
        candidates,
        timer=AdaptiveTimeout(timeout, enabled=False),
        max_inflight=max(1, min(len(candidates), budget.capacity)),
        budget=budget,
        on_result=record,
        stop_event=stop_event,
    )


def connect_scan_host(
    host: str,
    ports: list[int],
    timeout: float,
    workers: int,
    retries: int,
    stop_event: Optional[threading.Event] = None,
    progress: Optional[ProgressReporter] = None,
    on_open: Optional[Callable[[int], None]] = None,
    *,
    budget: Optional[SocketBudget] = None,
    early_exit: bool = True,
    adaptive: bool = True,
    min_timeout: float = DEFAULT_MIN_TIMEOUT,
) -> tuple[list[int], int, int]:
    """Non-blocking TCP connect scan of a single host.

    ``workers`` bounds how many connects this host keeps in flight; the real
    ceiling is the process-wide :class:`SocketBudget`. All of them are driven
    from one thread by a selector, so concurrency costs a file descriptor
    rather than an OS thread.

    ``timeout`` is the longest a probe may wait. Unless ``adaptive`` is off,
    probes wait only as long as the host's measured round-trip time warrants,
    down to ``min_timeout``.

    Returns ``(open_ports, closed_count, filtered_count)``. Open ports are
    reported live through ``progress`` and handed to ``on_open`` the instant
    they are found, so a caller can identify services while the rest of the
    range is still being swept.
    """
    outcome = _connect_sweep(
        host,
        ports,
        timeout=timeout,
        max_inflight=max(1, workers),
        retries=retries,
        stop_event=stop_event,
        progress=progress,
        on_open=(lambda port, _sock: bool(on_open(port))) if on_open else None,
        budget=budget,
        early_exit=early_exit,
        timer=AdaptiveTimeout(timeout, floor=min_timeout, enabled=adaptive),
    )
    return outcome.open_ports, outcome.closed, outcome.filtered


def syn_scan_host(
    host: str,
    ports: list[int],
    timeout: float,
    stop_event: Optional[threading.Event] = None,
    progress: Optional[ProgressReporter] = None,
    on_open: Optional[Callable[[int, Optional[socket.socket]], bool]] = None,
    chunk_size: int = SYN_CHUNK_SIZE,
) -> tuple[list[int], int, int]:
    """Half-open SYN scan of a single host using Scapy. Requires root.

    Ports are sent in batches so the scan reports progress as it goes, hands
    open ports onward for identification immediately, and can be interrupted
    -- a single Scapy call over 65535 ports does none of those things.

    Returns ``(open_ports, closed_count, filtered_count)``.
    """
    from scapy.all import IP, TCP, sr, send, conf  # Imported lazily.

    conf.verb = 0
    if not ports:
        return [], 0, 0

    endpoint = resolve_endpoint(host)
    if endpoint.family != socket.AF_INET:
        raise RuntimeError(
            f"syn scan supports IPv4 only; {host} resolved to "
            f"{endpoint.address} - use --scan-method connect"
        )

    open_ports: list[int] = []
    closed = 0
    filtered = 0
    for chunk in _chunk(order_ports(ports), max(1, chunk_size)):
        if stop_event is not None and stop_event.is_set():
            break
        answered, _ = sr(
            IP(dst=endpoint.address) / TCP(dport=chunk, flags="S"),
            timeout=timeout,
            verbose=0,
        )
        replies = 0
        for _, received in answered:
            tcp_layer = received.getlayer(TCP)
            if tcp_layer is None:
                continue
            replies += 1
            port = int(tcp_layer.sport)
            if tcp_layer.flags == 0x12:  # SYN/ACK -> open
                open_ports.append(port)
                if progress is not None:
                    progress.log(
                        f"  [+] open   {host}:{port}  (identifying...)"
                    )
                if on_open is not None:
                    on_open(port, None)
                # Politely tear down the half-open connection with a RST.
                send(IP(dst=endpoint.address) / TCP(dport=port, flags="R"),
                     verbose=0)
            elif tcp_layer.flags == 0x14:  # RST/ACK -> closed
                closed += 1
        filtered += max(0, len(chunk) - replies)
        if progress is not None:
            progress.tick(len(chunk), opened=len(open_ports))
    return sorted(open_ports), closed, filtered


def _chunk(items: list, size: int) -> Iterator[list]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


# --------------------------------------------------------------------------- #
# SSH validation
# --------------------------------------------------------------------------- #
class _BufferedReader:
    """Line and fixed-length reads over one socket, sharing a read buffer.

    The SSH identification exchange is line-oriented while everything after it
    is binary and length-prefixed. Buffering lets both share a connection
    without the byte-at-a-time reads that reading lines from a raw socket
    otherwise requires, and enforces a single deadline across the whole
    exchange so a slow trickle of bytes cannot stall a probe indefinitely.
    """

    def __init__(self, sock: socket.socket, timeout: float):
        self._sock = sock
        self._buffer = b""
        self._deadline = time.monotonic() + timeout

    def _fill(self, size: int = 4096) -> bool:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            self._sock.settimeout(remaining)
            chunk = self._sock.recv(size)
        except OSError:
            return False
        if not chunk:
            return False
        self._buffer += chunk
        return True

    def read_line(self, limit: int) -> Optional[bytes]:
        """Return the next line without its terminator, or None if there is
        no complete line within ``limit`` bytes and the deadline."""
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = self._buffer[:index]
                self._buffer = self._buffer[index + 1:]
                return line.rstrip(b"\r")
            if len(self._buffer) > limit:
                return None  # Not line-oriented; stop reading.
            if not self._fill():
                return None

    def read_exact(self, count: int) -> bytes:
        """Read exactly ``count`` bytes.

        Raises:
            OSError: if the peer closes or goes quiet before they arrive.
        """
        while len(self._buffer) < count:
            if not self._fill(max(4096, count - len(self._buffer))):
                raise OSError("connection closed mid-packet")
        data = self._buffer[:count]
        self._buffer = self._buffer[count:]
        return data


def read_ssh_identification(
    reader: _BufferedReader, max_lines: int = MAX_PREAMBLE_LINES
) -> Optional[str]:
    """Scan incoming lines for the SSH identification string.

    RFC 4253 section 4.2 permits a server to send any number of other lines --
    legal notices, load messages -- before its ``SSH-`` identification string,
    and requires clients to skip them. A scanner that reads one buffer and
    demands ``SSH-`` at offset zero misses every such server.
    """
    for _ in range(max_lines):
        line = reader.read_line(MAX_IDENT_LINE)
        if line is None:
            return None
        if line.startswith(SSH_BANNER_PREFIX):
            return line[:MAX_IDENT_LINE].decode("latin-1", "replace")
    return None


def grab_ssh_banner(
    host: str,
    port: int,
    timeout: float,
    sock: Optional[socket.socket] = None,
) -> Optional[str]:
    """Confirm a port speaks SSH by completing the identification exchange.

    Our identification string goes out first, exactly as OpenSSH does. Servers
    that withhold their banner until the client identifies -- and the proxies
    and jump hosts that front them -- otherwise sit silent until the timeout
    expires and get written off as "not SSH".

    ``sock`` adopts an already-connected socket, so a port discovered by the
    sweep is identified over that same connection instead of paying for a
    second TCP handshake. The socket is always closed before returning.

    Returns the banner string if the service speaks SSH, otherwise None.
    """
    connection = sock
    try:
        if connection is None:
            connection = socket.create_connection((host, port), timeout=timeout)
        connection.setblocking(True)
        connection.settimeout(timeout)
        connection.sendall(CLIENT_BANNER)
        return read_ssh_identification(_BufferedReader(connection, timeout))
    except OSError:
        return None
    finally:
        _close_quietly(connection)


def _close_quietly(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:  # pragma: no cover - defensive
        pass


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
        audit.pq_status, audit.pq_kex = assess_post_quantum(kex)

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


def read_server_kexinit(
    host: str,
    port: int,
    timeout: float,
    sock: Optional[socket.socket] = None,
) -> Optional[dict]:
    """Connect, exchange identification strings and read the server KEXINIT.

    Raises:
        OSError: if the connection fails or dies mid-packet.
    """
    connection = sock
    try:
        if connection is None:
            connection = socket.create_connection((host, port), timeout=timeout)
        connection.setblocking(True)
        connection.settimeout(timeout)
        connection.sendall(CLIENT_BANNER)
        reader = _BufferedReader(connection, timeout)
        banner = read_ssh_identification(reader)
        if banner is None:
            return None
        # First binary packet from the server is its KEXINIT. Pre-key-exchange
        # packets are unencrypted and carry no MAC, so we can read them raw.
        (packet_len,) = struct.unpack(">I", reader.read_exact(4))
        if not 2 <= packet_len <= MAX_SSH_PACKET:
            return None
        body = reader.read_exact(packet_len)
        padding_len = body[0]
        if padding_len + 1 > packet_len:
            return None  # Padding cannot exceed the packet it pads.
        payload = body[1:packet_len - padding_len]
        parsed = parse_kexinit(payload)
        if parsed is None:
            return None
        parsed["banner"] = banner
        return parsed
    finally:
        _close_quietly(connection)


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


def assess_post_quantum(kex: Optional[dict]) -> tuple:
    """Classify a server's post-quantum key exchange readiness.

    Returns ``(status, pq_algorithms)``.

    This is a statement about capability, not about what any particular
    session will negotiate. RFC 4253 picks the first algorithm on the
    *client's* list that the server also supports, so the client decides the
    outcome; what a scan can establish is what the server makes possible. The
    verdicts are therefore phrased in terms of what a current client would get:

    * ``ready``  -- a standardised hybrid is offered, so a current OpenSSH
      client negotiates post-quantum key agreement.
    * ``legacy`` -- only pre-standard hybrids are offered. This looks
      post-quantum in an algorithm dump but is not: OpenSSH dropped the
      withdrawn sntrup4591761 parameter set in 2020, so a current client finds
      no common post-quantum method and falls back to classical crypto.
    * ``absent`` -- no post-quantum key exchange at all. Every session is
      exposed to store-now-decrypt-later capture.
    * ``unknown`` -- the KEXINIT could not be read, so nothing is claimed.
    """
    if not kex:
        return PQ_UNKNOWN, []
    offered = kex.get("kex")
    if not offered:
        return PQ_UNKNOWN, []
    candidates = [
        name for name in offered
        if any(marker in name.lower() for marker in PQ_KEX_MARKERS)
    ]
    if not candidates:
        return PQ_ABSENT, []
    if any(name in PQ_KEX_STANDARD for name in candidates):
        return PQ_READY, candidates
    return PQ_LEGACY, candidates


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
    audit_deep: bool = True,
    stop_event: Optional[threading.Event] = None,
    progress: Optional[ProgressReporter] = None,
    stream: Optional[EventStream] = None,
    budget: Optional[SocketBudget] = None,
    early_exit: bool = True,
    rtt_pool: Optional[AdaptiveTimeout] = None,
) -> HostResult:
    """Scan a single host, identifying the service behind each open port as
    soon as it is discovered.

    Discovery and assessment (SSH validation plus optional audit) run as a
    pipeline: the moment a port is found open it is handed to the assessment
    pool -- along with the socket that discovered it, so identification costs
    no second handshake -- and SSH services are confirmed while the rest of
    the port range is still being swept.

    ``rtt_pool`` shares round-trip knowledge with the rest of the scan; this
    host derives its own estimator from it. Note that only port discovery
    adapts: the banner exchange and the audit keep the full ``timeout``,
    because how quickly a host completes a TCP handshake says nothing about
    how quickly its SSH daemon composes a greeting.
    """
    result = HostResult(host=host)
    result.service_checked = validate != "none"

    assess_pool: Optional[ThreadPoolExecutor] = None
    assess_futures: dict = {}
    if result.service_checked:
        assess_pool = ThreadPoolExecutor(max_workers=_assess_pool_size(workers))

    def handle_open(port: int, sock: Optional[socket.socket] = None) -> bool:
        """Pipeline an open port; returns True if it adopted ``sock``."""
        if stream is not None:
            stream.emit("open", host=host, port=port)
        stopping = stop_event is not None and stop_event.is_set()
        if assess_pool is None or stopping:
            return False
        try:
            future = assess_pool.submit(
                _assess_service, host, port, timeout, validate, audit,
                stop_event, progress, sock, stream, audit_deep,
            )
        except RuntimeError:  # pragma: no cover - pool already shutting down
            return False
        assess_futures[future] = port
        return sock is not None

    try:
        if scan_method == "syn":
            open_ports, closed, filtered = syn_scan_host(
                host, ports, timeout, stop_event, progress, on_open=handle_open,
            )
            result.open_ports = open_ports
            result.closed = closed
            result.filtered = filtered
        else:
            outcome = _connect_sweep(
                host,
                ports,
                timeout=timeout,
                max_inflight=max(1, workers),
                retries=retries,
                stop_event=stop_event,
                progress=progress,
                on_open=handle_open,
                budget=budget,
                early_exit=early_exit,
                timer=rtt_pool.derive() if rtt_pool is not None else None,
            )
            result.open_ports = outcome.open_ports
            result.closed = outcome.closed
            result.filtered = outcome.filtered
            result.early_exit = outcome.unresponsive
            if outcome.rtt is not None:
                result.rtt_ms = round(outcome.rtt * 1000, 3)
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
    sock: Optional[socket.socket] = None,
    stream: Optional[EventStream] = None,
    audit_deep: bool = True,
) -> _Assessment:
    """Identify (and optionally audit) the service behind a single open port.

    ``sock`` is the connection that discovered the port; it is consumed or
    closed here, never leaked back to the caller. ``audit_deep`` controls
    whether the audit also runs the Paramiko partial handshake; the algorithm
    inventory, Terrapin check and post-quantum verdict all come from the
    KEXINIT and need neither Paramiko nor the extra connection.
    """
    assessment = _Assessment(port=port)
    if stop_event is not None and stop_event.is_set():
        _close_quietly(sock)
        return assessment

    if validate == "paramiko":
        # Paramiko negotiates from scratch on a connection it owns.
        _close_quietly(sock)
        banner = validate_ssh_paramiko(host, port, timeout)
    else:
        banner = grab_ssh_banner(host, port, timeout, sock=sock)
    if not banner:
        return assessment

    assessment.banner = banner
    message = f"  [SSH] {host}:{port}" + (f"  {banner}" if banner else "")
    if progress is not None:
        progress.log(message)
    else:
        LOGGER.info("SSH on %s:%s", host, port)
    if stream is not None:
        stream.emit("ssh", host=host, port=port, banner=banner)

    if audit and not (stop_event is not None and stop_event.is_set()):
        info = audit_ssh_service(host, port, timeout, deep=audit_deep)
        assessment.audit = info
        _report_audit(progress, info)
        if stream is not None:
            stream.emit("audit", host=host, port=port, **info.as_dict())
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
    audit_deep: bool = True,
    progress: Optional[ProgressReporter] = None,
    stream: Optional[EventStream] = None,
    early_exit: bool = True,
    adaptive_timeout: bool = True,
    min_timeout: float = DEFAULT_MIN_TIMEOUT,
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
    budget = shared_socket_budget()
    # One pool of round-trip knowledge for the whole scan; each host derives
    # its own estimator from it, so later hosts start from what earlier ones
    # measured instead of every host relearning the network from scratch.
    rtt_pool = AdaptiveTimeout(
        timeout, floor=min_timeout, enabled=adaptive_timeout
    )
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
            audit_deep=audit_deep,
            stop_event=stop_event,
            progress=progress,
            stream=stream,
            budget=budget,
            early_exit=early_exit,
            rtt_pool=rtt_pool,
        ): host
        for host in hosts
    }

    def _collect(done_futures) -> None:
        for future in done_futures:
            host = futures[future]
            if host in results_map:
                continue
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.error("unexpected error scanning %s: %s", host, exc)
                result = HostResult(host=host, error=str(exc))
            results_map[host] = result
            # Publish each host the moment it finishes rather than banking
            # every result until the whole scan ends.
            if stream is not None:
                stream.emit("host", **result.as_dict())

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
    if stream is not None:
        stream.emit(
            "summary",
            hosts_requested=len(hosts),
            hosts_completed=len(results),
            ssh_services=sum(len(r.ssh_ports) for r in results),
            interrupted=stop_event.is_set(),
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
            if result.early_exit:
                lines.append(
                    "  no open ports - host answered nothing; sweep stopped "
                    f"early after {EARLY_EXIT_PROBES} silent probes "
                    "(use --no-early-exit to force the full range)"
                )
            elif result.filtered and not result.responsive:
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
    if any(result.audits for result in results):
        lines.append(render_pq_report(results))
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
    lines.extend(_render_pq(audit))
    for finding in audit.weaknesses:
        lines.append(f"       [!] {finding}")
    for note in audit.notes:
        lines.append(f"       note: {note}")
    return lines


def _render_pq(audit: SSHAudit) -> list[str]:
    """Render one service's post-quantum verdict."""
    if audit.pq_status == PQ_READY:
        return [f"       post-quantum: ready ({', '.join(audit.pq_kex)})"]
    if audit.pq_status == PQ_LEGACY:
        return [
            "       [!] post-quantum: pre-standard only "
            f"({', '.join(audit.pq_kex)}); a current client negotiates "
            "classical crypto"
        ]
    if audit.pq_status == PQ_ABSENT:
        return [
            "       [!] post-quantum: no PQ key exchange offered; sessions "
            "are exposed to store-now-decrypt-later capture"
        ]
    return []


def collect_pq_posture(results: list[HostResult]) -> dict:
    """Group SSH services by post-quantum readiness across the whole scan.

    Returns ``{status: [socket, ...]}``. The list matters more than the count:
    the actionable artifact for an estate owner is which services to fix.
    """
    posture: dict = defaultdict(list)
    for result in results:
        for port in sorted(result.audits):
            audit = result.audits[port]
            posture[audit.pq_status].append(f"{result.host}:{port}")
    return dict(posture)


def render_pq_report(results: list[HostResult]) -> str:
    """Render the fleet-level post-quantum readiness summary."""
    posture = collect_pq_posture(results)
    audited = sum(len(sockets) for sockets in posture.values())
    lines = ["Post-quantum readiness:"]
    if not audited:
        lines.append("  no SSH services were audited")
        return "\n".join(lines)

    exposed = posture.get(PQ_ABSENT, []) + posture.get(PQ_LEGACY, [])
    ready = posture.get(PQ_READY, [])
    unknown = posture.get(PQ_UNKNOWN, [])
    lines.append(
        f"  {len(ready)}/{audited} service(s) negotiate post-quantum key "
        "exchange with a current client"
    )
    if posture.get(PQ_ABSENT):
        absent = posture[PQ_ABSENT]
        lines.append(
            f"  [!] no PQ key exchange offered ({len(absent)}):"
        )
        lines.extend(f"        {sock}" for sock in posture[PQ_ABSENT])
    if posture.get(PQ_LEGACY):
        lines.append(
            f"  [!] pre-standard PQ only ({len(posture[PQ_LEGACY])}) - looks "
            "post-quantum but is not:"
        )
        lines.extend(f"        {sock}" for sock in posture[PQ_LEGACY])
    if unknown:
        lines.append(f"  key exchange unreadable ({len(unknown)}):")
        lines.extend(f"        {sock}" for sock in unknown)
    if exposed:
        lines.append(
            f"  {len(exposed)} service(s) exposed to store-now-decrypt-later "
            "capture; upgrade to OpenSSH 9.0+ (10.0+ preferred)"
        )
    return "\n".join(lines)


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
        "Terrapin (CVE-2023-48795), post-quantum readiness and "
        "shared-host-key correlation.",
    )
    parser.add_argument(
        "--pq-report",
        action="store_true",
        help="Report post-quantum key exchange readiness across the estate. "
        "Reads only the KEXINIT, so it needs no third-party library and "
        "costs one connection per confirmed SSH service.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Longest a probe may wait, in seconds "
        f"(default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--min-timeout",
        type=float,
        default=DEFAULT_MIN_TIMEOUT,
        help="Floor for the adaptive probe timeout "
        f"(default: {DEFAULT_MIN_TIMEOUT}).",
    )
    parser.add_argument(
        "--no-adaptive-timeout",
        action="store_true",
        help="Wait the full --timeout on every probe instead of adapting it "
        "to the measured round-trip time.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Connections kept in flight per host "
        f"(default: {DEFAULT_WORKERS}); --max-sockets is the hard ceiling.",
    )
    parser.add_argument(
        "--max-sockets",
        type=int,
        default=0,
        help="Cap on probe sockets open at once across the whole scan "
        "(default: derived from the file-descriptor limit).",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=DEFAULT_MAX_TARGETS,
        help="Refuse target lists larger than this "
        f"(default: {DEFAULT_MAX_TARGETS}).",
    )
    parser.add_argument(
        "--no-early-exit",
        action="store_true",
        help="Sweep every port even on hosts that answer nothing at all.",
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
        "--stream",
        action="store_true",
        help="Emit newline-delimited JSON events on stdout as ports open and "
        "SSH services are confirmed, instead of one report at the end.",
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

    if args.workers < 1 or args.host_concurrency < 1:
        parser.error("workers and host-concurrency must be >= 1")
    if args.retries < 0:
        parser.error("retries must be >= 0")
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if args.min_timeout <= 0:
        parser.error("min-timeout must be positive")
    if args.min_timeout > args.timeout:
        parser.error("min-timeout cannot exceed timeout")
    if args.max_targets < 1:
        parser.error("max-targets must be >= 1")
    if args.max_sockets < 0:
        parser.error("max-sockets must be >= 0")

    try:
        hosts = expand_targets(tokens, max_targets=args.max_targets)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    if args.max_sockets:
        configure_socket_budget(args.max_sockets)

    scan_method = resolve_scan_method(args.scan_method)
    if scan_method == "syn" and not has_raw_socket_privilege():
        parser.error("syn scan requires root privileges")
    if args.scan_method == "syn" and not _scapy_available():
        parser.error("syn scan requires the optional 'scapy' dependency")

    # --pq-report needs the KEXINIT but not the Paramiko handshake, so it runs
    # the audit shallow: dependency-free, and one connection per service
    # instead of two.
    audit = args.audit or args.pq_report
    audit_deep = args.audit
    validate = args.validate
    if audit and validate == "none":
        # Auditing needs confirmed SSH services to act on.
        validate = "banner"
        LOGGER.info("auditing requires SSH validation; using 'banner'")

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
    stream = EventStream(sys.stdout) if args.stream else None

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
            audit=audit,
            audit_deep=audit_deep,
            progress=reporter,
            stream=stream,
            early_exit=not args.no_early_exit,
            adaptive_timeout=not args.no_adaptive_timeout,
            min_timeout=args.min_timeout,
        )
    finally:
        reporter.finish()

    if args.json:
        output = render_json(results)
    elif args.pq_report and not args.audit:
        # Asked only for the readiness picture, so give exactly that: a full
        # per-host listing across an estate would bury it.
        output = render_pq_report(results)
    else:
        output = render_text(results)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            LOGGER.error("cannot write output file: %s", exc)
            return 1
        LOGGER.info("results written to %s", args.output)
    elif not args.stream:
        # With --stream the results already went out as they were found;
        # a trailing report would corrupt the JSONL on stdout.
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
