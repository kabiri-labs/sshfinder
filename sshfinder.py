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
import ipaddress
import json
import logging
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional

__version__ = "2.0.0"

LOGGER = logging.getLogger("sshfinder")

# Defaults chosen to be safe and reasonably fast on typical networks.
DEFAULT_PORTS = "1-65535"
DEFAULT_TIMEOUT = 2.0
DEFAULT_WORKERS = 200
DEFAULT_RETRIES = 1
MAX_PORT = 65535
SSH_BANNER_PREFIX = b"SSH-"
# Identification string we present when probing, per RFC 4253.
CLIENT_BANNER = b"SSH-2.0-sshfinder\r\n"


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class HostResult:
    """Outcome of scanning a single host."""

    host: str
    open_ports: list[int] = field(default_factory=list)
    ssh_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "open_ports": sorted(self.open_ports),
            "ssh_ports": sorted(self.ssh_ports),
            "banners": {str(p): b for p, b in sorted(self.banners.items())},
            "error": self.error,
        }


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
    return False  # Non-POSIX: assume no raw-socket access.


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
) -> list[int]:
    """Concurrent TCP connect scan of a single host.

    Returns the sorted list of ports that accepted a connection.
    """
    open_ports: list[int] = []
    if not ports:
        return open_ports

    # Cap the worker pool so we never create more threads than there is work.
    pool_size = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=pool_size) as executor:
        future_to_port = {
            executor.submit(_probe_port, host, port, timeout, retries): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.debug("probe %s:%s failed: %s", host, port, exc)
    return sorted(open_ports)


def _probe_port(host: str, port: int, timeout: float, retries: int) -> bool:
    """Return True if a TCP connection to ``host:port`` succeeds."""
    last_attempt = retries + 1
    for attempt in range(last_attempt):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            # Host is reachable but the port is closed; retrying won't help.
            return False
        except OSError:
            # Timeouts and transient errors are worth retrying.
            if attempt + 1 >= last_attempt:
                return False
    return False


def syn_scan_host(host: str, ports: list[int], timeout: float) -> list[int]:
    """Half-open SYN scan of a single host using Scapy. Requires root."""
    from scapy.all import IP, TCP, sr, send, conf  # Imported lazily.

    conf.verb = 0
    if not ports:
        return []

    try:
        resolved = socket.gethostbyname(host)
    except OSError as exc:
        raise RuntimeError(f"cannot resolve {host}: {exc}") from exc

    open_ports: set[int] = set()
    packets = IP(dst=resolved) / TCP(dport=ports, flags="S")
    answered, _ = sr(packets, timeout=timeout, verbose=0)
    for _, received in answered:
        tcp_layer = received.getlayer(TCP)
        if tcp_layer is not None and tcp_layer.flags == 0x12:  # SYN/ACK
            open_ports.add(int(tcp_layer.sport))
            # Politely tear down the half-open connection with a RST.
            send(IP(dst=resolved) / TCP(dport=tcp_layer.sport, flags="R"),
                 verbose=0)
    return sorted(open_ports)


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
) -> dict[int, str]:
    """Validate which of ``ports`` serve SSH, concurrently.

    Returns a mapping of port -> banner for confirmed SSH services.
    """
    if method == "none" or not ports:
        return {}

    validator = validate_ssh_paramiko if method == "paramiko" else grab_ssh_banner
    confirmed: dict[int, str] = {}
    pool_size = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=pool_size) as executor:
        future_to_port = {
            executor.submit(validator, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            banner = future.result()
            if banner:
                confirmed[port] = banner
    return confirmed


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def scan_host(
    host: str,
    ports: list[int],
    *,
    scan_method: str,
    validate: str,
    timeout: float,
    workers: int,
    retries: int,
) -> HostResult:
    """Scan a single host end to end: port scan then SSH validation."""
    result = HostResult(host=host)
    try:
        if scan_method == "syn":
            result.open_ports = syn_scan_host(host, ports, timeout)
        else:
            result.open_ports = connect_scan_host(
                host, ports, timeout, workers, retries
            )
    except Exception as exc:
        result.error = str(exc)
        LOGGER.debug("scan of %s failed: %s", host, exc)
        return result

    if result.open_ports:
        banners = validate_ssh_ports(
            host, result.open_ports, timeout, workers, validate
        )
        result.banners = banners
        result.ssh_ports = sorted(banners)
    return result


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
) -> list[HostResult]:
    """Scan many hosts concurrently and return their results."""
    results: list[HostResult] = []
    pool_size = max(1, min(host_concurrency, len(hosts)))
    with ThreadPoolExecutor(max_workers=pool_size) as executor:
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
            ): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.error("unexpected error scanning %s: %s", host, exc)
                results.append(HostResult(host=host, error=str(exc)))
    # Preserve the input ordering for stable, readable output.
    order = {host: i for i, host in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r.host, len(order)))
    return results


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def render_text(results: list[HostResult]) -> str:
    lines: list[str] = []
    total_ssh = 0
    for result in results:
        lines.append(f"=== {result.host} ===")
        if result.error:
            lines.append(f"  error: {result.error}")
            continue
        if not result.open_ports:
            lines.append("  no open ports found")
            continue
        lines.append(f"  open ports: {', '.join(map(str, result.open_ports))}")
        if result.ssh_ports:
            total_ssh += len(result.ssh_ports)
            for port in result.ssh_ports:
                banner = result.banners.get(port, "")
                suffix = f"  ({banner})" if banner else ""
                lines.append(f"  SSH on port {port}{suffix}")
        else:
            lines.append("  no SSH services confirmed")
    lines.append("")
    lines.append(
        f"Scanned {len(results)} host(s); "
        f"confirmed {total_ssh} SSH service(s)."
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
        default=16,
        help="Number of hosts scanned in parallel (default: 16).",
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
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress logging.",
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
    elif verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
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
    if args.timeout <= 0:
        parser.error("timeout must be positive")

    scan_method = resolve_scan_method(args.scan_method)
    if scan_method == "syn" and not has_raw_socket_privilege():
        parser.error("syn scan requires root privileges")
    if args.scan_method == "syn" and not _scapy_available():
        parser.error("syn scan requires the optional 'scapy' dependency")

    LOGGER.info(
        "Scanning %d host(s) across %d port(s) using %s scan",
        len(hosts),
        len(ports),
        scan_method,
    )

    try:
        results = scan_targets(
            hosts,
            ports,
            scan_method=scan_method,
            validate=args.validate,
            timeout=args.timeout,
            workers=args.workers,
            retries=args.retries,
            host_concurrency=args.host_concurrency,
        )
    except KeyboardInterrupt:
        LOGGER.error("scan aborted by user")
        return 130

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
    if all(r.error for r in results) and results:
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
