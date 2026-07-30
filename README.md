# sshfinder

[![CI](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml/badge.svg)](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-2.5.0-blue)

`sshfinder` is a fast, reliable tool for discovering open **SSH** services
across one or many targets. It scans for open TCP ports and then confirms
which of them actually speak SSH — running both stages concurrently for
speed.

## Features

- **Multiple targets** — scan many IPs, hostnames, and CIDR networks
  (e.g. `10.0.0.0/24`) in a single run, or load them from a file.
- **Non-blocking scan engine** — every connection in flight is driven from a
  single thread by an OS event loop (`epoll`/`kqueue`/`select`), so
  concurrency costs a file descriptor rather than an OS thread. A full
  1–65535 sweep is ~6× faster than the previous thread-pool engine, and the
  target is resolved once per host instead of once per port.
- **SSH ports first** — the handful of ports SSH actually lives on (22, 2222,
  22222, …) are probed at the head of every sweep, so a service is usually
  confirmed in well under a second even when the scan covers all 65535 ports.
- **Adaptive timeout** — probes wait as long as the path actually warrants,
  not a flat two seconds. The smoothed round-trip estimator from RFC 6298 —
  the one TCP itself uses — is fed by every answered probe and shared across
  the scan, so `--timeout` becomes a ceiling rather than a fixed cost. On a
  live-but-mostly-filtered host this is worth ~5× (34s → 6s over 8000 ports)
  with identical findings; `--no-adaptive-timeout` restores the flat wait.
- **Two scan back-ends**:
  - `connect` — portable TCP connect scan, no privileges required (default).
  - `syn` — half-open SYN scan via Scapy (faster, requires root).
- **Reliable SSH validation** — completes the RFC 4253 identification
  exchange rather than glancing at the first bytes on the wire: servers that
  print a legal banner first, that wait for the client to identify, or whose
  banner arrives split across TCP segments are all correctly recognised.
  Optional full Paramiko handshake validation is available too.
- **Streaming output (`--stream`)** — newline-delimited JSON events on stdout,
  flushed as each port opens and each SSH service is confirmed, so a pipeline
  can act on the first result while the scan is still running.
- **SSH security audit (`--audit`)** — turns discovery into attack-surface
  intelligence for pentesters: enumerates accepted authentication methods
  (flagging password auth), lists offered KEX/cipher/MAC/host-key algorithms
  and flags weak/deprecated ones, detects **Terrapin (CVE-2023-48795)**, and
  **correlates shared host keys** across targets to reveal cloned or
  load-balanced infrastructure.
- **Zero required dependencies** — the default connect scan and banner
  validation run on the Python standard library alone.
- **Bounded by design** — a process-wide socket budget derived from the
  file-descriptor limit keeps a large scan from exhausting descriptors and
  misreporting live services as filtered, and target expansion refuses to
  materialise a range larger than `--max-targets`.
- **Early exit on dead hosts** — a host that answers nothing at all across the
  first few hundred probes is reported as unresponsive instead of consuming
  one timeout per remaining port. Because SSH's ports are swept first, a live
  service is always seen first; `--no-early-exit` forces the full range.
- **Pipelined identification** — the service behind each open port is
  identified (and audited) the instant the port is found, in parallel with the
  rest of the port sweep. SSH services are confirmed without waiting for the
  whole scan to finish, and every open port is labelled `[SSH]` / `[not ssh]`
  so an open port is never mistaken for an SSH one.
- **Live, per-socket discovery** — open ports and confirmed SSH services are
  printed the moment they are found, as `host:port`, so it is always clear
  which result belongs to which target when scanning many hosts.
- **Live progress & robust Ctrl+C** — a real-time progress indicator shows the
  scan is working. Ctrl+C is honoured even on Windows (where an unbounded
  thread wait normally swallows it): the first press stops gracefully and
  returns partial results, a second forces an immediate exit.
- **Clear host status** — distinguishes open, closed, and *filtered* ports,
  so a firewalled or unreachable host is reported as such instead of looking
  like a hang.
- **Machine-readable output** — human-friendly text or `--json`, optionally
  written to a file.

## Installation

```bash
git clone https://github.com/kabiri-labs/sshfinder.git
cd sshfinder

# Installs paramiko (recommended: enables the full --audit deep checks and
# --validate paramiko):
pip install -r requirements.txt

# Optional, only for half-open SYN scans (needs root):
pip install scapy>=2.5
```

The core connect scan, banner validation and the dependency-free parts of
`--audit` (algorithm inventory, weak-crypto flags, Terrapin) work without any
third-party packages; paramiko unlocks host-key fingerprints, auth-method
enumeration and shared-key correlation.

Requires **Python 3.9+**.

## Usage

```bash
python sshfinder.py [targets ...] [options]
```

### Options

| Option | Description |
| ------ | ----------- |
| `targets` | One or more IPs, hostnames, or CIDR networks. |
| `-iL, --target-file FILE` | Read targets from a file (one per line, `#` comments allowed). |
| `-p, --ports SPEC` | Ports to scan, e.g. `22,80,1000-2000` (default: `1-65535`). |
| `--scan-method {auto,connect,syn}` | Scan back-end (default: `auto`). |
| `--validate {banner,paramiko,none}` | SSH validation strategy (default: `banner`). |
| `--audit` | Audit each SSH service (algorithms, host key, auth methods, Terrapin, shared-key correlation). |
| `-t, --timeout SECONDS` | Longest a probe may wait (default: `2.0`). |
| `--min-timeout SECONDS` | Floor for the adaptive probe timeout (default: `0.1`). |
| `--no-adaptive-timeout` | Wait the full `--timeout` on every probe instead of adapting to the measured round-trip time. |
| `-w, --workers N` | Connections in flight per host (default: `512`). |
| `--max-sockets N` | Ceiling on probe sockets open at once across the whole scan (default: derived from the file-descriptor limit). |
| `--host-concurrency N` | Hosts scanned in parallel (default: `16`). |
| `-r, --retries N` | Retries for timed-out probes (default: `0`). |
| `--max-targets N` | Refuse target lists larger than this (default: `65536`). |
| `--no-early-exit` | Sweep every port even on hosts that answer nothing at all. |
| `--json` | Emit results as JSON. |
| `--stream` | Emit newline-delimited JSON events on stdout as results are found. |
| `-o, --output FILE` | Write results to a file instead of stdout. |
| `--no-progress` | Disable the live progress indicator. |
| `-v` | Verbose (debug) logging. |
| `-q, --quiet` | Suppress progress and informational logging. |

> **Note on slow scans.** A full `1-65535` sweep of a firewalled host still
> has to wait out a timeout per filtered port. Four things keep that from
> hurting: SSH's own ports are probed first, so a live service surfaces
> immediately; the timeout shrinks to whatever the host's measured round-trip
> time warrants; a host that answers nothing at all is abandoned after a few
> hundred silent probes; and `--stream` delivers each result as it lands. To
> go faster still, narrow the ports (`-p 22,2222`) or lower the ceiling
> (`-t 1`).
>
> The adaptive timeout only governs port discovery. The banner exchange and
> `--audit` always get the full `--timeout`, because how fast a host completes
> a TCP handshake says nothing about how fast its SSH daemon answers. The
> ports SSH usually lives on also get one final probe at the full ceiling
> before being reported filtered.
>
> `-w` bounds the connections one host keeps in flight, but the real ceiling
> is `--max-sockets`, derived from the process file-descriptor limit and
> shared across all hosts. Raising `-w` past it has no effect.

`auto` selects the SYN scan when running as root with Scapy installed,
and otherwise falls back to the privilege-free connect scan.

## Examples

Scan a single host on the common SSH ports:

```bash
python sshfinder.py 192.168.1.1 -p 22,2222
```

Scan an entire subnet and emit JSON:

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --json -o results.json
```

Scan many targets from a file with a fast SYN scan (as root):

```bash
sudo python sshfinder.py -iL targets.txt --scan-method syn
```

Strictly validate SSH with a full handshake:

```bash
python sshfinder.py example.com -p 22 --validate paramiko
```

Stream results into a pipeline as they are found, without waiting for the
scan to finish:

```bash
python sshfinder.py 10.0.0.0/24 --stream -q | jq -c 'select(.event=="ssh")'
```

```
{"event":"ssh","elapsed":0.164,"host":"10.0.0.5","port":22,"banner":"SSH-2.0-OpenSSH_9.6"}
{"event":"ssh","elapsed":0.881,"host":"10.0.0.9","port":2222,"banner":"SSH-2.0-dropbear"}
```

Audit the SSH attack surface across a subnet (auth methods, weak crypto,
Terrapin, shared host keys):

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --audit
```

Example audit output:

```
=== 10.0.0.5 ===
  open: 10.0.0.5:22
  SSH  10.0.0.5:22  (SSH-2.0-OpenSSH_7.4)
       host key: ssh-ed25519 SHA256:T/ZM4jOL4amTsO5K3AaCdg2...
       auth: publickey, password  [!] password auth enabled
       [!] Terrapin (CVE-2023-48795): VULNERABLE
       [!] weak ciphers: aes128-cbc

Shared SSH host keys (possible shared/cloned hosts):
  SHA256:T/ZM4jOL4amTsO5K3AaCdg2...
    -> 10.0.0.5:22, 10.0.0.9:22
```

The algorithm inventory, weak-crypto flags and Terrapin check work with no
dependencies. Host key fingerprints, auth-method enumeration and shared-key
correlation use Paramiko (`pip install paramiko`).

## Development

The test suite is standard-library only, so it runs on a bare interpreter:

```bash
python -m unittest discover -s tests
```

Install the runtime dependencies to also exercise the Paramiko-backed audit
tests, which skip themselves when Paramiko is missing:

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests
```

## Legal

Only scan systems you own or are explicitly authorized to test. Unauthorized
scanning may be illegal in your jurisdiction.
