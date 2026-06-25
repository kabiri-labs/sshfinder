# sshfinder

[![CI](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml/badge.svg)](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml)

`sshfinder` is a fast, reliable tool for discovering open **SSH** services
across one or many targets. It scans for open TCP ports and then confirms
which of them actually speak SSH — running both stages concurrently for
speed.

## Features

- **Multiple targets** — scan many IPs, hostnames, and CIDR networks
  (e.g. `10.0.0.0/24`) in a single run, or load them from a file.
- **Parallel scanning** — ports are probed concurrently and hosts are
  scanned in parallel, making large scans dramatically faster.
- **Two scan back-ends**:
  - `connect` — portable TCP connect scan, no privileges required (default).
  - `syn` — half-open SYN scan via Scapy (faster, requires root).
- **Reliable SSH validation** — reads the SSH identification banner
  (RFC 4253) by default, with optional full Paramiko handshake validation.
- **SSH security audit (`--audit`)** — turns discovery into attack-surface
  intelligence for pentesters: enumerates accepted authentication methods
  (flagging password auth), lists offered KEX/cipher/MAC/host-key algorithms
  and flags weak/deprecated ones, detects **Terrapin (CVE-2023-48795)**, and
  **correlates shared host keys** across targets to reveal cloned or
  load-balanced infrastructure.
- **Zero required dependencies** — the default connect scan and banner
  validation run on the Python standard library alone.
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

# Optional extras (paramiko for deep validation, scapy for SYN scans):
pip install -r requirements.txt
```

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
| `-t, --timeout SECONDS` | Per-connection timeout (default: `2.0`). |
| `-w, --workers N` | Concurrent probes per host (default: `200`). |
| `--host-concurrency N` | Hosts scanned in parallel (default: `16`). |
| `-r, --retries N` | Retries for timed-out probes (default: `0`). |
| `--json` | Emit results as JSON. |
| `-o, --output FILE` | Write results to a file instead of stdout. |
| `--no-progress` | Disable the live progress indicator. |
| `-v` | Verbose (debug) logging. |
| `-q, --quiet` | Suppress progress and informational logging. |

> **Note on slow scans.** Scanning the full `1-65535` range against a
> firewalled or unreachable host is inherently slow: every filtered port must
> wait out the timeout. The progress indicator shows it is still working, and
> Ctrl+C stops it promptly. To go faster, narrow the ports (e.g.
> `-p 22,2222`), lower the timeout (`-t 1`), or raise concurrency (`-w`).

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

```bash
pip install -r requirements-dev.txt
pytest
```

## Legal

Only scan systems you own or are explicitly authorized to test. Unauthorized
scanning may be illegal in your jurisdiction.
