# sshfinder

[![CI](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml/badge.svg)](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-2.11.0-blue)

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
- **Post-quantum readiness (`--pq-report`)** — one number for the estate: how
  many SSH services still cannot negotiate post-quantum key exchange, and
  exactly which ones. OpenSSH 10.0 made `mlkem768x25519-sha256` the default
  and 10.1 warns that classical sessions are open to *store now, decrypt
  later* capture. Reads only the KEXINIT, so it needs no third-party library.
  It also separates services offering **pre-standard** hybrids (the withdrawn
  `sntrup4591761`, Kyber drafts) — these look post-quantum in an algorithm
  dump but negotiate classical crypto with every current client.
- **Curated algorithm judgements** — every flagged key exchange, cipher, MAC
  and host key comes from an explicit table with a severity (`critical` or
  `weak`) and a stated reason, not a chain of substring tests. Names are
  normalised first, so a vendor suffix cannot slip an algorithm past a check
  — `rijndael-cbc@lysator.liu.se` is CBC no matter who ships it. Negotiation
  markers such as `kex-strict-s-v00@openssh.com` are never assessed as
  algorithms. This table is what the policy gate and the baseline comparison
  ultimately rest on.
- **Policy gate (`--policy`)** — check every SSH service against a baseline
  and **exit non-zero on violation**, so a scan can gate CI or a scheduled
  job. Ships with `baseline`, `strict` and `pq` built in, or takes a JSON
  policy of your own. Rules carry a `fail`/`warn` severity, and `--fail-on`
  decides which one gates. An unrecognised check, field or severity is a
  hard error, never a silently skipped rule — a typo must not turn a failing
  estate green.
- **Baseline comparison (`--baseline`)** — run it nightly against yesterday's
  `--json` report and see only what moved: a **host key that changed** (the
  signal that matters most — expected only after a rebuild or key rotation),
  password login newly enabled, crypto weakened, post-quantum readiness lost,
  services and ports appearing or disappearing. Only hosts present in *both*
  scans are compared, and a field neither scan measured is never reported as
  a change, so scanning one rack does not decommission every other one.
- **Rate limiting (`--max-rate`)** — concurrency bounds how many connections
  are open at once; this bounds how fast new ones start. A scan of production
  has to be able to promise a ceiling on the traffic it generates, which is
  what makes it acceptable to run under rules of engagement at all.
- **Scan through a jump host (`--socks`)** — reach a segmented network via a
  SOCKS5 proxy, with optional credentials. Discovery, the banner exchange and
  the audit all go through it, so results are never half-pivoted. A proxy
  that is unreachable is reported as a scan error, never as "no SSH found".
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
- **Machine-readable output** — `--format text|json|sarif|csv`, optionally
  written to a file. **SARIF 2.1.0** for security tooling (validated against
  the OASIS schema; findings are anchored to `host:port` logical locations and
  carry stable fingerprints so a consumer tracks the same finding across
  runs). **CSV** for a spreadsheet: one row per confirmed SSH service, which
  is the shape an asset inventory actually gets filtered and sorted in.

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
| `--audit` | Audit each SSH service (algorithms, host key, auth methods, Terrapin, post-quantum readiness, shared-key correlation). |
| `--pq-report` | Report post-quantum key exchange readiness across the estate. Reads only the KEXINIT — no third-party library needed. |
| `--policy NAME_OR_PATH` | Check each SSH service against a policy (`baseline`, `strict`, `pq`, or a JSON file) and exit `3` on violation. |
| `--fail-on {fail,warn,never}` | Which policy severity gates the exit code (default: `fail`). |
| `--baseline FILE` | Compare against a previous `--json` report and list what changed. |
| `--fail-on-drift` | Exit `4` when the comparison raises an alert. Services appearing or disappearing do not gate. |

| `-t, --timeout SECONDS` | Longest a probe may wait (default: `2.0`). |
| `--min-timeout SECONDS` | Floor for the adaptive probe timeout (default: `0.1`). |
| `--no-adaptive-timeout` | Wait the full `--timeout` on every probe instead of adapting to the measured round-trip time. |
| `-w, --workers N` | Connections in flight per host (default: `512`). |
| `--max-sockets N` | Ceiling on probe sockets open at once across the whole scan (default: derived from the file-descriptor limit). |
| `--max-rate N` | Cap probes per second across the whole scan (default: no cap). |
| `--socks [user:pass@]host:port` | Reach every target through a SOCKS5 proxy. |
| `--host-concurrency N` | Hosts scanned in parallel (default: `16`). |
| `-r, --retries N` | Retries for timed-out probes (default: `0`). |
| `--max-targets N` | Refuse target lists larger than this (default: `65536`). |
| `--no-early-exit` | Sweep every port even on hosts that answer nothing at all. |
| `--format {text,json,sarif,csv}` | Output format (default: `text`). |
| `--json` | Shorthand for `--format json`. |
| `--stream` | Emit newline-delimited JSON events on stdout as results are found. |
| `-o, --output FILE` | Write results to a file instead of stdout. |
| `--no-progress` | Disable the live progress indicator. |
| `-v` | Verbose (debug) logging. |
| `-q, --quiet` | Suppress progress and informational logging. |

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Success. Nothing found is still success — an empty estate is not an error. |
| `1` | Hard error: every target failed to scan, or the output file could not be written. |
| `2` | Bad invocation (unknown flag, invalid port spec, malformed policy). |
| `3` | Policy violation at or above `--fail-on`. Only ever returned with `--policy`. |
| `4` | Baseline drift alert. Only ever returned with `--baseline --fail-on-drift`. |
| `130` | Interrupted with Ctrl+C. |

A hard error outranks a policy verdict, and a policy verdict outranks drift:
if nothing was reachable, the scan proved nothing about compliance either way,
so you get `1` rather than a misleading pass or fail; and failing a stated bar
is a more specific finding than "something changed".

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

Check post-quantum readiness across an estate (no dependencies required):

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --pq-report
```

```
Post-quantum readiness:
  1/3 service(s) negotiate post-quantum key exchange with a current client
  [!] no PQ key exchange offered (1):
        10.0.0.2:22
  [!] pre-standard PQ only (1) - looks post-quantum but is not:
        10.0.0.3:22
  2 service(s) exposed to store-now-decrypt-later capture; upgrade to OpenSSH 9.0+ (10.0+ preferred)
```

Gate a CI job or a scheduled scan on a baseline — exits `3` if any service
violates it:

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --policy baseline
```

```
Policy 'baseline':
  No password login, no Terrapin exposure, no weak algorithms.
  1/3 service(s) pass
  [FAIL] 1 service(s):
        10.0.0.3:22
          - password_auth: password login accepted: publickey, password
          - terrapin: vulnerable to Terrapin (CVE-2023-48795)
          - post_quantum (warn): post-quantum readiness is absent, ready required
  [warn] 1 service(s):
        10.0.0.2:22
          - post_quantum (warn): post-quantum readiness is absent, ready required
```

Write your own policy as JSON:

```json
{
  "name": "house-rules",
  "description": "What we expect of every SSH service.",
  "rules": [
    {"check": "password_auth", "severity": "fail"},
    {"check": "terrapin", "severity": "fail"},
    {"check": "post_quantum", "require": "ready", "severity": "warn"},
    {"check": "forbid", "field": "ciphers",
     "algorithms": ["3des-cbc", "arcfour"], "severity": "fail"},
    {"check": "require", "field": "kex_algorithms",
     "algorithms": ["curve25519-sha256"], "severity": "fail"}
  ]
}
```

Available checks: `password_auth`, `terrapin`, `weak_algorithms`,
`post_quantum` (with `require`: `ready`, `legacy`, `absent`), and
`forbid` / `require` over a `field` of `kex_algorithms`,
`host_key_algorithms`, `ciphers` or `macs`. Anything else is rejected when
the policy loads.

Export the SSH inventory to a spreadsheet, one row per service:

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --audit --format csv -o ssh.csv
```

Emit SARIF 2.1.0 for security tooling:

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --policy baseline --format sarif \
    -o sshfinder.sarif
```

Each finding is anchored to a `host:port` **logical location** — the part of
SARIF meant for results that are not tied to a source file — and carries a
stable `partialFingerprints` entry so a consumer tracks the same finding
across runs rather than opening a fresh alert every night. When `--policy` is
given the policy violations *are* the findings; without one, the intrinsic
audit findings are reported instead. Either way each finding appears once.

> **On GitHub code scanning.** SARIF results must carry a non-empty artifact
> location or `upload-sarif` rejects the file, so a synthetic
> `ssh://host:port` URI is emitted alongside the logical location. It does not
> resolve to a file in your repository, so alerts appear without a code
> anchor. Treat this output as SARIF for security tooling generally — the
> VS Code SARIF viewer, Azure DevOps, archival — rather than as a way to get
> network findings annotated onto a diff.

Track an estate over time — capture a report, then compare against it:

```bash
# Nightly, in cron:
python sshfinder.py 10.0.0.0/24 -p 22,2222 --audit --json -o today.json
python sshfinder.py 10.0.0.0/24 -p 22,2222 --baseline yesterday.json \
    --fail-on-drift
```

```
Baseline drift (vs yesterday.json):
  [alert] 2 change(s):
        10.0.0.5:22  SHA256:T/ZM4jO... -> SHA256:9aKm2Qx...; expected only after a rebuild or key rotation
        10.0.0.3:22  password login is now accepted
  [added] 1 change(s):
        10.0.0.9:2222  new SSH service (SSH-2.0-OpenSSH_9.6)
  [improved] 1 change(s):
        10.0.0.7:22  post-quantum readiness rose from absent to ready
```

The comparison matches the baseline's depth automatically: a baseline holding
host key fingerprints makes this scan run the deep probe too, so a shallow
rescan never reads as every key having vanished.

Example audit output:

```
=== 10.0.0.5 ===
  open: 10.0.0.5:22
  SSH  10.0.0.5:22  (SSH-2.0-OpenSSH_7.4)
       host key: ssh-ed25519 SHA256:T/ZM4jOL4amTsO5K3AaCdg2...
       auth: publickey, password  [!] password auth enabled
       [!] Terrapin (CVE-2023-48795): VULNERABLE
       [!] weak ciphers: aes128-cbc
           aes128-cbc [weak]: CBC mode is vulnerable to the SSH plaintext-recovery attack (CVE-2008-5161) and, with Encrypt-then-MAC, to Terrapin

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
