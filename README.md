# sshfinder

[![CI](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml/badge.svg)](https://github.com/kabiri-labs/sshfinder/actions/workflows/ci.yml)
![version](https://img.shields.io/badge/version-2.11.0-blue)

**Find every SSH service on your network, judge whether it meets your
standard, and get told when that changes.**

`sshfinder` is a single Python file with no required dependencies. Point it at
a CIDR range and it discovers SSH wherever it is actually listening — not just
port 22 — confirms each one really speaks SSH, assesses its cryptographic
posture, and returns a non-zero exit code when something fails your policy.

---

## The problem it solves

Most teams cannot answer three questions about their own SSH estate:

1. **How many SSH services do we have, and where?** Not how many machines —
   how many *listening SSH services*, including the one on port 2222 that a
   contractor set up in 2019.
2. **Do they all meet our standard?** Password login disabled, no broken
   ciphers, not exposed to Terrapin. Provably, not by assertion.
3. **What changed since last night?** A host key that moved. A service that
   appeared. Password authentication that came back on after a rebuild.

The existing tools each answer part of this and stop:

| Tool | Discovers SSH | Assesses it | Across a fleet |
| --- | --- | --- | --- |
| `nmap` | yes | shallow, via NSE scripts | yes |
| `ssh-audit` | **no** — you give it one host | deeply | no |
| `masscan` / `zmap` | at internet scale | **no** | yes |
| **`sshfinder`** | yes | yes | yes |

That gap — discovery *and* assessment *and* a verdict, in one artifact — is
what this tool exists to fill. If you only need to audit one host you already
know about, use [`ssh-audit`](https://github.com/jtesta/ssh-audit); it goes
deeper on a single service than this does.

## Who it is for

- **Internal security and asset inventory.** Build and maintain a record of
  every SSH service in the estate, exported to CSV or JSON.
- **Platform and SRE teams with a compliance obligation.** Prove, on a
  schedule and with an exit code, that no host in a VPC accepts password
  login or offers weak crypto.
- **Anyone running a post-quantum migration.** One number for how much of the
  fleet still cannot negotiate post-quantum key exchange, and exactly which
  services those are.

Penetration testers will find the audit and the SOCKS pivot useful, but the
tool is shaped around running the same scan repeatedly against an estate you
own, not around a one-off engagement.

---

## Quick start

```bash
git clone https://github.com/kabiri-labs/sshfinder.git
cd sshfinder
python sshfinder.py 10.0.0.0/24 -p 22,2222
```

No installation, no dependencies. Requires **Python 3.9+**.

The three things it does, in three commands:

```bash
# 1. INVENTORY — what SSH is out there?
python sshfinder.py 10.0.0.0/24 --audit --format csv -o ssh-inventory.csv

# 2. VERDICT — does it meet our standard? (exits 3 if not)
python sshfinder.py 10.0.0.0/24 -p 22,2222 --policy baseline

# 3. DRIFT — what changed since last night?
python sshfinder.py 10.0.0.0/24 -p 22,2222 --baseline yesterday.json \
    --fail-on-drift
```

---

## 1. Inventory

Scanning all 65535 ports is the default, because an SSH service on a
non-standard port is precisely the one nobody has written down. Every open
port is labelled, so an open port is never silently counted as an SSH one:

```
=== 10.0.0.5 ===
  open: 10.0.0.5:22 [SSH], 10.0.0.5:8080 [not ssh]
  SSH  10.0.0.5:22  (SSH-2.0-OpenSSH_7.4)
```

Confirmation is a real RFC 4253 identification exchange, not a glance at the
first bytes on the wire. Servers that print a legal banner first, that wait
for the client to identify itself, or whose banner arrives split across TCP
segments are all recognised correctly — each of those is a false negative in
a naive implementation.

Add `--audit` for the full picture of each service:

```
  SSH  10.0.0.5:22  (SSH-2.0-OpenSSH_7.4)
       host key: ssh-ed25519 SHA256:T/ZM4jOL4amTsO5K3AaCdg2...
       auth: publickey, password  [!] password auth enabled
       [!] Terrapin (CVE-2023-48795): VULNERABLE
       [!] weak ciphers: aes128-cbc
           aes128-cbc [weak]: CBC mode is vulnerable to the SSH plaintext-recovery attack (CVE-2008-5161) and, …

Shared SSH host keys (possible shared/cloned hosts):
  SHA256:T/ZM4jOL4amTsO5K3AaCdg2...
    -> 10.0.0.5:22, 10.0.0.9:22
```

That last block is worth knowing about: a host key reused across machines
usually means cloned VMs or a shared image, and it means compromising one
host compromises the identity of all of them.

### Post-quantum readiness

OpenSSH 10.0 made `mlkem768x25519-sha256` the default key exchange, and 10.1
warns that classical sessions are open to *store now, decrypt later* capture.
`--pq-report` answers the fleet-level question directly, using only the
KEXINIT — so it needs no third-party library:

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
  2 service(s) exposed to store-now-decrypt-later capture; upgrade to OpenSSH 9.0+
```

The `pre-standard` category is the one that catches people out. A server
advertising `sntrup4591761x25519-sha512@tinyssh.org` or a Kyber draft looks
post-quantum in an algorithm dump, but OpenSSH dropped that withdrawn
parameter set in 2020 — so a current client finds no common method and falls
back to classical crypto. Counted as ready, it would be worse than not
looking at all.

## 2. Verdict

A report describes a problem. A policy *asserts* one, and can fail a build:

```bash
python sshfinder.py 10.0.0.0/24 -p 22,2222 --policy baseline; echo "exit $?"
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
exit 3
```

Three policies ship built in — `baseline`, `strict` and `pq` — named for the
outcome they enforce rather than for a distribution. Rules carry a `fail` or
`warn` severity and `--fail-on` decides which gates, so a team can adopt a
stricter bar as a warning first and promote it later without editing anything.

Write your own as JSON:

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

Checks: `password_auth`, `terrapin`, `weak_algorithms`, `post_quantum` (with
`require`: `ready`, `legacy` or `absent`), and `forbid` / `require` over a
`field` of `kex_algorithms`, `host_key_algorithms`, `ciphers` or `macs`.

**Anything else is a hard error when the policy loads, before the scan
starts.** A gate that silently skips a rule it does not understand is worse
than no gate: the run goes green and nobody learns the check never executed.

```
$ sshfinder 10.0.0.0/24 --policy house.json
sshfinder: error: rule 1: unknown check 'pasword_auth'
  (known: forbid, password_auth, post_quantum, require, terrapin, weak_algorithms)
```

## 3. Drift

Run it nightly against yesterday's report and see only what moved:

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

**A host key that changed** is the signal that matters most here — expected
only after a rebuild or a key rotation, and worth a look every other time.

Only `alert` gates `--fail-on-drift`. A decommissioned host is ordinary
churn, and failing a nightly job on it would train everyone to ignore the
result.

The comparison is careful not to invent changes. A field neither scan
measured is never reported as having changed, only hosts present in *both*
scans are compared, and a baseline holding host key fingerprints makes this
scan run the deep probe too — so a shallow rescan never reads as every key
having vanished.

---

## Output formats

`--format text|json|sarif|csv`, optionally written to a file with `-o`.

- **`csv`** — one row per confirmed SSH service. The shape an asset
  inventory actually gets sorted and filtered in.
- **`json`** — the native report, and the input format for `--baseline`.
- **`sarif`** — SARIF 2.1.0, validated against the OASIS schema. Findings are
  anchored to `host:port` logical locations and carry stable fingerprints, so
  a consumer tracks the same finding across nightly runs rather than opening
  a fresh alert each time.
- **`--stream`** — newline-delimited JSON events flushed as each port opens
  and each service is confirmed, so a pipeline can act on the first result
  while the scan is still running:

```bash
python sshfinder.py 10.0.0.0/24 --stream -q | jq -c 'select(.event=="ssh")'
```

```
{"event":"ssh","elapsed":0.164,"host":"10.0.0.5","port":22,"banner":"SSH-2.0-OpenSSH_9.6"}
{"event":"ssh","elapsed":0.881,"host":"10.0.0.9","port":2222,"banner":"SSH-2.0-dropbear"}
```

> **On SARIF and GitHub code scanning.** SARIF results must carry a non-empty
> artifact location or `upload-sarif` rejects the file, so a synthetic
> `ssh://host:port` URI is emitted alongside the logical location. It does not
> resolve to a file in your repository, so alerts appear without a code
> anchor. Treat this as SARIF for security tooling generally — the VS Code
> SARIF viewer, Azure DevOps, archival — not as a way to annotate a diff.

## Exit codes

The whole point of the policy and drift features, so they are worth stating
precisely:

| Code | Meaning |
| ---- | ------- |
| `0` | Success. Nothing found is still success — an empty estate is not an error. |
| `1` | Hard error: every target failed to scan, or the output file could not be written. |
| `2` | Bad invocation (unknown flag, invalid port spec, malformed policy or proxy). |
| `3` | Policy violation at or above `--fail-on`. Only with `--policy`. |
| `4` | Baseline drift alert. Only with `--baseline --fail-on-drift`. |
| `130` | Interrupted with Ctrl+C. |

A hard error outranks a policy verdict, and a policy verdict outranks drift.
If nothing was reachable, the scan proved nothing about compliance either
way, so you get `1` rather than a misleading pass or fail; and failing a
stated bar is a more specific finding than "something changed".

---

## Installation

The core scan, banner validation and the dependency-free parts of `--audit`
(algorithm inventory, weak-crypto flags, Terrapin, post-quantum readiness)
need nothing but Python 3.9+.

```bash
# Recommended: unlocks host key fingerprints, auth-method enumeration and
# shared-key correlation in --audit, plus --validate paramiko.
pip install -r requirements.txt

# Optional, only for half-open SYN scans (needs root):
pip install scapy>=2.5
```

## Options

| Option | Description |
| ------ | ----------- |
| `targets` | One or more IPs, hostnames, or CIDR networks. |
| `-iL, --target-file FILE` | Read targets from a file (one per line, `#` comments allowed). |
| `-p, --ports SPEC` | Ports to scan, e.g. `22,80,1000-2000` (default: `1-65535`). |
| `--audit` | Audit each SSH service: algorithms, host key, auth methods, Terrapin, post-quantum readiness, shared-key correlation. |
| `--pq-report` | Report post-quantum readiness across the estate. Needs no third-party library. |
| `--policy NAME_OR_PATH` | Check each service against `baseline`, `strict`, `pq`, or a JSON policy file. Exits `3` on violation. |
| `--fail-on {fail,warn,never}` | Which policy severity gates the exit code (default: `fail`). |
| `--baseline FILE` | Compare against a previous `--json` report and list what changed. |
| `--fail-on-drift` | Exit `4` when the comparison raises an alert. |
| `--format {text,json,sarif,csv}` | Output format (default: `text`). |
| `--json` | Shorthand for `--format json`. |
| `--stream` | Emit newline-delimited JSON events as results are found. |
| `-o, --output FILE` | Write results to a file instead of stdout. |
| `--validate {banner,paramiko,none}` | SSH validation strategy (default: `banner`). |
| `--scan-method {auto,connect,syn}` | Scan back-end (default: `auto`). |
| `--socks [user:pass@]host:port` | Reach every target through a SOCKS5 proxy. |
| `--max-rate N` | Cap probes per second across the whole scan (default: no cap). |
| `-t, --timeout SECONDS` | Longest a probe may wait (default: `2.0`). |
| `--min-timeout SECONDS` | Floor for the adaptive probe timeout (default: `0.1`). |
| `--no-adaptive-timeout` | Wait the full `--timeout` on every probe. |
| `-w, --workers N` | Connections in flight per host (default: `512`). |
| `--max-sockets N` | Ceiling on probe sockets open at once (default: from the file-descriptor limit). |
| `--host-concurrency N` | Hosts scanned in parallel (default: `16`). |
| `-r, --retries N` | Retries for timed-out probes (default: `0`). |
| `--max-targets N` | Refuse target lists larger than this (default: `65536`). |
| `--no-early-exit` | Sweep every port even on hosts that answer nothing at all. |
| `--no-progress` | Disable the live progress indicator. |
| `-v, --verbose` | Verbose logging (`-vv` also un-silences Paramiko). |
| `-q, --quiet` | Suppress progress and informational logging. |
| `--version` | Print the version and exit. |

`--scan-method auto` selects the SYN scan when running as root with Scapy
installed, and otherwise falls back to the privilege-free connect scan.
SOCKS cannot be combined with a SYN scan — SOCKS5 carries TCP streams, not
raw packets.

### Scanning through a jump host

```bash
python sshfinder.py 10.0.0.0/24 -p 22 --socks user:pass@bastion.example:1080
```

Discovery, the banner exchange and the audit all traverse the pivot, so
results are never half-tunnelled. A proxy that is unreachable is reported as
a scan error, never as "no SSH found".

### Scanning production safely

`--max-rate` caps probes per second across the whole scan. Concurrency
bounds how many connections are open at once; this bounds how fast new ones
start, which is the ceiling you need to be able to promise before scanning
anything under rules of engagement.

---

## How it works

Implementation notes, for when the behaviour above needs explaining.

**The scan engine.** Every connection in flight is driven from one thread by
an OS event loop (`epoll`/`kqueue`/`select`), so concurrency costs a file
descriptor rather than an OS thread, and each host is resolved once rather
than once per port. A full 1–65535 sweep runs about 6× faster than a
thread-pool design.

**SSH ports first.** The handful of ports SSH actually lives on (22, 2222,
22222, …) are probed at the head of every sweep. On a full sweep, the first
confirmed SSH service appears in about 0.2 seconds instead of 16.

**One handshake per service.** The socket that discovered an open port is
handed straight to the banner exchange, so a confirmed SSH service costs one
TCP handshake rather than two.

**Adaptive timeout.** Probes wait as long as the path warrants, using the
smoothed round-trip estimator from RFC 6298 — the one TCP itself uses — fed
by every answered probe and shared across the scan. `--timeout` becomes a
ceiling rather than a fixed cost: on a live-but-mostly-filtered host that is
worth about 5× with identical findings. Only a definite answer teaches it
anything; a timeout says nothing about the path and is never fed back in.

Two places deliberately keep the full ceiling. The banner exchange and the
audit never adapt, because how fast a host completes a TCP handshake says
nothing about how fast its SSH daemon composes a greeting. Neither does the
final re-probe of SSH's usual ports, since a dropped SYN there is the one
loss that actually costs this tool a finding.

**Early exit.** A host that answers nothing at all across its first few
hundred probes is reported as unresponsive rather than consuming one timeout
per remaining port. Because SSH's ports are swept first, a live service is
always seen before this can trip; `--no-early-exit` forces the full range.

**Bounded by design.** A process-wide socket budget derived from the
file-descriptor limit stops a large scan from exhausting descriptors and
misreporting live services as filtered. Target expansion checks a network's
size before materialising it, so a stray `/8` is refused in milliseconds
rather than consuming a gigabyte of memory.

**Curated algorithm judgements.** Every flagged algorithm comes from an
explicit table with a severity and a stated reason, not a chain of substring
tests. Names are normalised first, so a vendor suffix cannot slip one past a
check — `rijndael-cbc@lysator.liu.se` is CBC no matter who ships it — and
negotiation markers like `kex-strict-s-v00@openssh.com` are never assessed as
algorithms. This table is what the policy gate and the drift comparison
ultimately rest on.

**Robust Ctrl+C.** Honoured even on Windows, where an unbounded thread wait
normally swallows it: the first press stops gracefully and returns partial
results, a second forces an immediate exit.

---

## What it deliberately does not do

- **Infer CVEs from banner versions.** Distributions backport fixes without
  touching the version string, so `OpenSSH_9.6p1` on Ubuntu 24.04 is patched
  against most of what public databases attribute to 9.6p1. That is a
  false-positive machine — it is why `ssh-audit` removed its own version-based
  CVE detection, and why Tenable ships a plugin whose whole job is detecting
  the backporting that breaks it. Only what a server actually advertises is
  assessed.
- **Brute-force credentials.** Different tool, different purpose, different
  legal posture.
- **Compete with `nmap` on general port scanning**, or with `masscan` and
  `zmap` at internet scale. Those problems are solved.

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
