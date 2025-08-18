# sshfinder

sshfinder is a fast and efficient tool for scanning open SSH ports on a target system.

## Features

- **Fast Port Scanning**: Utilizes Scapy for efficient SYN scans.
- **SSH Service Validation**: Confirms SSH services using Paramiko.
- **Custom Port Ranges**: Allows scanning of specific port ranges.
- **User-Friendly Output**: Provides clear and concise results.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/ahmad-kabiri/sshfinder.git

2. **Clone the Repository**

   ```bash
   pip install -r requirements.txt
   

## Usage

   ```bash
   python sshfinder.py target_address [options]
   ```

## Options

   ```bash
   -p, --ports: Specify a custom port range to scan. The format should be start-end (e.g., 22-1024). The default value is 1-65535.
   ```

## Examples

1. **Scan Default Port Range**

   This command scans all ports (1-65535) on the target 192.168.1.1:

   ```bash
   python sshfinder.py 192.168.1.1


2. **Scan Default Port Range**

   This command scans ports 22 to 1024 on the target 192.168.1.1:

   ```bash
   python sshfinder.py 192.168.1.1 -p 22-1024


3. **Scan a Remote Host by DNS Name**

   This command scans a remote host (e.g., example.com) using the default port range:

   ```bash
   python sshfinder.py example.com

## Requirements
   
   Python 3.6 or newer

