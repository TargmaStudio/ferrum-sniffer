# ferrum-sniff 🦀

A low-level network packet analyzer built in Rust. Captures and analyzes live network traffic at the Ethernet, IP, TCP, and UDP layers.

## What it does

- Captures live packets off your NIC in promiscuous mode
- Parses Ethernet, IPv4, TCP, and UDP headers by hand
- Detects suspicious TCP flag combinations and port scans
- Persists packet metadata to SQLite with automatic retention
- Supports BPF filters for targeted capture

## Why Rust

Memory safety matters when parsing untrusted network data. A malformed packet cannot exploit ferrum-sniff — the parser either succeeds or returns `None`. No buffer overflows, no undefined behavior.

## Usage

```bash
# list available interfaces
sudo ./ferrum-sniff --list

# capture 20 packets on default interface
sudo ./ferrum-sniff -c 20

# capture only HTTPS traffic
sudo ./ferrum-sniff -i en0 --filter "tcp and port 443"

# capture only DNS
sudo ./ferrum-sniff -i en0 --filter "udp and port 53"

# watch a specific IP
sudo ./ferrum-sniff -i en0 --filter "host 160.79.104.10"

# unlimited capture
sudo ./ferrum-sniff -i en0 -c 0
```

## Requirements

- libpcap (`brew install libpcap` on macOS)
- Rust 1.75+
- Run with `sudo` for raw packet access

## Architecture