# lanmap

A live LAN scanner with a terminal dashboard. Shows all devices on your network with real-time ping, MAC addresses, and vendor identification.

![Rust](https://img.shields.io/badge/Rust-stable-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)

## Features

- Auto-detects your local subnet (`/24`)
- Parallel ICMP ping sweep — all 254 hosts concurrently
- Finds hosts that block ping but answer ARP (e.g. Windows firewalls)
- MAC address lookup via ARP cache (Windows and Linux)
- Vendor identification from OUI (Apple, Samsung, ASUS, TP-Link, and more)
- Detects MAC randomization (iOS / Android privacy MACs)
- Reverse DNS hostname resolution
- "★ new" badge for devices that join while lanmap is running
- Offline hosts show when they were last seen
- Live ratatui TUI with animated scanning indicator
- Auto-rescan every 30 seconds

## Usage

> **Requires Administrator / root** for raw ICMP sockets.

```
lanmap
```

Override subnet manually (useful when on VPN; `/16` is the maximum sweep size):

```
lanmap --subnet 192.168.1.0/24
```

### Keybindings

| Key | Action |
|-----|--------|
| `r` | Force rescan |
| `↑ / k` | Navigate up |
| `↓ / j` | Navigate down |
| `q / Esc` | Quit |

## Build

```bash
cargo build --release
./target/release/lanmap
```

## Stack

- [`surge-ping`](https://crates.io/crates/surge-ping) — async ICMP
- [`ratatui`](https://crates.io/crates/ratatui) + [`crossterm`](https://crates.io/crates/crossterm) — TUI
- [`network-interface`](https://crates.io/crates/network-interface) — interface detection
- [`dns-lookup`](https://crates.io/crates/dns-lookup) — reverse DNS
- [`tokio`](https://crates.io/crates/tokio) — async runtime
