# lanmap — Architecture

## Overview

lanmap is a live LAN scanner with a terminal dashboard. It runs two concurrent
tasks: a background scanner and a foreground TUI, communicating through a shared
`Arc<Mutex<ScanState>>`.

## Structure

```
src/
  main.rs      — entry point, --subnet validation, spawns scanner task, starts UI
  scanner.rs   — subnet detection, ICMP ping, ARP harvest, DNS lookup, shared state
  ui.rs        — ratatui TUI, event loop, rendering, terminal restore/panic hook
docs/
  ARCHITECTURE.md
  CHANGELOG.md
```

## Data flow

```
tokio::spawn(run_scanner)
  └─ detect_subnet()           local IP → /24 network (or forced --subnet)
  └─ JoinSet<probe_host>       254 concurrent ICMP pings
       └─ ping_once()          surge-ping ICMP (identifier = low 16 bits of IP)
       └─ lookup_addr()        reverse DNS (spawn_blocking)
  └─ state.lock() → update     write results into ScanState
  └─ fetch_arp_table()         harvest ARP cache the sweep populated:
       └─ merge MAC/vendor     into known hosts
       └─ add silent hosts     ICMP-blocking devices that answered ARP
  └─ sleep 30s / rescan flag

ui::run() [main thread]
  └─ panic hook + restore      terminal always restored on error/panic
  └─ visible_hosts()           filter + sort a view over ScanState.hosts
  └─ terminal.draw()           render header / table / footer from the view
  └─ event::poll()             keyboard → mutate state, sort, filter, export
```

The UI never mutates `hosts`; sorting and the online-only filter are a
render-time view (`visible_hosts`) so the scanner stays the single writer.
Export (`scanner::export_json`) serializes a snapshot to JSON on keypress.

## State machine

`ScanState` is the single source of truth:
- `scanning` + `scan_progress/total` → header status bar
- `hosts: Vec<HostInfo>` → table rows (sorted by IP)
- `rescan_requested` → scanner loop checks this to skip the 30s wait
- `error` → shown fullscreen if the ICMP socket fails (needs admin)

## Adding features later

- **Alerts (new device):** `HostInfo.is_new` already flags these (UI badge);
  hook a notification into the ARP-merge step in `run_scanner`
- **Export:** done — `e` writes JSON via `scanner::export_json`. CSV would be
  a second serializer over the same snapshot
- **Port scan:** add `open_ports: Vec<u16>` to `HostInfo`, scan in `probe_host`
- **Bandwidth / connrs integration:** feed PIDs from connrs into a second panel
