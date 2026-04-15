# lanmap — Architecture

## Overview

lanmap is a live LAN scanner with a terminal dashboard. It runs two concurrent
tasks: a background scanner and a foreground TUI, communicating through a shared
`Arc<Mutex<ScanState>>`.

## Structure

```
src/
  main.rs      — entry point, spawns scanner task, starts UI
  scanner.rs   — subnet detection, ICMP ping, DNS lookup, shared state
  ui.rs        — ratatui TUI, event loop, rendering
DOCS/
  ARCHITECTURE.md
  CHANGELOG.md
```

## Data flow

```
tokio::spawn(run_scanner)
  └─ detect_subnet()           local IP → /24 network
  └─ JoinSet<probe_host>       254 concurrent ICMP pings
       └─ ping_once()          surge-ping ICMP
       └─ lookup_addr()        reverse DNS (spawn_blocking)
  └─ state.lock() → update     write results into ScanState
  └─ sleep 30s / rescan flag

ui::run() [main thread]
  └─ terminal.draw()           render from locked ScanState snapshot
  └─ event::poll()             keyboard input → mutate state or break
```

## State machine

`ScanState` is the single source of truth:
- `scanning` + `scan_progress/total` → header status bar
- `hosts: Vec<HostInfo>` → table rows (sorted by IP)
- `rescan_requested` → scanner loop checks this to skip the 30s wait
- `error` → shown fullscreen if the ICMP socket fails (needs admin)

## Adding features later

- **Alerts (new device):** compare `hosts` snapshot before/after each scan
- **Export:** serialize `hosts` to JSON on keypress
- **Port scan:** add `open_ports: Vec<u16>` to `HostInfo`, scan in `probe_host`
- **Bandwidth / connrs integration:** feed PIDs from connrs into a second panel
