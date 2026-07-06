# Changelog

## [0.3.0]

### Added
- **JSON export** (`e`) — writes the current scan to `lanmap-<unixtime>.json`
  in the working directory, with a confirmation on the status line
- **Sort cycling** (`s`) — order the table by IP, latency, hostname, or last
  seen; unreachable/nameless hosts sort last, IP is the stable tiebreaker
- **Online-only filter** (`f`) — hide offline hosts; the table title shows
  `shown / total` while filtered
- Header shows the active sort mode and filter state; the selection stays
  clamped to the visible list when filtering/sorting changes it

## [0.2.0]

### Fixed
- Terminal is now restored on every exit path (error or panic) — a crash no
  longer leaves the shell in raw mode with the error message unreadable
- Invalid `--subnet` values error out with a clear message instead of being
  silently ignored (which scanned the auto-detected subnet instead); subnets
  larger than /16 are rejected
- Forcing a subnet no longer shows the network address as the local IP; the
  real local IP is still detected and excluded from the sweep
- ARP table parsing now works on Linux (both `/proc/net/arp` and `arp -a`
  formats) — MAC/vendor columns were always empty there before
- Multicast/broadcast/incomplete ARP entries are rejected by the group bit
  instead of a `ff`-prefix heuristic
- Ping identifiers are derived from the target IP instead of random u16s,
  eliminating reply-routing collisions (~38% chance per /24 sweep) that could
  randomly drop hosts

### Added
- Hosts that block ICMP but answered ARP (e.g. Windows firewalls) are now
  discovered from the ARP cache after each sweep, including hostname lookup.
  Trade-off: a device that just left can linger "online" for a round or two
  until its ARP entry ages out
- "★ new" badge for devices that join the network after the first sweep
- Offline hosts show how long ago they were last seen (`○ 12m ago`)
- Footer shows "rescan queued" after pressing `r` mid-scan
- Sub-millisecond latency precision (`0.4 ms` instead of `0 ms`)
- Unit tests for ARP parsing and OUI vendor lookup

### Changed
- Ping payload is 16 bytes (some devices ignore zero-length echo requests)
- Dropped the `rand` dependency

## [0.1.0] — MVP

- Auto-detect local /24 subnet from system IP
- Parallel ICMP ping sweep (all 254 hosts concurrently)
- Reverse DNS hostname lookup for online hosts
- Live ratatui TUI: header, hosts table, footer
- Color-coded online/offline status
- Animated spinner during scan
- Keyboard: q=quit, r=force rescan, ↑↓/jk=navigate
- Auto-rescan every 30 seconds
- Graceful error display if ICMP socket fails (no admin)
