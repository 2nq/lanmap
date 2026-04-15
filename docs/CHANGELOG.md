# Changelog

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
