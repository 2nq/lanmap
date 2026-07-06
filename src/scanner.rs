use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dns_lookup::lookup_addr;
use ipnetwork::Ipv4Network;
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};

pub const RESCAN_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_millis(1000);
// Some devices ignore zero-length echo requests; send a small payload like `ping` does.
const PING_PAYLOAD: [u8; 16] = *b"lanmap-probe-016";

#[derive(Clone, Debug)]
pub struct HostInfo {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub latency_ms: Option<f64>,
    pub online: bool,
    /// Discovered after the first full sweep, i.e. it joined while we were watching.
    pub is_new: bool,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

#[derive(Default)]
pub struct ScanState {
    pub hosts: Vec<HostInfo>,
    pub subnet: Option<Ipv4Network>,
    pub local_ip: Option<Ipv4Addr>,
    pub scanning: bool,
    pub scan_progress: usize,
    pub scan_total: usize,
    pub last_scan: Option<Instant>,
    pub error: Option<String>,
    pub rescan_requested: bool,
    pub first_scan_done: bool,
}

// ---------------------------------------------------------------------------
// OUI vendor lookup — first 3 octets of MAC → vendor name
// ---------------------------------------------------------------------------

fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let parts: Vec<&str> = mac.splitn(6, [':', '-']).collect();
    if parts.len() < 3 {
        return None;
    }

    // Locally administered bit (bit 1 of first octet) → MAC randomization
    if let Ok(first) = u8::from_str_radix(parts[0], 16) {
        if first & 0x02 != 0 {
            return Some("Randomized");
        }
    }

    let oui = format!(
        "{}:{}:{}",
        parts[0].to_lowercase(),
        parts[1].to_lowercase(),
        parts[2].to_lowercase()
    );
    match oui.as_str() {
        // Apple
        "00:03:93"|"00:0a:27"|"00:0a:95"|"00:16:cb"|"00:17:f2"|"00:1b:63"|
        "00:1c:b3"|"00:23:12"|"00:23:32"|"00:26:bb"|"28:cf:da"|"34:15:9e"|
        "3c:15:c2"|"40:30:04"|"48:60:bc"|"54:72:4f"|"58:1f:aa"|"60:f8:1d"|
        "64:20:0c"|"68:5b:35"|"6c:ab:31"|"70:3e:ac"|"78:31:c1"|"7c:fa:df"|
        "80:92:9f"|"84:b1:53"|"88:53:2e"|"8c:58:77"|"90:27:e4"|"9c:f3:87"|
        "a4:5e:60"|"a8:51:ab"|"ac:bc:32"|"ac:de:48"|"b0:70:2d"|"b4:f0:ab"|
        "b8:53:ac"|"b8:78:2e"|"bc:52:b7"|"c0:ce:cd"|"c8:85:50"|"cc:08:8d"|
        "cc:29:f5"|"d4:61:9d"|"d8:1d:72"|"d8:9e:3f"|"dc:2b:2a"|"dc:86:d8"|
        "e0:66:78"|"e4:25:e7"|"e4:9a:79"|"e8:04:0b"|"ec:35:86"|"f0:b4:79"|
        "f0:cb:a1"|"f0:d1:a9"|"f4:1b:a1"|"f4:37:b7"|"f4:f1:5a"|"f8:1e:df"|
        "f8:27:93"|"fc:25:3f"|"fc:e9:98"|"9c:20:7b"|"a0:d7:95"|"3c:2e:f9"|
        "4c:57:ca"|"50:ea:d6"|"54:26:96"|"5c:59:48"|"60:33:4b"|"64:76:ba"|
        "6c:40:08"|"6c:72:e7"|"70:56:81"|"70:cd:60"|"74:e1:b6"|"78:4f:43"|
        "7c:01:91"|"7c:6d:62"|"7c:d1:c3"|"80:00:6e"|"80:49:71"|"80:e6:50"|
        "84:38:35"|"84:85:06"|"84:fc:ac"|"88:1f:a1"|"8c:00:6d"|"8c:7b:9d"|
        "8c:fa:ba"|"90:3c:92"|"90:60:f0"|"90:8d:6c"|"98:01:a7"|"98:10:e8"|
        "98:fe:94"|"9c:04:eb"|"9c:35:eb"|"9c:84:bf" => Some("Apple"),

        // Samsung
        "00:15:b9"|"00:17:c9"|"00:21:19"|"08:08:c2"|"08:d4:0c"|"0c:14:20"|
        "18:3f:47"|"20:64:32"|"28:ba:b5"|"34:14:5f"|"38:01:97"|"3c:5a:37"|
        "40:0e:85"|"44:78:3e"|"48:44:f7"|"50:01:bb"|"50:a4:c8"|"54:88:0e"|
        "5c:49:79"|"60:af:6d"|"68:27:37"|"70:f9:27"|"78:40:e4"|"84:25:db"|
        "88:32:9b"|"8c:77:12"|"94:35:0a"|"98:52:b1"|"a0:07:98"|"a4:eb:d3"|
        "ac:5f:3e"|"b4:3a:28"|"bc:b1:f3"|"c4:42:02"|"c8:14:79"|"d0:22:be"|
        "d4:88:90"|"d8:57:ef"|"e4:40:e2"|"e4:58:b8"|"e8:50:8b"|"f0:25:b7"|
        "f4:09:d8"|"00:12:fb"|"00:13:77"|"00:16:32"|"00:16:6b"|"00:17:d5"|
        "00:1a:8a"|"00:1b:98"|"00:1d:25"|"00:1e:7d"|"2c:54:cf"|"30:19:66"|
        "38:2d:e8"|"44:f4:59"|"50:32:75"|"50:85:69"|"50:cc:f8"|"54:9b:12"|
        "58:ef:68"|"64:77:91"|"68:eb:ae"|"70:28:8b"|"74:45:8a"|"78:25:ad"|
        "7c:1c:4e"|"80:65:6d"|"84:38:38"|"8c:71:f8"|"90:18:7c"|"94:63:d1"|
        "9c:3a:af"|"a0:0b:ba"|"a8:7d:12"|"b0:47:bf"|"b0:72:bf"|"b4:79:a7"|
        "bc:20:ba"|"bc:8c:cd"|"c0:97:27"|"c4:57:6e"|"c4:73:1e"|"c8:ba:94"|
        "cc:07:ab"|"d0:59:e4"|"d8:96:95"|"dc:71:96"|"e4:7c:f9"|"e8:11:32"|
        "ec:1f:72"|"ec:9b:f3"|"f8:04:2e"|"f8:d0:bd" => Some("Samsung"),

        // ASUS
        "00:0c:6e"|"00:0e:a6"|"00:11:2f"|"00:1a:92"|"00:1e:8c"|"04:d4:c4"|
        "08:60:6e"|"10:7b:44"|"10:bf:48"|"14:da:e9"|"1c:87:2c"|"24:4b:fe"|
        "2c:56:dc"|"30:5a:3a"|"38:2c:4a"|"3c:97:0e"|"40:16:7e"|"4c:ed:fb"|
        "50:46:5d"|"54:04:a6"|"5c:ff:35"|"60:45:cb"|"6c:f3:7f"|"74:d0:2b"|
        "78:24:af"|"80:1f:02"|"88:d7:f6"|"90:9f:33"|"94:de:80"|"a8:5e:45"|
        "b0:6e:bf"|"d0:17:c2"|"e0:3f:49"|"f0:2f:74"|"f8:32:e4"|"fc:34:97"|
        "00:13:d4"|"00:15:f2"|"00:17:31"|"00:1b:fc"|"00:1f:c6"|"00:22:15"|
        "00:23:54"|"00:24:8c"|"00:25:22"|"04:92:26"|"08:62:66"|"1c:75:08"|
        "20:cf:30"|"2c:4d:54"|"2c:fd:a1"|"48:5b:39"|"6c:62:6d"|"74:03:bd"|
        "bc:ee:7b"|"c8:60:00"|"d8:50:e6"|"e4:3a:6e"|"e8:94:f6"|"e8:9c:25" => Some("ASUS"),

        // Amazon
        "00:bb:3a"|"08:74:02"|"0c:47:c9"|"18:74:2e"|"34:d2:70"|"40:b4:cd"|
        "44:65:0d"|"50:f5:da"|"68:37:e9"|"74:c2:46"|"84:d6:d0"|"88:71:e5"|
        "a0:02:dc"|"b4:7c:9c"|"cc:9e:a2"|"d0:f8:8c"|"f0:a2:25"|"f0:f0:a4"|
        "10:ae:60"|"1c:12:b0"|"20:fe:4b"|"24:df:6a"|"38:f7:3d"|"48:23:35"|
        "4c:ef:c0"|"54:4d:90"|"8c:49:62" => Some("Amazon"),

        // Google
        "00:1a:11"|"08:9e:08"|"1c:f2:9a"|"20:df:b9"|"3c:28:6d"|"48:d6:d5"|
        "54:60:09"|"70:3a:cb"|"94:95:a0"|"a4:77:33"|"f4:f5:d8"|"6c:ad:f8"|
        "7c:2e:bd"|"b0:e0:3b" => Some("Google"),

        // Raspberry Pi
        "28:cd:c1"|"2c:cf:67"|"b8:27:eb"|"d8:3a:dd"|"dc:a6:32"|"e4:5f:01" => Some("Raspberry Pi"),

        // TP-Link
        "00:27:19"|"04:18:d6"|"14:cc:20"|"1c:61:b4"|"20:dc:e6"|"28:28:5d"|
        "2c:27:d7"|"34:60:f9"|"3c:84:6a"|"50:91:e3"|"54:c8:0f"|"60:a4:b7"|
        "6c:5a:b0"|"74:da:38"|"7c:8b:ca"|"84:16:f9"|"90:f6:52"|"94:0c:6d"|
        "a0:f3:c1"|"b0:95:75"|"b4:b0:24"|"c4:6e:1f"|"c8:0e:14"|"d8:07:b6"|
        "e8:de:27"|"ec:08:6b"|"f0:a7:31"|"f4:ec:38"|"f8:1a:67" => Some("TP-Link"),

        // Netgear
        "00:09:5b"|"00:14:6c"|"00:1b:2f"|"00:1e:2a"|"00:1f:33"|"00:24:b2"|
        "08:36:c9"|"0c:3d:c9"|"18:1b:eb"|"1c:af:f7"|"28:c6:8e"|"2c:b0:5d"|
        "38:70:0c"|"4c:60:de"|"6c:b0:ce"|"74:44:01"|"80:37:73"|"84:1b:5e"|
        "9c:d3:6d"|"a0:21:b7"|"b0:7f:b9"|"c8:d7:19"|"d4:7b:35" => Some("Netgear"),

        // Intel (WiFi NICs in laptops/PCs)
        "00:02:b3"|"00:03:47"|"00:0e:0c"|"00:13:02"|"00:15:00"|"00:15:17"|
        "00:16:41"|"00:1b:21"|"00:1d:e0"|"40:25:c2"|"44:85:00"|"48:51:b7"|
        "54:27:1e"|"5c:51:4f"|"7c:76:35"|"a0:88:69"|"a4:c3:f0"|"b4:b6:76"|
        "e4:a7:c5"|"00:1e:64"|"00:1e:65"|"00:1f:3b"|"00:1f:3c"|"00:21:5c"|
        "00:21:5d"|"8c:ec:4b"|"9c:b6:d0" => Some("Intel"),

        // Xiaomi
        "0c:1d:af"|"14:f6:5a"|"18:59:36"|"20:82:c0"|"28:6c:07"|"34:80:b3"|
        "50:64:2b"|"58:44:98"|"64:09:80"|"64:b4:73"|"78:11:dc"|"8c:be:be"|
        "94:fb:b2"|"98:fa:e3"|"a0:86:c6"|"f4:8b:32"|"f8:a4:5f"|"2c:db:07"|
        "34:ce:00"|"4c:49:e3"|"58:a2:b5"|"68:df:dd"|"6c:e8:73"|"74:23:44"|
        "78:02:f8"|"9c:99:a0"|"ac:c1:ee"|"b0:e2:35"|"d4:97:0b"|"e4:46:da" => Some("Xiaomi"),

        // Huawei
        "00:18:82"|"00:25:9e"|"04:02:1f"|"0c:37:dc"|"10:1b:54"|"14:9d:09"|
        "18:c5:8a"|"1c:8e:5c"|"24:4c:07"|"2c:ab:00"|"30:d1:7e"|"34:29:12"|
        "40:4d:8e"|"4c:1f:cc"|"54:51:1b"|"60:de:44"|"70:72:3c"|"80:d0:9b"|
        "84:a9:c4"|"94:04:9c"|"9c:74:1a"|"a0:08:6f"|"ac:e2:15"|"b4:15:13"|
        "c4:ff:1f"|"cc:53:b5"|"d4:6e:5c"|"dc:72:9b"|"e0:19:1d"|"f4:c7:14" => Some("Huawei"),

        // Sony
        "00:01:4a"|"00:04:1f"|"00:0d:4b"|"00:13:a9"|"00:19:4e"|"00:1a:80"|
        "00:1d:0d"|"28:0d:fc"|"30:17:c8"|"3c:01:ef"|"40:b0:fa"|"54:42:49"|
        "70:2d:d4"|"88:c9:e8"|"9c:ad:97"|"a0:e4:53"|"b0:5c:da"|"c4:43:8f"|
        "f8:7b:20"|"d8:d4:3c"|"e0:ae:5e"|"f0:bf:97" => Some("Sony"),

        // LG Electronics
        "00:1e:75"|"00:1f:6b"|"00:24:83"|"00:26:e2"|"04:b1:67"|"10:68:3f"|
        "14:b4:84"|"1c:08:c1"|"1c:99:4c"|"28:3f:69"|"30:1a:a3"|"40:4e:36"|
        "48:59:29"|"4c:bd:8f"|"50:55:27"|"54:fc:f3"|"5c:70:a3"|"60:21:c0"|
        "74:38:b7"|"7c:66:ef"|"88:c9:d0"|"90:e6:ba"|"a8:16:d0"|"ac:af:b9"|
        "bc:f5:ac"|"c8:08:73"|"d0:13:fd"|"d8:13:99"|"e8:88:d3" => Some("LG"),

        // Realtek (common on PC motherboards/NICs)
        "00:01:6c"|"00:e0:4c"|"08:be:ac"|"30:9c:23"|"40:b0:34"|"44:c3:06"|
        "52:54:00"|"6c:4b:90"|"8c:16:45"|"e0:d5:5e" => Some("Realtek"),

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ARP table — IP → MAC mappings from /proc/net/arp (Linux) or `arp -a`
// ---------------------------------------------------------------------------

// Format-agnostic: takes the first IP-looking token and the first MAC-looking
// token from a line. Handles Windows (`192.168.1.1  aa-bb-...  dynamic`),
// Linux/macOS `arp -a` (`? (192.168.1.1) at aa:bb:... [ether] on eth0`) and
// /proc/net/arp rows alike.
fn parse_arp_line(line: &str) -> Option<(Ipv4Addr, String)> {
    let mut ip = None;
    let mut mac = None;
    for tok in line.split_whitespace() {
        let tok = tok.trim_matches(|c| c == '(' || c == ')');
        if ip.is_none() {
            if let Ok(parsed) = tok.parse::<Ipv4Addr>() {
                ip = Some(parsed);
                continue;
            }
        }
        if mac.is_none() && tok.len() == 17 {
            let norm = tok.replace('-', ":").to_lowercase();
            let mut octets = norm.split(':');
            if octets.clone().count() == 6
                && octets.all(|o| o.len() == 2 && o.chars().all(|c| c.is_ascii_hexdigit()))
            {
                mac = Some(norm);
            }
        }
        if ip.is_some() && mac.is_some() {
            break;
        }
    }
    ip.zip(mac)
}

// Reject incomplete (all-zero), broadcast, and multicast (group bit set) entries.
fn is_unicast_mac(mac: &str) -> bool {
    if mac == "00:00:00:00:00:00" {
        return false;
    }
    matches!(u8::from_str_radix(&mac[..2], 16), Ok(first) if first & 0x01 == 0)
}

async fn fetch_arp_table() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();

    // Linux: read the kernel table directly — `arp` (net-tools) is often not installed.
    #[cfg(target_os = "linux")]
    if let Ok(content) = tokio::fs::read_to_string("/proc/net/arp").await {
        for line in content.lines().skip(1) {
            if let Some((ip, mac)) = parse_arp_line(line) {
                if is_unicast_mac(&mac) {
                    map.insert(ip, mac);
                }
            }
        }
        if !map.is_empty() {
            return map;
        }
    }

    let Ok(out) = tokio::process::Command::new("arp")
        .arg("-a")
        .output()
        .await
    else {
        return map;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((ip, mac)) = parse_arp_line(line) {
            if is_unicast_mac(&mac) {
                map.insert(ip, mac);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_arp_output() {
        let (ip, mac) = parse_arp_line("  192.168.1.1           aa-bb-cc-dd-ee-0f     dynamic").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(mac, "aa:bb:cc:dd:ee:0f");
    }

    #[test]
    fn parses_linux_arp_output() {
        let (ip, mac) = parse_arp_line("? (192.168.1.1) at aa:bb:cc:dd:ee:0f [ether] on wlan0").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(mac, "aa:bb:cc:dd:ee:0f");
    }

    #[test]
    fn parses_proc_net_arp() {
        let (ip, mac) = parse_arp_line("192.168.1.7      0x1         0x2         aa:bb:cc:dd:ee:0f     *        eth0").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 7));
        assert_eq!(mac, "aa:bb:cc:dd:ee:0f");
    }

    #[test]
    fn skips_lines_without_ip_and_mac() {
        assert!(parse_arp_line("Interface: 192.168.1.5 --- 0x10").is_none());
        assert!(parse_arp_line("  Internet Address      Physical Address      Type").is_none());
        assert!(parse_arp_line("").is_none());
    }

    #[test]
    fn rejects_non_unicast_macs() {
        assert!(!is_unicast_mac("ff:ff:ff:ff:ff:ff")); // broadcast
        assert!(!is_unicast_mac("01:00:5e:00:00:fb")); // IPv4 multicast
        assert!(!is_unicast_mac("33:33:00:00:00:01")); // IPv6 multicast
        assert!(!is_unicast_mac("00:00:00:00:00:00")); // incomplete
        assert!(is_unicast_mac("aa:bb:cc:dd:ee:0f"));
    }

    #[test]
    fn vendor_lookup_detects_randomized_and_known_ouis() {
        assert_eq!(lookup_vendor("b8:27:eb:12:34:56"), Some("Raspberry Pi"));
        assert_eq!(lookup_vendor("B8-27-EB-12-34-56"), Some("Raspberry Pi"));
        // locally-administered bit set → randomized privacy MAC
        assert_eq!(lookup_vendor("da:11:22:33:44:55"), Some("Randomized"));
        assert_eq!(lookup_vendor("11:22:33:44:55:66"), None);
        assert_eq!(lookup_vendor("garbage"), None);
    }
}

// ---------------------------------------------------------------------------
// VPN / interface filtering
// ---------------------------------------------------------------------------

const VPN_NAME_HINTS: &[&str] = &[
    "vpn", "tunnel", "tap-", "nordlynx", "nordvpn", "wireguard", "openvpn",
    "expressvpn", "mullvad", "protonvpn", "surfshark", "windscribe", "loopback",
];

fn is_vpn_iface(name: &str) -> bool {
    let lower = name.to_lowercase();
    VPN_NAME_HINTS.iter().any(|hint| lower.contains(hint))
}

pub fn detect_subnet() -> Option<(Ipv4Addr, Ipv4Network)> {
    let interfaces = NetworkInterface::show().ok()?;
    let mut lan: Vec<Ipv4Addr> = Vec::new();
    let mut vpn: Vec<Ipv4Addr> = Vec::new();

    for iface in &interfaces {
        let is_vpn = is_vpn_iface(&iface.name);
        for addr in &iface.addr {
            if let Addr::V4(v4) = addr {
                let ip = v4.ip;
                if ip.is_loopback() || !ip.is_private() {
                    continue;
                }
                if is_vpn { vpn.push(ip); } else { lan.push(ip); }
            }
        }
    }

    let pick = lan
        .iter()
        .find(|ip| ip.octets()[0] == 192 && ip.octets()[1] == 168)
        .or_else(|| lan.iter().find(|ip| ip.octets()[0] == 172))
        .or_else(|| lan.iter().find(|ip| ip.octets()[0] == 10))
        .or_else(|| vpn.first())
        .copied()?;

    let o = pick.octets();
    let base = Ipv4Addr::new(o[0], o[1], o[2], 0);
    let network = Ipv4Network::new(base, 24).ok()?;
    Some((pick, network))
}

// ---------------------------------------------------------------------------
// Ping helpers
// ---------------------------------------------------------------------------

async fn ping_once(client: &Client, ip: Ipv4Addr) -> Option<f64> {
    // The identifier must be unique per in-flight pinger or replies can be
    // misrouted; derive it from the address (unique within a /16 or smaller,
    // which parse_forced_subnet guarantees).
    let ident = PingIdentifier(u32::from(ip) as u16);
    let mut pinger = client.pinger(IpAddr::V4(ip), ident).await;
    pinger.timeout(PING_TIMEOUT);
    match pinger.ping(PingSequence(0), &PING_PAYLOAD).await {
        Ok((IcmpPacket::V4(_), dur)) => Some(dur.as_secs_f64() * 1000.0),
        _ => None,
    }
}

async fn probe_host(client: Arc<Client>, ip: Ipv4Addr) -> (Ipv4Addr, Option<f64>, Option<String>) {
    let latency = ping_once(&client, ip).await;
    let hostname = if latency.is_some() {
        resolve_hostname(ip).await
    } else {
        None
    };
    (ip, latency, hostname)
}

async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    tokio::task::spawn_blocking(move || lookup_addr(&IpAddr::V4(ip)).ok())
        .await
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// Main scanner loop
// ---------------------------------------------------------------------------

pub async fn run_scanner(state: Arc<Mutex<ScanState>>) {
    let forced = state.lock().unwrap().subnet;
    let detected = detect_subnet();

    let (subnet, local_ip) = match (forced, detected) {
        // Forced subnet: keep the real local IP for self-exclusion, but only
        // if it actually lies inside the forced range.
        (Some(net), detected) => (net, detected.map(|(ip, _)| ip).filter(|ip| net.contains(*ip))),
        (None, Some((ip, net))) => (net, Some(ip)),
        (None, None) => {
            state.lock().unwrap().error = Some(
                "Could not detect local IP. Try: lanmap --subnet 192.168.1.0/24".into(),
            );
            return;
        }
    };

    {
        let mut s = state.lock().unwrap();
        s.subnet = Some(subnet);
        s.local_ip = local_ip;
    }

    let client = match Client::new(&Config::builder().kind(ICMP::V4).build()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            state.lock().unwrap().error = Some(format!(
                "ICMP socket error: {}  →  try running as Administrator",
                e
            ));
            return;
        }
    };

    let network_addr = subnet.network();
    let broadcast_addr = subnet.broadcast();

    loop {
        let targets: Vec<Ipv4Addr> = subnet
            .iter()
            .filter(|&ip| Some(ip) != local_ip && ip != network_addr && ip != broadcast_addr)
            .collect();

        {
            let mut s = state.lock().unwrap();
            s.scanning = true;
            s.scan_progress = 0;
            s.scan_total = targets.len();
            s.rescan_requested = false;
        }

        let mut join_set = tokio::task::JoinSet::new();
        for ip in targets {
            let c = Arc::clone(&client);
            join_set.spawn(probe_host(c, ip));
        }

        let now = Instant::now();
        while let Some(result) = join_set.join_next().await {
            let Ok((ip, latency, hostname)) = result else {
                continue;
            };
            let online = latency.is_some();
            let mut s = state.lock().unwrap();
            s.scan_progress += 1;

            if let Some(host) = s.hosts.iter_mut().find(|h| h.ip == ip) {
                host.online = online;
                host.latency_ms = latency;
                if online {
                    host.last_seen = now;
                }
                if hostname.is_some() {
                    host.hostname = hostname;
                }
            } else if online {
                let is_new = s.first_scan_done;
                s.hosts.push(HostInfo {
                    ip,
                    hostname,
                    mac: None,
                    vendor: None,
                    latency_ms: latency,
                    online,
                    is_new,
                    first_seen: now,
                    last_seen: now,
                });
                s.hosts.sort_by_key(|h| u32::from(h.ip));
            }
        }

        // The sweep just refreshed the OS ARP cache; harvest it. Besides MAC →
        // vendor info, this finds hosts that drop ICMP (e.g. Windows firewalls)
        // but still answered ARP at layer 2.
        let arp = fetch_arp_table().await;

        let silent_hosts: Vec<(Ipv4Addr, String)> = {
            let s = state.lock().unwrap();
            arp.iter()
                .filter(|(&ip, _)| {
                    subnet.contains(ip)
                        && ip != network_addr
                        && ip != broadcast_addr
                        && Some(ip) != local_ip
                        && !s.hosts.iter().any(|h| h.ip == ip)
                })
                .map(|(&ip, mac)| (ip, mac.clone()))
                .collect()
        };

        // Resolve hostnames for ARP-only discoveries before inserting them —
        // the ping path only resolves hosts that answered.
        let mut dns_set = tokio::task::JoinSet::new();
        for (ip, mac) in silent_hosts {
            dns_set.spawn(async move {
                let hostname = resolve_hostname(ip).await;
                (ip, mac, hostname)
            });
        }
        let mut discovered = Vec::new();
        while let Some(result) = dns_set.join_next().await {
            if let Ok(entry) = result {
                discovered.push(entry);
            }
        }

        {
            let mut s = state.lock().unwrap();
            let arp_now = Instant::now();
            for host in &mut s.hosts {
                if let Some(mac) = arp.get(&host.ip) {
                    host.vendor = lookup_vendor(mac).map(str::to_string);
                    host.mac = Some(mac.clone());
                    if !host.online {
                        // ARP entry survived the sweep: host is up, just not
                        // answering pings.
                        host.online = true;
                        host.last_seen = arp_now;
                    }
                }
            }
            let is_new = s.first_scan_done;
            for (ip, mac, hostname) in discovered {
                let vendor = lookup_vendor(&mac).map(str::to_string);
                s.hosts.push(HostInfo {
                    ip,
                    hostname,
                    mac: Some(mac),
                    vendor,
                    latency_ms: None,
                    online: true,
                    is_new,
                    first_seen: arp_now,
                    last_seen: arp_now,
                });
            }
            s.hosts.sort_by_key(|h| u32::from(h.ip));
            s.scanning = false;
            s.first_scan_done = true;
            s.last_scan = Some(Instant::now());
        }

        let mut waited = Duration::ZERO;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            waited += Duration::from_millis(500);
            if state.lock().unwrap().rescan_requested || waited >= RESCAN_INTERVAL {
                break;
            }
        }
    }
}
