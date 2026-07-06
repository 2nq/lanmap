mod scanner;
mod ui;

use std::sync::{Arc, Mutex};

use ipnetwork::Ipv4Network;
use scanner::ScanState;

// Optional: lanmap --subnet 192.168.1.0/24
fn parse_forced_subnet() -> Option<Ipv4Network> {
    let args: Vec<String> = std::env::args().collect();
    let pos = args.iter().position(|a| a == "--subnet")?;

    let Some(raw) = args.get(pos + 1) else {
        eprintln!("error: --subnet requires a value, e.g. --subnet 192.168.1.0/24");
        std::process::exit(2);
    };
    match raw.parse::<Ipv4Network>() {
        Ok(net) if net.prefix() >= 16 => Some(net),
        Ok(net) => {
            eprintln!(
                "error: subnet {} is too large to sweep — /16 is the maximum",
                net
            );
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("error: invalid subnet '{}': {}", raw, e);
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() {
    let forced_subnet = parse_forced_subnet();

    let state = Arc::new(Mutex::new(ScanState::default()));

    // Pre-fill a forced subnet; the scanner still detects the real local IP
    // so it can exclude ourselves from the sweep.
    if let Some(subnet) = forced_subnet {
        state.lock().unwrap().subnet = Some(subnet);
    }

    let scanner_state = Arc::clone(&state);
    tokio::spawn(async move {
        scanner::run_scanner(scanner_state).await;
    });

    if let Err(e) = ui::run(state) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
