mod scanner;
mod ui;

use std::sync::{Arc, Mutex};

use ipnetwork::Ipv4Network;
use scanner::ScanState;

#[tokio::main]
async fn main() {
    // Optional: lanmap --subnet 192.168.1.0/24
    let forced_subnet = std::env::args()
        .skip_while(|a| a != "--subnet")
        .nth(1)
        .and_then(|s| s.parse::<Ipv4Network>().ok());

    let state = Arc::new(Mutex::new(ScanState::default()));

    // If user forced a subnet, pre-fill it so the scanner uses it directly
    if let Some(subnet) = forced_subnet {
        let local = subnet.ip(); // treat network addr as "us" for filtering
        let mut s = state.lock().unwrap();
        s.subnet = Some(subnet);
        s.local_ip = Some(local);
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
