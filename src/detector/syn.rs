use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use crate::parser::tcp::TcpFlags;

pub struct SynDetector {
    // Track: IP -> list of (port, time) pairs
    port_scan_tracker: HashMap<[u8; 4], Vec<(u16, Instant)>>,

    // How many ports in how many seconds = port scan
    scan_threshold: usize,
    scan_window: Duration,
}

impl SynDetector {
    pub fn new() -> Self {
        SynDetector {
            port_scan_tracker: HashMap::new(),
            scan_threshold: 10, // 10 different pairs
            scan_window: Duration::from_secs(5),
        }
    }

    pub fn analyze(
        &mut self,
        src_ip: &[u8; 4],
        dst_port: u16,
        flags: &TcpFlags,
    ) {
        // step 1: illegal combinations
        if flags.contains(TcpFlags::SYN) && flags.contains(TcpFlags::FIN) {
            println!(
                "⚠️  ILLEGAL FLAGS: SYN+FIN from {}",
                format_ip(src_ip)
            );
        }

        // step 2: NULL scan (no flags at all)
        if flags.is_empty() {
            println!(
                "⚠️  NULL SCAN from {}",
                format_ip(src_ip)
            );
        }

        // step 3: SYN without ACK = new connection attempt
        if flags.contains(TcpFlags::SYN) && !flags.contains(TcpFlags::ACK) {
            println!(
                "→  NEW CONNECTION: {} → port {}",
                format_ip(src_ip),
                dst_port
            );

            // step 4: track for port scan detection
            let entry = self.port_scan_tracker
                .entry(*src_ip)
                .or_insert_with(Vec::new);

            // add this port and timestamp
            entry.push((dst_port, Instant::now()));

            // step 5: clean old entries outside the window
            let window = self.scan_window;
            entry.retain(|(_, time)| time.elapsed() < window);

            // step 6: check if threshold exceeded
            let unique_ports: HashSet<u16> = entry.iter().map(|(p, _)| *p).collect();

            if unique_ports.len() > self.scan_threshold {
                println!(
                    "🚨 PORT SCAN DETECTED from {} — {} ports in {:?}",
                    format_ip(src_ip),
                    unique_ports.len(),
                    self.scan_window
                );
            }
        }
    }
}

fn format_ip(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}