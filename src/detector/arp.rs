use std::collections::HashMap;
use std::time::{Duration, Instant};

pub enum ArpEvent {
    NewMapping,
    MacUpdated,
    PoisoningDetected {
        ip: [u8; 4],
        known_mac: [u8; 6],
        spoofed_mac: [u8; 6],
    }
}

pub struct ArpDetector {
    cache: HashMap<[u8; 4], ([u8; 6], Instant)>,
    pub poisoning_window: Duration,
}

impl ArpDetector {
    pub fn new() -> ArpDetector {
        ArpDetector {
            cache: HashMap::new(),
            poisoning_window: Duration::from_secs(300),
        }
    }

    pub fn analyze(&mut self, sender_ip: &[u8; 4], sender_mac: &[u8; 6]) -> ArpEvent{
        if let Some((known_mac, last_seen)) = self.cache.get(sender_ip) {
            if known_mac != sender_mac {
                return if last_seen.elapsed() < self.poisoning_window {
                    ArpEvent::PoisoningDetected {
                        ip: *sender_ip,
                        known_mac: *known_mac,
                        spoofed_mac: *sender_mac,
                    }
                } else {
                    // Slow MAC change -> DHCP reassignment
                    self.cache.insert(*sender_ip, (*sender_mac, Instant::now()));

                    ArpEvent::MacUpdated
                }
            }
        } else {
            self.cache.insert(*sender_ip, (*sender_mac, Instant::now()));
        }

        ArpEvent::NewMapping
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_new_mapping_stored() {
        let mut detector = ArpDetector::new();
        let ip  = [192, 168, 1, 1];
        let mac = [0x28, 0x5b, 0x0c, 0x8f, 0x30, 0x42];

        let event = detector.analyze(&ip, &mac);
        assert!(matches!(event, ArpEvent::NewMapping));
    }

    #[test]
    fn test_same_mac_no_alert() {
        let mut detector = ArpDetector::new();
        let ip  = [192, 168, 1, 1];
        let mac = [0x28, 0x5b, 0x0c, 0x8f, 0x30, 0x42];

        detector.analyze(&ip, &mac);
        let event = detector.analyze(&ip, &mac);
        assert!(matches!(event, ArpEvent::NewMapping));
    }

    #[test]
    fn test_detects_poisoning() {
        let mut detector = ArpDetector::new();
        let ip          = [192, 168, 1, 1];
        let real_mac    = [0x28, 0x5b, 0x0c, 0x8f, 0x30, 0x42];
        let spoofed_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        detector.analyze(&ip, &real_mac);
        // immediately change MAC → poisoning
        let event = detector.analyze(&ip, &spoofed_mac);
        assert!(matches!(event, ArpEvent::PoisoningDetected { .. }));
    }

    #[test]
    fn test_different_ips_no_alert() {
        let mut detector = ArpDetector::new();
        let ip1 = [192, 168, 1, 1];
        let ip2 = [192, 168, 1, 2];
        let mac = [0x28, 0x5b, 0x0c, 0x8f, 0x30, 0x42];

        detector.analyze(&ip1, &mac);
        let event = detector.analyze(&ip2, &mac);
        assert!(matches!(event, ArpEvent::NewMapping));
    }

    #[test]
    fn test_dhcp_reassignment_no_alert() {
        let mut detector = ArpDetector::new();
        // set tiny window for testing
        detector.poisoning_window = Duration::from_millis(1);

        let ip          = [192, 168, 1, 1];
        let real_mac    = [0x28, 0x5b, 0x0c, 0x8f, 0x30, 0x42];
        let new_mac     = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        detector.analyze(&ip, &real_mac);

        // wait longer than poisoning window
        std::thread::sleep(Duration::from_millis(5));

        // MAC change after window → legitimate reassignment
        let event = detector.analyze(&ip, &new_mac);
        assert!(matches!(event, ArpEvent::MacUpdated));
    }
}
