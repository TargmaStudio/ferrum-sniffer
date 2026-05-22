pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: u16,
}

pub fn parse(data: &[u8]) -> Option<EthernetFrame> {
    if data.len() < 14 {
        return None;
    }

    Some(EthernetFrame {
        destination: data[0..6].try_into().ok()?,
        source: data[0..6].try_into().ok()?,
        ether_type: u16::from_be_bytes([data[12], data[13]]),
    })
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
