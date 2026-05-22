#[derive(Debug)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Unknown(u8),
}

impl Protocol {
    pub fn from_u8(value: u8) -> Protocol {
        match value {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            n => Protocol::Unknown(n),
        }
    }
}

pub struct Ipv4Packet {
    pub version: u8,
    pub header_length: u8,
    pub ttl: u8,
    pub protocol: Protocol,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

impl Ipv4Packet {
    pub fn parse(data: &[u8]) -> Option<Ipv4Packet> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] & 0b11110000)>> 4;
        let header_length = (data[0] & 0b00001111) * 4;
        let ttl = data[8];
        let protocol = Protocol::from_u8(data[9]);
        let source = data[12..16].try_into().ok()?;
        let destination = data[16..20].try_into().ok()?;

        Some(Ipv4Packet {
            version,
            header_length,
            ttl,
            protocol,
            source,
            destination
        })
    }

    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }
}