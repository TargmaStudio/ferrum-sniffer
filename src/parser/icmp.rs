pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: [u8; 4],
}

impl IcmpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let icmp_type = data[0];
        let code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let rest = data[4..8].try_into().ok()?;

        Some(IcmpHeader {
            icmp_type,
            code,
            checksum,
            rest
        })
    }
}