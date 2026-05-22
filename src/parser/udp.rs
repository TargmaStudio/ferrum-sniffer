pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        // 1. Check minimum length
        if data.len() < 8 {
            return None;
        }

        // 2. extract each field
        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        // 3. return Some(UdpHeader)

        Some(UdpHeader {
            src_port,
            dst_port,
            length,
            checksum
        })
    }
}