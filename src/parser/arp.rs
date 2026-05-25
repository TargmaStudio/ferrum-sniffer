

pub struct ArpHeader {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_length: u8,
    pub protocol_length: u8,
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }

        let hardware_type = u16::from_be_bytes([data[0], data[1]]);
        let protocol_type = u16::from_be_bytes([data[2], data[3]]);
        let hardware_length = data[4];
        let protocol_length = data[5];
        let operation = u16::from_be_bytes([data[6], data[7]]);
        let sender_mac = data[8..14].try_into().ok()?;
        let sender_ip = data[14..18].try_into().ok()?;
        let target_mac = data[18..24].try_into().ok()?;
        let target_ip = data[24..28].try_into().ok()?;

        Some(ArpHeader {
            hardware_type,
            protocol_type,
            hardware_length,
            protocol_length,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }
}