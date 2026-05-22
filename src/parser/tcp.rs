use bitflags::bitflags;

bitflags! {
    #[derive(Debug)]
    pub struct TcpFlags: u8 {
        const FIN = 0b0000_0001;
        const SYN = 0b0000_0010;
        const RST = 0b0000_0100;
        const PSH = 0b0000_1000;
        const ACK = 0b0001_0000;
        const URG = 0b0010_0000;
    }
}

pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let data_offset = (data[12] & 0b1111_0000) >> 4;

        Some(TcpHeader {
            src_port:       u16::from_be_bytes([data[0], data[1]]),
            dst_port:       u16::from_be_bytes([data[2], data[3]]),
            seq:            u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack:            u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset,
            flags:          TcpFlags::from_bits_truncate(data[13]),
            window_size:    u16::from_be_bytes([data[14], data[15]]),
            checksum:       u16::from_be_bytes([data[16], data[17]]),
            urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
        })
    }
}