use anyhow::{Context, Result};
use pcap::{Capture, Device};
use crate::db::store::{PacketRecord, Store};
use crate::detector::syn;
use crate::parser::{ethernet, ipv4::{Ipv4Packet, Protocol}};
use crate::parser::tcp::{TcpHeader};
use crate::parser::udp::UdpHeader;

pub fn list_interfaces() -> Result<()> {
    let devices = get_devices()?;

    for device in &devices {
        let desc = device.desc.as_deref().unwrap_or("no description");

        println!("{} - {}", device.name, desc);
    }

    Ok(())
}

pub fn default_interface() -> Result<String> {
    let devices = get_devices()?;

    let device = devices
        .iter()
        .find(|d| d.name != "lo" && d.name != "lo0")
        .or_else(|| devices.first())
        .context("No network devices found")?;

    Ok(device.name.clone())
}

pub async fn start(interface: &str, count: usize, filter: &str) -> Result<()> {
    let store = Store::new("sqlite://ferrum.db?mode=rwc").await?;
    let mut cap = Capture::from_device(interface)
        .context("Failed to open interface")?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .context("Failed to open interface")?;
    cap.filter(filter, true)
        .context("Failed to filter")?;

    let mut detector = syn::SynDetector::new();
    let mut packet_number: usize = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                packet_number += 1;
                if let Some(frame) = ethernet::parse(packet.data) {
                    if frame.ether_type == 0x0800 {
                        if let Some(ip) = Ipv4Packet::parse(&packet.data[14..]) {
                            let ip_header_len = ip.header_length as usize;
                            let transport = &packet.data[14 + ip_header_len..];

                            match ip.protocol {
                                Protocol::TCP => {
                                    if let Some(tcp) = TcpHeader::parse(transport) {
                                        detector.analyze(&ip.source, tcp.dst_port, &tcp.flags);

                                        // Store the packet
                                        let record = PacketRecord {
                                            src_ip: Ipv4Packet::format_ip(&ip.source),
                                            dst_ip: Ipv4Packet::format_ip(&ip.destination),
                                            src_port: tcp.src_port,
                                            dst_port: tcp.dst_port,
                                            protocol: "TCP".to_string(),
                                            flags: Some(format_flags(&tcp.flags)),
                                            length: transport.len() as u16
                                        };
                                        store.insert_packet(&record).await?;

                                        println!(
                                            "#{} {}:{} -> {}:{} [{}] seq={} ack={} win={}",
                                            packet_number,
                                            Ipv4Packet::format_ip(&ip.source),
                                            tcp.src_port,
                                            Ipv4Packet::format_ip(&ip.destination),
                                            tcp.dst_port,
                                            format_flags(&tcp.flags),
                                            tcp.seq,
                                            tcp.ack,
                                            tcp.window_size
                                        );
                                    }
                                },
                                Protocol::UDP => {
                                    if let Some(udp) = UdpHeader::parse(transport) {
                                        let record = PacketRecord {
                                            src_ip:   Ipv4Packet::format_ip(&ip.source),
                                            dst_ip:   Ipv4Packet::format_ip(&ip.destination),
                                            src_port: udp.src_port,
                                            dst_port: udp.dst_port,
                                            protocol: "UDP".to_string(),
                                            flags:    None,
                                            length:   udp.length,
                                        };
                                        store.insert_packet(&record).await?;

                                        println!(
                                            "#{} {}:{} -> {}:{} [UDP] len={}",
                                            packet_number,
                                            Ipv4Packet::format_ip(&ip.source),
                                            udp.src_port,
                                            Ipv4Packet::format_ip(&ip.destination),
                                            udp.dst_port,
                                            udp.length
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }

                if packet_number % 1000 == 0 {
                    let deleted = store.cleanup_old_packets(7).await?;
                    if deleted > 0 {
                        println!("🧹 Cleaned {} old packets", deleted);
                    }
                }

                if count > 0 && packet_number >= count {
                    println!("Captured {} packets. Done", count);
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Capture error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn get_devices() -> Result<Vec<Device>> {
    Device::list().context("Failed to list network devices")
}

fn format_flags(flags: &crate::parser::tcp::TcpFlags) -> String {
    let mut f = Vec::new();
    if flags.contains(crate::parser::tcp::TcpFlags::SYN) { f.push("SYN"); }
    if flags.contains(crate::parser::tcp::TcpFlags::ACK) { f.push("ACK"); }
    if flags.contains(crate::parser::tcp::TcpFlags::FIN) { f.push("FIN"); }
    if flags.contains(crate::parser::tcp::TcpFlags::RST) { f.push("RST"); }
    if flags.contains(crate::parser::tcp::TcpFlags::PSH) { f.push("PSH"); }
    if flags.contains(crate::parser::tcp::TcpFlags::URG) { f.push("URG"); }
    f.join("|")
}