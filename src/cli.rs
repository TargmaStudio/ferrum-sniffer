use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ferrum-sniff")]
#[command(about = "A low-level packet analyzer")]
pub struct Args {
    /// Network interface to sniff (e.g., eth0, en0)
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Number of packets to capture (0 = unlimited)
    #[arg(short, long, default_value_t = 0)]
    pub count: usize,

    /// List available interfaces and exit
    #[arg(short, long)]
    pub list: bool,

    /// BPF filter expression
    #[arg(short, long, default_value = "ip and (tcp or udp)")]
    pub filter: String,
}