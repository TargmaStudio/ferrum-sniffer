mod cli;
mod capture;
pub mod parser;
pub mod detector;
pub mod db;

use anyhow::Result;
use clap::Parser;
use crate::cli::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.list {
        capture::list_interfaces()?;
        return Ok(());
    }

    let interface = match args.interface {
        Some(name) => name,
        None => capture::default_interface()?,
    };

    capture::start(&interface, args.count, &args.filter).await?;

    Ok(())
}
