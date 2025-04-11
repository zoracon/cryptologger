use clap::Parser;

/// A CLI tool to encrypt IP addresses in server logs.
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    /// Path to the output log file
    #[arg(short, long)]
    pub write: String,

    /// Path to the input log file
    #[arg(short, long)]
    pub log: String,
}
