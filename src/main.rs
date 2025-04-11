mod args;
mod processor;
mod utils;

use anyhow::Result;
use args::Args;
use clap::Parser;
use processor::process_log;

fn main() -> Result<()> {
    let args = Args::parse();
    process_log(&args)?;
    Ok(())
}

#[test]
fn ipv4_test() {
    let input = "127.0.0.1 - - [01/Jan/2024] \"GET / HTTP/1.1\" 200 1234";
    let regex = regex::Regex::new(r"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
    let hashed = processor::encrypt_ips(input, &regex);
    assert_ne!(hashed, input);
}

// #[test]
// fn ipv6_test() {
//     let input = "fe80::1ff:fe23:4567:890a - - [11/Apr/2025:10:45:05 +0000] \"GET /images/logo.png HTTP/1.1\" 200 5432";
//     let regex = regex::Regex::new(
//         r#"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4})"#,
//     )
//     .unwrap();
//     let hashed = processor::encrypt_ips(input, &regex);
//     assert_ne!(hashed, input);
// }
