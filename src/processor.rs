use crate::{args::Args, utils};
use anyhow::{Context, Result};
use regex::Regex;

pub fn process_log(args: &Args) -> Result<()> {
    println!("Reading from: {}", args.log);
    let lines = utils::read_lines(&args.log)?;
    let ip_regex = build_ip_regex()?;

    let processed: Vec<String> = lines
        .into_iter()
        .map(|line| encrypt_ips(&line, &ip_regex))
        .collect();

    println!("Writing to: {}", args.write);
    utils::write_lines(&args.write, &processed)?;
    Ok(())
}

pub fn build_ip_regex() -> Result<Regex> {
    // Regex for IPv4 and IPv6 addresses
    Regex::new(
        r#"\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4})"#,
    )
    .context("Failed to compile regex")
}

pub fn encrypt_ips(line: &str, regex: &Regex) -> String {
    regex
        .replace_all(line, |caps: &regex::Captures| {
            utils::hash(caps.get(0).unwrap().as_str().as_bytes(), 8, None)
        })
        .to_string()
}
