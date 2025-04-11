mod bsixtyfour;
use anyhow::{Context, Result};
use bsixtyfour::b64_vec_encode;
use hmac::{Hmac, Mac};
use rand::{thread_rng, Rng};
use sha2::Sha256;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    str,
};

type HmacSha256 = Hmac<Sha256>;
const SALT_SIZE: usize = 16;

lazy_static::lazy_static! {
    static ref SALT: Vec<u8> = generate_salt(SALT_SIZE);
}

pub fn hash(input: &[u8], size: usize, salt_param: Option<&[u8]>) -> String {
    let salt = salt_param.unwrap_or_else(|| &*SALT);
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC init failed");
    mac.update(input);
    let digest = mac.finalize().into_bytes();
    let encoded = b64_vec_encode(&digest);
    str::from_utf8(&encoded[..size])
        .expect("UTF-8 conversion failed")
        .to_string()
}

pub fn read_lines(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context("Unable to open input file")?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(Result::ok).collect())
}

pub fn write_lines(path: &str, lines: &[String]) -> Result<()> {
    let mut file = File::create(path).context("Unable to create output file")?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn generate_salt(size: usize) -> Vec<u8> {
    thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(size)
        .collect()
}
