//! Deterministic line transport for cross-implementation conformance tests.

use std::env;
use std::error::Error;
use std::io::{self, BufRead as _, Write as _};

use cofferwired::RelayService;

fn main() -> Result<(), Box<dyn Error>> {
    let database = env::args_os()
        .nth(1)
        .ok_or("usage: cofferwire-line-relay DATABASE")?;
    if env::args_os().nth(2).is_some() {
        return Err("usage: cofferwire-line-relay DATABASE".into());
    }
    let service = RelayService::open(database)?;
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let (now, frame) = line
            .split_once(' ')
            .ok_or("line must be: UNIX_SECONDS FRAME_HEX")?;
        let response = service.exchange_frame_at(&decode_hex(frame)?, now.parse()?)?;
        writeln!(stdout, "{}", encode_hex(&response))?;
        stdout.flush()?;
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err("hex input has odd length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}
