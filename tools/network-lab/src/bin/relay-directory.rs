#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use messenger_transport::{RelayEndpoint, SignedRelayDirectory};
use rand_core::OsRng;
use std::{env, fs, io, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, secret, public] if command == "generate-key" => {
            let key = SigningKey::generate(&mut OsRng);
            write_secret(Path::new(secret), &key.to_bytes())?;
            fs::write(public, encode_hex(&key.verifying_key().to_bytes()))?;
            println!("generated offline signing key and public verification key");
        }
        [
            command,
            secret,
            output,
            version,
            issued_at,
            expires_at,
            endpoints,
        ] if command == "sign" => {
            let key_bytes: [u8; 32] = fs::read(secret)?.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "signing key must be 32 bytes")
            })?;
            let key = SigningKey::from_bytes(&key_bytes);
            let mut directory = SignedRelayDirectory {
                version: version.parse()?,
                issued_at: issued_at.parse()?,
                expires_at: expires_at.parse()?,
                endpoints: read_endpoints(Path::new(endpoints))?,
                signature: [0; 64],
            };
            directory.signature = key.sign(&directory.signing_bytes()?).to_bytes();
            fs::write(output, directory.encode()?)?;
            println!("signed relay directory version {}", directory.version);
        }
        [command, public, input, now, minimum] if command == "verify" => {
            let public_text = fs::read_to_string(public)?;
            let public_key: [u8; 32] = decode_hex(public_text.trim())?
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad public key"))?;
            let directory = SignedRelayDirectory::decode(&fs::read(input)?)?;
            directory.verify(&public_key, now.parse()?, minimum.parse()?)?;
            println!("relay directory version {} is valid", directory.version);
        }
        _ => {
            eprintln!(
                "usage:\n  relay-directory generate-key SECRET.bin PUBLIC.hex\n  relay-directory sign SECRET.bin DIRECTORY.bin VERSION ISSUED_AT EXPIRES_AT ENDPOINTS.txt\n  relay-directory verify PUBLIC.hex DIRECTORY.bin NOW MINIMUM_VERSION"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

fn read_endpoints(path: &Path) -> Result<Vec<RelayEndpoint>, Box<dyn std::error::Error>> {
    let mut endpoints = Vec::new();
    for (line_number, line) in fs::read_to_string(path)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("endpoint line {} must have four fields", line_number + 1),
            )
            .into());
        }
        endpoints.push(RelayEndpoint {
            endpoint_id: decode_hex(fields[0])?.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "endpoint ID must be 16 bytes")
            })?,
            priority: fields[1].parse()?,
            websocket_url: fields[2].to_owned(),
            https_url: fields[3].to_owned(),
        });
    }
    if endpoints.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no endpoints").into());
    }
    Ok(endpoints)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, io::Error> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "odd hex length"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, io::Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid hex")),
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(unix)]
fn write_secret(path: &Path, value: &[u8]) -> io::Result<()> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(value)
}

#[cfg(not(unix))]
fn write_secret(path: &Path, value: &[u8]) -> io::Result<()> {
    let _ = path;
    let _ = value;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "generate the offline key on a Unix host with restrictive permissions",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_rejects_invalid() {
        let value = [0x00, 0xab, 0xff];
        assert_eq!(decode_hex(&encode_hex(&value)).unwrap(), value);
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
    }
}
