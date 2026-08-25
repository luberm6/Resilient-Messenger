#![forbid(unsafe_code)]
pub fn protocol_version() -> u16 { messenger_protocol::PROTOCOL_VERSION }
#[cfg(test)] mod tests { #[test] fn version_is_available() { assert_eq!(super::protocol_version(), 1); } }
