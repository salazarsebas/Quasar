//! Stellar StrKey validation.
//!
//! StrKey format: 1 byte version prefix + 32 bytes payload + 2 bytes CRC16-XModem checksum,
//! all base32-encoded (56 characters total).
//!
//! Version prefixes:
//! - `G` (byte 6 << 3 = 48) -> Ed25519 public key (account)
//! - `C` (byte 2 << 3 = 16) -> Contract ID

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode a base32 string (RFC 4648, no padding) into bytes.
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut output = Vec::new();

    for &ch in input.as_bytes() {
        let val = match BASE32_ALPHABET.iter().position(|&c| c == ch) {
            Some(v) => v as u64,
            None => return None,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Some(output)
}

/// CRC16-XModem checksum used by Stellar StrKey.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[derive(Debug, PartialEq, Eq)]
pub enum StrKeyKind {
    AccountId,
    Contract,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StrKeyError {
    InvalidLength(usize),
    InvalidPrefix(char),
    InvalidBase32,
    InvalidChecksum,
}

impl std::fmt::Display for StrKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrKeyError::InvalidLength(len) => {
                write!(f, "expected 56 characters, got {}", len)
            }
            StrKeyError::InvalidPrefix(ch) => {
                write!(
                    f,
                    "invalid prefix '{}' (expected 'G' for accounts or 'C' for contracts)",
                    ch
                )
            }
            StrKeyError::InvalidBase32 => write!(f, "contains invalid base32 characters"),
            StrKeyError::InvalidChecksum => write!(f, "invalid CRC16 checksum"),
        }
    }
}

/// Validate a Stellar StrKey address and return its kind.
pub fn validate_strkey(address: &str) -> Result<StrKeyKind, StrKeyError> {
    if address.len() != 56 {
        return Err(StrKeyError::InvalidLength(address.len()));
    }

    let first_char = address.chars().next().unwrap();
    let expected_kind = match first_char {
        'G' => StrKeyKind::AccountId,
        'C' => StrKeyKind::Contract,
        ch => return Err(StrKeyError::InvalidPrefix(ch)),
    };

    let decoded = base32_decode(address).ok_or(StrKeyError::InvalidBase32)?;

    // Decoded should be 35 bytes: 1 version + 32 payload + 2 checksum
    if decoded.len() != 35 {
        return Err(StrKeyError::InvalidBase32);
    }

    let payload = &decoded[..33]; // version + ed25519 key
    let checksum_bytes = &decoded[33..35];
    let expected_checksum = u16::from_le_bytes([checksum_bytes[0], checksum_bytes[1]]);
    let actual_checksum = crc16_xmodem(payload);

    if expected_checksum != actual_checksum {
        return Err(StrKeyError::InvalidChecksum);
    }

    Ok(expected_kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid addresses generated with deterministic payloads and correct CRC16 checksums.
    const ACCOUNT_1: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const ACCOUNT_2: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABOV";
    const CONTRACT_1: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    #[test]
    fn valid_account_address() {
        let result = validate_strkey(ACCOUNT_1);
        assert_eq!(result, Ok(StrKeyKind::AccountId));
    }

    #[test]
    fn valid_account_address_2() {
        let result = validate_strkey(ACCOUNT_2);
        assert_eq!(result, Ok(StrKeyKind::AccountId));
    }

    #[test]
    fn valid_contract_address() {
        let result = validate_strkey(CONTRACT_1);
        assert_eq!(result, Ok(StrKeyKind::Contract));
    }

    #[test]
    fn invalid_length() {
        let result = validate_strkey("GAAAA");
        assert_eq!(result, Err(StrKeyError::InvalidLength(5)));
    }

    #[test]
    fn invalid_prefix() {
        // 56 chars but starts with X
        let result = validate_strkey("XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(result, Err(StrKeyError::InvalidPrefix('X')));
    }

    #[test]
    fn invalid_checksum() {
        // Valid base32 and starts with G, but wrong checksum (changed last 3 chars)
        let result = validate_strkey("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(result, Err(StrKeyError::InvalidChecksum));
    }

    #[test]
    fn invalid_base32_chars() {
        // '1' is not in the base32 alphabet (only 2-7 are valid digits)
        let result = validate_strkey("G1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(result, Err(StrKeyError::InvalidBase32));
    }

    #[test]
    fn invalid_prefix_lowercase() {
        // Lowercase 'g' is not a valid prefix
        let result = validate_strkey("gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(result, Err(StrKeyError::InvalidPrefix('g')));
    }

    #[test]
    fn crc16_known_values() {
        assert_eq!(crc16_xmodem(b""), 0x0000);
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    #[test]
    fn base32_decode_roundtrip() {
        // Decode a known valid account: version byte 48 + 32 zero bytes + checksum
        let decoded = base32_decode(ACCOUNT_1).unwrap();
        assert_eq!(decoded.len(), 35);
        assert_eq!(decoded[0], 48); // G version byte
        assert!(decoded[1..33].iter().all(|&b| b == 0)); // zero payload
    }
}
