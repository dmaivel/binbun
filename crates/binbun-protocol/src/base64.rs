//! Bytes on the wire as standard base64 (RFC 4648, padded), as JSON has
//! no bytes. `#[serde(with = "crate::base64::option")]` for an
//! `Option<Vec<u8>>`.

/// The alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` as base64.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let word = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (word >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(
                    ALPHABET.get(index as usize).copied().unwrap_or(b'A'),
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The value of base64 character `c`.
fn value(c: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|at| u32::try_from(at).ok())
}

/// The bytes `text` encodes.
///
/// # Errors
///
/// It is not padded base64.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("base64 of a length not a multiple of 4".to_owned());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quad in bytes.chunks(4) {
        let padding = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 {
            return Err("base64 with too much padding".to_owned());
        }
        let mut word = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            let v = if i >= 4 - padding {
                0
            } else {
                value(c).ok_or_else(|| format!("{:?} is not base64", char::from(c)))?
            };
            word = word << 6 | v;
        }
        let [_, a, b, c] = word.to_be_bytes();
        out.extend_from_slice([a, b, c].get(..3 - padding).unwrap_or_default());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn base64_round_trips_rfc_4648_vectors() {
        for (bytes, text) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[0xff, 0x00, 0xfe], "/wD+"),
        ] {
            assert_eq!(encode(bytes), text);
            assert_eq!(decode(text).unwrap(), bytes);
        }
        assert!(decode("Zg=").is_err());
        assert!(decode("Z!==").is_err());
        assert!(decode("Z===").is_err());
    }
}
