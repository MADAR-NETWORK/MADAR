//! SS58 addresses: encode a 32-byte account for display, decode any SS58 string back to its key.

use blake2::{Blake2b512, Digest};

fn checksum(data: &[u8]) -> [u8; 64] {
    let mut h = Blake2b512::new();
    h.update(b"SS58PRE");
    h.update(data);
    h.finalize().into()
}

pub fn encode(key: &[u8; 32], prefix: u16) -> String {
    let mut v = if prefix < 64 {
        vec![prefix as u8]
    } else {
        vec![
            ((prefix & 0b1111_1100) >> 2) as u8 | 0b0100_0000,
            ((prefix >> 8) as u8) | ((prefix & 0b11) << 6) as u8,
        ]
    };
    v.extend_from_slice(key);
    let c = checksum(&v);
    v.extend_from_slice(&c[..2]);
    bs58::encode(v).into_string()
}

/// Returns the 32-byte account key of any valid SS58 address (any prefix).
pub fn decode(s: &str) -> Option<[u8; 32]> {
    let b = bs58::decode(s.trim()).into_vec().ok()?;
    let plen = match b.first()? {
        0..=63 => 1,
        64..=127 => 2,
        _ => return None,
    };
    if b.len() != plen + 32 + 2 {
        return None;
    }
    let c = checksum(&b[..plen + 32]);
    if b[plen + 32..] != c[..2] {
        return None;
    }
    b[plen..plen + 32].try_into().ok()
}

/// Short form for messages: 1abc…wxyz
pub fn short(addr: &str) -> String {
    if addr.chars().count() <= 14 {
        return addr.to_string();
    }
    let head: String = addr.chars().take(6).collect();
    let tail: String = addr
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known_address() {
        // Alice, generic prefix 42
        let alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let k = decode(alice).unwrap();
        assert_eq!(
            hex::encode(k),
            "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
        assert_eq!(encode(&k, 42), alice);
        assert_eq!(decode(&encode(&k, 0)).unwrap(), k);
        assert_eq!(decode(&encode(&k, 85)).unwrap(), k);
        assert!(decode("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ").is_none());
    }
}
