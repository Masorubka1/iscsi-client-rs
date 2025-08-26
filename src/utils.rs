// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2012-2025 Andrei Maltsev

use std::fmt::Write;

use rand::Rng;

/// Generates a random ISID (6 bytes) and returns:
/// - `[u8; 6]` for direct use in the PDU
/// - `String` containing its hexadecimal representation (no prefix)
pub fn generate_isid() -> ([u8; 6], String) {
    let mut isid = [0u8; 6];
    rand::rng().fill(&mut isid);

    isid[0] &= 0x3F;

    let mut hex = String::with_capacity(12);
    for byte in &isid {
        write!(&mut hex, "{byte:02x}").expect("Writing to String cannot fail");
    }

    (isid, hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isid_generation() {
        let (bytes, hex) = generate_isid();
        assert_eq!(bytes.len(), 6);
        assert_eq!(hex.len(), 12);
        let decoded = hex::decode(&hex).expect("failed decode");
        assert_eq!(decoded, bytes);
    }
}
