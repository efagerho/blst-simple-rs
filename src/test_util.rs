use std::vec::Vec;

pub(crate) fn hex<const N: usize>(input: &str) -> [u8; N] {
    hex_bytes(input).try_into().unwrap()
}

pub(crate) fn hex_bytes(input: &str) -> Vec<u8> {
    let input = input.strip_prefix("0x").unwrap_or(input);
    assert_eq!(input.len() % 2, 0);

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| (nibble(digits[0]) << 4) | nibble(digits[1]))
        .collect()
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hexadecimal digit"),
    }
}
