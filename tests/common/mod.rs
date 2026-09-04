pub fn decode_hex_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    decode_hex(input)?.try_into().ok()
}

pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let input = input.strip_prefix("0x").unwrap_or(input);
    if input.len() % 2 != 0 {
        return None;
    }

    input
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| Some(nibble(digits[0])? << 4 | nibble(digits[1])?))
        .collect()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
