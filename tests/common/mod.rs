#[cfg(blst_simple_dangerous)]
use blst_simple_rs::{AggregatePublicKey, AggregateSignature, AggregateVerifier, PublicKey};
use blst_simple_rs::{HashedMessage, Signature, UnverifiedPublicKey};

pub const SINGLE_VERIFICATION_PATHS: [&str; 3] = [
    "raw-message signature",
    "hashed-message signature",
    "prepared-message signature",
];

#[cfg(blst_simple_dangerous)]
#[allow(dead_code)]
pub const FAST_AGGREGATE_VERIFICATION_PATHS: [&str; 10] = [
    "raw message with keys",
    "hashed message with keys",
    "prepared message with keys",
    "raw message with aggregate key",
    "hashed message with aggregate key",
    "prepared message with aggregate key",
    "hashed-message group slice",
    "prepared-message group slice",
    "hashed-message stream",
    "prepared-message stream",
];

pub fn decode_hex_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    decode_hex(input)?.try_into().ok()
}

pub fn verify_single_at_each_entry_point(
    key: &UnverifiedPublicKey,
    message: &[u8],
    signature: &Signature,
) -> [bool; 3] {
    let hashed = HashedMessage::new(message);
    let prepared = hashed.prepare();

    [
        signature.verify_message(key, message),
        signature.verify(key, &hashed),
        signature.verify_prepared(key, &prepared),
    ]
}

#[cfg(blst_simple_dangerous)]
#[allow(dead_code)]
pub fn verify_fast_aggregate_at_each_entry_point(
    keys: &[PublicKey],
    message: &[u8],
    signature: &AggregateSignature,
) -> [bool; 10] {
    let hashed = HashedMessage::new(message);
    let prepared = hashed.prepare();
    let with_keys = [
        signature.verify_message_with_keys(keys, message),
        signature.verify_with_keys(keys, &hashed),
        signature.verify_prepared_with_keys(keys, &prepared),
    ];
    let Ok(key) = AggregatePublicKey::from_keys(keys) else {
        return [
            with_keys[0],
            with_keys[1],
            with_keys[2],
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        ];
    };

    let groups = [(&key, &hashed)];
    let prepared_groups = [(&key, &prepared)];
    let mut verifier = AggregateVerifier::new(1);
    let streamed = verifier.add(&key, &hashed).is_ok() && verifier.finish_and_reset(signature);
    let mut verifier = AggregateVerifier::new(1);
    let streamed_prepared =
        verifier.add_prepared(&key, &prepared).is_ok() && verifier.finish_and_reset(signature);

    [
        with_keys[0],
        with_keys[1],
        with_keys[2],
        signature.verify_message(&key, message),
        signature.verify(&key, &hashed),
        signature.verify_prepared(&key, &prepared),
        signature.verify_groups(&groups),
        signature.verify_prepared_groups(&prepared_groups),
        streamed,
        streamed_prepared,
    ]
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
