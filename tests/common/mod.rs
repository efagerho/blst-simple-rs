#[cfg(blst_simple_dangerous)]
use blst_simple_rs::{AggregatePublicKey, AggregateSignature, AggregateVerifier, PublicKey};
use blst_simple_rs::{HashedMessage, Signature, UnverifiedPublicKey};

pub fn decode_hex_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    decode_hex(input)?.try_into().ok()
}

pub fn verify_single_at_each_entry_point(
    key: &UnverifiedPublicKey,
    message: &[u8],
    signature: &Signature,
) -> [(&'static str, bool); 3] {
    let hashed = HashedMessage::new(message);
    let prepared = hashed.prepare();

    [
        (
            "raw-message signature",
            signature.verify_message(key, message),
        ),
        ("hashed-message signature", signature.verify(key, &hashed)),
        (
            "prepared-message signature",
            signature.verify_prepared(key, &prepared),
        ),
    ]
}

pub fn failed_single_verification() -> [(&'static str, bool); 3] {
    [
        ("raw-message signature", false),
        ("hashed-message signature", false),
        ("prepared-message signature", false),
    ]
}

#[cfg(blst_simple_dangerous)]
#[allow(dead_code)]
pub fn verify_fast_aggregate_at_each_entry_point(
    keys: &[PublicKey],
    message: &[u8],
    signature: &AggregateSignature,
) -> [(&'static str, bool); 10] {
    let hashed = HashedMessage::new(message);
    let prepared = hashed.prepare();
    let key = AggregatePublicKey::from_keys(keys).ok();

    [
        (
            "raw message with keys",
            signature.verify_message_with_keys(keys, message),
        ),
        (
            "hashed message with keys",
            signature.verify_with_keys(keys, &hashed),
        ),
        (
            "prepared message with keys",
            signature.verify_prepared_with_keys(keys, &prepared),
        ),
        (
            "raw message with aggregate key",
            key.as_ref()
                .is_some_and(|key| signature.verify_message(key, message)),
        ),
        (
            "hashed message with aggregate key",
            key.as_ref()
                .is_some_and(|key| signature.verify(key, &hashed)),
        ),
        (
            "prepared message with aggregate key",
            key.as_ref()
                .is_some_and(|key| signature.verify_prepared(key, &prepared)),
        ),
        (
            "hashed-message group slice",
            key.as_ref()
                .is_some_and(|key| signature.verify_groups(&[(key, &hashed)])),
        ),
        (
            "prepared-message group slice",
            key.as_ref()
                .is_some_and(|key| signature.verify_prepared_groups(&[(key, &prepared)])),
        ),
        (
            "hashed-message stream",
            key.as_ref().is_some_and(|key| {
                let mut verifier = AggregateVerifier::new(1);
                verifier.add(key, &hashed).is_ok() && verifier.finish_and_reset(signature)
            }),
        ),
        (
            "prepared-message stream",
            key.as_ref().is_some_and(|key| {
                let mut verifier = AggregateVerifier::new(1);
                verifier.add_prepared(key, &prepared).is_ok()
                    && verifier.finish_and_reset(signature)
            }),
        ),
    ]
}

#[cfg(blst_simple_dangerous)]
#[allow(dead_code)]
pub fn failed_fast_aggregate_verification() -> [(&'static str, bool); 10] {
    [
        ("raw message with keys", false),
        ("hashed message with keys", false),
        ("prepared message with keys", false),
        ("raw message with aggregate key", false),
        ("hashed message with aggregate key", false),
        ("prepared message with aggregate key", false),
        ("hashed-message group slice", false),
        ("prepared-message group slice", false),
        ("hashed-message stream", false),
        ("prepared-message stream", false),
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
