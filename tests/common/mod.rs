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

    single_verification_results([
        signature.verify_message(key, message),
        signature.verify(key, &hashed),
        signature.verify_prepared(key, &prepared),
    ])
}

pub fn failed_single_verification() -> [(&'static str, bool); 3] {
    single_verification_results([false; 3])
}

fn single_verification_results([raw, hashed, prepared]: [bool; 3]) -> [(&'static str, bool); 3] {
    [
        ("raw-message signature", raw),
        ("hashed-message signature", hashed),
        ("prepared-message signature", prepared),
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
    let with_keys = [
        signature.verify_message_with_keys(keys, message),
        signature.verify_with_keys(keys, &hashed),
        signature.verify_prepared_with_keys(keys, &prepared),
    ];
    let with_aggregate_key = match AggregatePublicKey::from_keys(keys) {
        Ok(key) => {
            let groups = [(&key, &hashed)];
            let prepared_groups = [(&key, &prepared)];
            let mut verifier = AggregateVerifier::new(1);
            let streamed =
                verifier.add(&key, &hashed).is_ok() && verifier.finish_and_reset(signature);
            let mut verifier = AggregateVerifier::new(1);
            let streamed_prepared = verifier.add_prepared(&key, &prepared).is_ok()
                && verifier.finish_and_reset(signature);

            [
                signature.verify_message(&key, message),
                signature.verify(&key, &hashed),
                signature.verify_prepared(&key, &prepared),
                signature.verify_groups(&groups),
                signature.verify_prepared_groups(&prepared_groups),
                streamed,
                streamed_prepared,
            ]
        }
        Err(_) => [false; 7],
    };

    fast_aggregate_verification_results(with_keys, with_aggregate_key)
}

#[cfg(blst_simple_dangerous)]
#[allow(dead_code)]
pub fn failed_fast_aggregate_verification() -> [(&'static str, bool); 10] {
    fast_aggregate_verification_results([false; 3], [false; 7])
}

#[cfg(blst_simple_dangerous)]
fn fast_aggregate_verification_results(
    [raw_keys, hashed_keys, prepared_keys]: [bool; 3],
    [
        raw_aggregate,
        hashed_aggregate,
        prepared_aggregate,
        hashed_groups,
        prepared_groups,
        hashed_stream,
        prepared_stream,
    ]: [bool; 7],
) -> [(&'static str, bool); 10] {
    [
        ("raw message with keys", raw_keys),
        ("hashed message with keys", hashed_keys),
        ("prepared message with keys", prepared_keys),
        ("raw message with aggregate key", raw_aggregate),
        ("hashed message with aggregate key", hashed_aggregate),
        ("prepared message with aggregate key", prepared_aggregate),
        ("hashed-message group slice", hashed_groups),
        ("prepared-message group slice", prepared_groups),
        ("hashed-message stream", hashed_stream),
        ("prepared-message stream", prepared_stream),
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
