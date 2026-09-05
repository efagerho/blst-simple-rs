use std::vec::Vec;

use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};
use crate::{PublicKey, Signature};

pub(crate) fn scalar(value: u8) -> [u8; 32] {
    let mut scalar = [0; 32];
    scalar[31] = value;
    scalar
}

pub(crate) fn signature(secret: [u8; 32], message: &[u8]) -> Signature {
    signature_from_secret(&decode_secret(secret), message)
}

pub(crate) fn public_key(secret: [u8; 32]) -> PublicKey {
    public_key_from_secret(&decode_secret(secret))
}

pub(crate) fn participant(secret: [u8; 32], message: &[u8]) -> (PublicKey, Signature) {
    let secret = decode_secret(secret);
    (
        public_key_from_secret(&secret),
        signature_from_secret(&secret, message),
    )
}

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

fn decode_secret(bytes: [u8; 32]) -> blst::min_pk::SecretKey {
    blst::min_pk::SecretKey::from_bytes(&bytes).unwrap()
}

fn signature_from_secret(secret: &blst::min_pk::SecretKey, message: &[u8]) -> Signature {
    let bytes = secret.sign(message, SIGNATURE_DST, b"").to_bytes();
    Signature::from_bytes(&bytes).unwrap()
}

fn public_key_from_secret(secret: &blst::min_pk::SecretKey) -> PublicKey {
    let key = secret.sk_to_pk().to_bytes();
    let proof = secret.sign(&key, PROOF_OF_POSSESSION_DST, b"").to_bytes();
    PublicKey::from_bytes_with_proof(&key, &proof).unwrap()
}
