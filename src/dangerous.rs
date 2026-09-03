//! Proof-of-possession verification bypasses.

use crate::{PublicKey, UnverifiedPublicKey};

/// Admits a key whose proof of possession was verified by a trusted path.
///
/// The caller must have verified a valid proof for this exact key. Using an
/// unverified key can make aggregate signatures forgeable. Point decoding,
/// subgroup checking, and identity rejection are not bypassed.
#[must_use]
pub fn assume_proof_verified(key: UnverifiedPublicKey) -> PublicKey {
    PublicKey { unverified: key }
}
