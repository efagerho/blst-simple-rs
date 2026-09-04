//! APIs that bypass validation enforced by the crate's safe types.

use crate::{PublicKey, UnverifiedPublicKey};

/// Treats a public key as though its proof of possession was verified.
///
/// Bypassing proof verification can make aggregate signatures forgeable. The
/// caller must have verified a valid proof for this exact key through another
/// trusted mechanism.
#[must_use]
pub fn assume_proof_verified(key: UnverifiedPublicKey) -> PublicKey {
    PublicKey { unverified: key }
}
