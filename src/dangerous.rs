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

#[cfg(test)]
mod tests {
    use super::assume_proof_verified;
    use crate::UnverifiedPublicKey;

    #[test]
    fn preserves_the_admitted_key() {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let bytes = blst::min_pk::SecretKey::from_bytes(&scalar)
            .unwrap()
            .sk_to_pk()
            .to_bytes();
        let unverified = UnverifiedPublicKey::from_bytes(&bytes).unwrap();

        let key = assume_proof_verified(unverified);

        assert_eq!(key.as_unverified(), &unverified);
        assert_eq!(key.to_bytes(), bytes);
    }
}
