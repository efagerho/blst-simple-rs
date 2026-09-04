//! Hierarchical BLS secret-key derivation.
//!
//! This module implements `derive_master_SK` and `derive_child_SK` from
//! EIP-2333, *BLS12-381 Key Generation*. Its HKDF-based key generation uses
//! HKDF-SHA-256 as defined by RFC 5869.
//!
//! Master-key derivation matches [`SecretKey::from_key_material`] for the same
//! input. Child-key derivation is specific to EIP-2333.

use crate::{KeyMaterialTooShortError, SecretKey};

/// Derives a hierarchical master secret key from `seed`.
///
/// This implements `derive_master_SK` from EIP-2333, *BLS12-381 Key
/// Generation*. `seed` must contain at least 32 bytes and come from a
/// cryptographically secure source. This function checks only its length and
/// produces the same key as [`SecretKey::from_key_material`] for the same
/// bytes.
pub fn master(seed: &[u8]) -> Result<SecretKey, KeyMaterialTooShortError> {
    SecretKey::from_key_material(seed)
}

/// Derives the child secret key at `index`.
///
/// This implements `derive_child_SK` from EIP-2333, *BLS12-381 Key
/// Generation*. EIP-2333 child derivation is hardened: deriving a child
/// requires the parent secret key.
#[must_use]
pub fn child(parent: &SecretKey, index: u32) -> SecretKey {
    parent.derive_hierarchical_child(index)
}

#[cfg(test)]
mod tests {
    use super::child;
    use crate::SecretKey;

    #[test]
    fn derives_the_maximum_child_index() {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let parent = SecretKey::from_bytes(&scalar).unwrap();
        let upstream = blst::min_pk::SecretKey::from_bytes(&scalar).unwrap();

        assert_eq!(
            child(&parent, u32::MAX).to_bytes_for_test(),
            upstream.derive_child_eip2333(u32::MAX).to_bytes()
        );
    }
}
