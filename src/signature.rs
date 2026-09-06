use core::hash::{Hash, Hasher};

use crate::DecodeError;
use crate::ffi::{self, G2Affine};

/// A decoded, subgroup-checked, non-identity signature in G2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) point: G2Affine,
}

impl Signature {
    /// Uncompresses, subgroup-checks, and rejects the identity.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, DecodeError> {
        ffi::decode_non_identity_g2(bytes).map(|point| Self { point })
    }

    /// Returns the canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        ffi::compress_g2(&self.point)
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ffi::hash_g2(&self.point, state);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Signature;
    use crate::test_util::{scalar, signature_bytes};

    #[test]
    fn round_trips_a_valid_signature() {
        let bytes = signature_bytes(scalar(1), b"message");
        let signature = Signature::from_bytes(&bytes).unwrap();
        let decoded_again = Signature::from_bytes(&signature.to_bytes()).unwrap();
        let mut signatures = HashMap::new();
        signatures.insert(signature, "valid");

        assert_eq!(signature.to_bytes(), bytes);
        assert_eq!(signature, decoded_again);
        assert_eq!(signatures.get(&decoded_again), Some(&"valid"));
    }
}
