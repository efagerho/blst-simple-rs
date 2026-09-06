use core::hash::{Hash, Hasher};

use crate::DecodeError;
use crate::ffi::{self, G2Affine};

/// A decoded, subgroup-checked, non-identity proof of possession in G2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofOfPossession {
    pub(crate) point: G2Affine,
}

impl ProofOfPossession {
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

impl Hash for ProofOfPossession {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ffi::hash_g2(&self.point, state);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::ProofOfPossession;
    use crate::{HashedMessage, ffi};

    #[test]
    fn round_trips_a_valid_group_element() {
        let point = HashedMessage::new(b"valid subgroup point");
        let bytes = ffi::compress_g2(&point.point);
        let proof = ProofOfPossession::from_bytes(&bytes).unwrap();
        let decoded_again = ProofOfPossession::from_bytes(&proof.to_bytes()).unwrap();
        let mut proofs = HashMap::new();
        proofs.insert(proof, "valid");

        assert_eq!(proof.to_bytes(), bytes);
        assert_eq!(proof, decoded_again);
        assert_eq!(proofs.get(&decoded_again), Some(&"valid"));
    }
}
