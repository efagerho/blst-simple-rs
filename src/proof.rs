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
        for coordinate in [&self.point.x, &self.point.y] {
            for component in &coordinate.fp {
                component.l.hash(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::hash::{Hash, Hasher};

    use std::collections::hash_map::DefaultHasher;

    use super::ProofOfPossession;
    use crate::{DecodeError, HashedMessage, ffi};

    fn hash(proof: &ProofOfPossession) -> u64 {
        let mut hasher = DefaultHasher::new();
        proof.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn round_trips_a_valid_group_element() {
        let point = HashedMessage::new(b"valid subgroup point");
        let bytes = ffi::compress_g2(&point.point);
        let proof = ProofOfPossession::from_bytes(&bytes).unwrap();
        let decoded_again = ProofOfPossession::from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(proof.to_bytes(), bytes);
        assert_eq!(proof, decoded_again);
        assert_eq!(hash(&proof), hash(&decoded_again));
    }

    #[test]
    fn rejects_bad_encoding_and_identity() {
        let uncompressed = [0; 96];
        let mut identity = [0; 96];
        identity[0] = 0xc0;
        let mut malformed_identity = identity;
        malformed_identity[95] = 1;

        assert_eq!(
            ProofOfPossession::from_bytes(&uncompressed).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            ProofOfPossession::from_bytes(&identity).unwrap_err(),
            DecodeError::PointAtInfinity
        );
        assert_eq!(
            ProofOfPossession::from_bytes(&malformed_identity).unwrap_err(),
            DecodeError::BadEncoding
        );
    }

    #[test]
    fn rejects_points_outside_the_curve_and_subgroup() {
        let mut not_on_curve = [0; 96];
        not_on_curve[0] = 0x80;

        let mut not_in_group = not_on_curve;
        not_in_group[95] = 2;

        assert_eq!(
            ProofOfPossession::from_bytes(&not_on_curve).unwrap_err(),
            DecodeError::NotOnCurve
        );
        assert_eq!(
            ProofOfPossession::from_bytes(&not_in_group).unwrap_err(),
            DecodeError::NotInGroup
        );
    }
}
