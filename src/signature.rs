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
    use crate::DecodeError;
    use crate::suite::SIGNATURE_DST;

    fn signature_bytes() -> [u8; 96] {
        blst::min_pk::SecretKey::key_gen_v5(&[1; 32], b"test salt", b"")
            .unwrap()
            .sign(b"message", SIGNATURE_DST, b"")
            .to_bytes()
    }

    #[test]
    fn round_trips_a_valid_signature() {
        let bytes = signature_bytes();
        let signature = Signature::from_bytes(&bytes).unwrap();
        let decoded_again = Signature::from_bytes(&signature.to_bytes()).unwrap();
        let mut signatures = HashMap::new();
        signatures.insert(signature, "valid");

        assert_eq!(signature.to_bytes(), bytes);
        assert_eq!(signature, decoded_again);
        assert_eq!(signatures.get(&decoded_again), Some(&"valid"));
    }

    #[test]
    fn rejects_bad_encoding_and_identity() {
        let uncompressed = [0; 96];
        let mut identity = [0; 96];
        identity[0] = 0xc0;
        let mut malformed_identity = identity;
        malformed_identity[95] = 1;

        assert_eq!(
            Signature::from_bytes(&uncompressed).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            Signature::from_bytes(&identity).unwrap_err(),
            DecodeError::PointAtInfinity
        );
        assert_eq!(
            Signature::from_bytes(&malformed_identity).unwrap_err(),
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
            Signature::from_bytes(&not_on_curve).unwrap_err(),
            DecodeError::NotOnCurve
        );
        assert_eq!(
            Signature::from_bytes(&not_in_group).unwrap_err(),
            DecodeError::NotInGroup
        );
    }
}
