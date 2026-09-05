use core::hash::{Hash, Hasher};

use crate::ffi::{self, G1Affine};
use crate::{DecodeError, InvalidProofError, ProofOfPossession, ProofVerificationError};

/// A decoded and subgroup-checked public key that has not proved possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnverifiedPublicKey {
    pub(crate) point: G1Affine,
}

impl UnverifiedPublicKey {
    /// Uncompresses, subgroup-checks, and rejects the identity.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, DecodeError> {
        ffi::decode_non_identity_g1(bytes).map(|point| Self { point })
    }

    /// Returns the canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        ffi::compress_g1(&self.point)
    }

    /// Verifies a proof of possession, returning this key with the
    /// verification capability on success.
    pub fn verify_proof(&self, proof: &ProofOfPossession) -> Result<PublicKey, InvalidProofError> {
        ffi::verify_proof(&self.point, &proof.point)
            .then_some(PublicKey { unverified: *self })
            .ok_or(InvalidProofError)
    }
}

impl Hash for UnverifiedPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ffi::hash_g1(&self.point, state);
    }
}

/// A public key carrying the capability that possession was verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    pub(crate) unverified: UnverifiedPublicKey,
}

impl core::ops::Deref for PublicKey {
    type Target = UnverifiedPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.unverified
    }
}

impl PublicKey {
    #[cfg(feature = "signing")]
    pub(crate) fn from_secret(point: G1Affine) -> Self {
        Self {
            unverified: UnverifiedPublicKey { point },
        }
    }

    /// Decodes a public key and proof, then verifies the proof of possession.
    pub fn from_bytes_with_proof(
        bytes: &[u8; 48],
        proof: &[u8; 96],
    ) -> Result<Self, ProofVerificationError> {
        let key = UnverifiedPublicKey::from_bytes(bytes)
            .map_err(ProofVerificationError::PublicKeyDecode)?;
        let proof =
            ProofOfPossession::from_bytes(proof).map_err(ProofVerificationError::ProofDecode)?;
        Ok(key.verify_proof(&proof)?)
    }

    /// Returns the canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        self.unverified.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{PublicKey, UnverifiedPublicKey};
    use crate::test_util::{public_key_and_proof_bytes, scalar};
    use crate::{DecodeError, InvalidProofError, ProofOfPossession, ProofVerificationError};

    #[test]
    fn round_trips_and_verifies_a_proved_key() {
        let (key_bytes, proof_bytes) = public_key_and_proof_bytes(scalar(1));
        let key = UnverifiedPublicKey::from_bytes(&key_bytes).unwrap();
        let decoded_again = UnverifiedPublicKey::from_bytes(&key.to_bytes()).unwrap();
        let proof = ProofOfPossession::from_bytes(&proof_bytes).unwrap();
        let verified = key.verify_proof(&proof).unwrap();
        let verified_again = decoded_again.verify_proof(&proof).unwrap();
        let mut keys = HashMap::new();
        keys.insert(verified, "verified");

        assert_eq!(key.to_bytes(), key_bytes);
        assert_eq!(key, decoded_again);
        assert_eq!(verified.to_bytes(), key_bytes);
        assert_eq!(&*verified, &key);
        assert_eq!(keys.get(&verified_again), Some(&"verified"));
    }

    #[test]
    fn rejects_bad_encoding_identity_curve_and_subgroup() {
        let uncompressed = [0; 48];
        let mut identity = [0; 48];
        identity[0] = 0xc0;
        let mut malformed_identity = identity;
        malformed_identity[47] = 1;
        let mut not_in_group = [0; 48];
        not_in_group[0] = 0x80;
        let mut not_on_curve = not_in_group;
        not_on_curve[47] = 1;
        let mut on_curve_outside_subgroup = not_in_group;
        on_curve_outside_subgroup[47] = 4;

        assert_eq!(
            UnverifiedPublicKey::from_bytes(&uncompressed).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&identity).unwrap_err(),
            DecodeError::PointAtInfinity
        );
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&malformed_identity).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&not_in_group).unwrap_err(),
            DecodeError::NotInGroup
        );
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&not_on_curve).unwrap_err(),
            DecodeError::NotOnCurve
        );
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&on_curve_outside_subgroup).unwrap_err(),
            DecodeError::NotInGroup
        );
    }

    #[test]
    fn rejects_a_proof_for_another_key() {
        let (key_bytes, _) = public_key_and_proof_bytes(scalar(1));
        let (_, proof_bytes) = public_key_and_proof_bytes(scalar(2));
        let key = UnverifiedPublicKey::from_bytes(&key_bytes).unwrap();
        let proof = ProofOfPossession::from_bytes(&proof_bytes).unwrap();

        assert_eq!(key.verify_proof(&proof), Err(InvalidProofError));
    }

    #[cfg(blst_simple_dangerous)]
    #[test]
    fn proof_bypass_preserves_the_admitted_key() {
        let (bytes, _) = public_key_and_proof_bytes(scalar(1));
        let unverified = UnverifiedPublicKey::from_bytes(&bytes).unwrap();

        let key = crate::dangerous::assume_proof_verified(unverified);

        assert_eq!(&*key, &unverified);
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn combined_constructor_preserves_error_context() {
        let (key_bytes, proof_bytes) = public_key_and_proof_bytes(scalar(1));
        let (_, wrong_proof) = public_key_and_proof_bytes(scalar(2));
        let bad_key = [0; 48];
        let bad_proof = [0; 96];

        assert_eq!(
            PublicKey::from_bytes_with_proof(&key_bytes, &proof_bytes)
                .unwrap()
                .to_bytes(),
            key_bytes
        );
        assert_eq!(
            PublicKey::from_bytes_with_proof(&bad_key, &proof_bytes).unwrap_err(),
            ProofVerificationError::PublicKeyDecode(DecodeError::BadEncoding)
        );
        assert_eq!(
            PublicKey::from_bytes_with_proof(&key_bytes, &bad_proof).unwrap_err(),
            ProofVerificationError::ProofDecode(DecodeError::BadEncoding)
        );
        assert_eq!(
            PublicKey::from_bytes_with_proof(&key_bytes, &wrong_proof).unwrap_err(),
            ProofVerificationError::InvalidProof
        );
    }
}
