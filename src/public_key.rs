use core::hash::{Hash, Hasher};

use crate::ffi::{self, G1Affine};
use crate::{DecodeError, InvalidProofError, ProofOfPossession, ProofVerificationError};

/// A decoded and subgroup-checked public key that has not proved possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnprovenPublicKey {
    pub(crate) point: G1Affine,
}

impl UnprovenPublicKey {
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
            .then_some(PublicKey { unproven: *self })
            .ok_or(InvalidProofError::VerificationFailed)
    }
}

impl Hash for UnprovenPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ffi::hash_g1_coordinates(&self.point, state);
    }
}

/// A public key carrying the capability that possession was verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    pub(crate) unproven: UnprovenPublicKey,
}

impl core::ops::Deref for PublicKey {
    type Target = UnprovenPublicKey;

    fn deref(&self) -> &Self::Target {
        &self.unproven
    }
}

impl PublicKey {
    #[cfg(feature = "signing")]
    pub(crate) fn from_secret_derived_point(point: G1Affine) -> Self {
        Self {
            unproven: UnprovenPublicKey { point },
        }
    }

    /// Decodes a public key and proof, then verifies the proof of possession.
    pub fn from_bytes_with_proof(
        bytes: &[u8; 48],
        proof: &[u8; 96],
    ) -> Result<Self, ProofVerificationError> {
        let key = UnprovenPublicKey::from_bytes(bytes)
            .map_err(ProofVerificationError::PublicKeyDecode)?;
        let proof =
            ProofOfPossession::from_bytes(proof).map_err(ProofVerificationError::ProofDecode)?;
        Ok(key.verify_proof(&proof)?)
    }

    /// Returns the canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        self.unproven.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{PublicKey, UnprovenPublicKey};
    use crate::test_util::{public_key_and_proof_bytes, scalar_bytes};
    use crate::{DecodeError, InvalidProofError, ProofOfPossession, ProofVerificationError};

    #[test]
    fn round_trips_and_verifies_a_proved_key() {
        let (key_bytes, proof_bytes) = public_key_and_proof_bytes(scalar_bytes(1));
        let key = UnprovenPublicKey::from_bytes(&key_bytes).unwrap();
        let decoded_again = UnprovenPublicKey::from_bytes(&key.to_bytes()).unwrap();
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
    fn rejects_a_proof_for_another_key() {
        let (key_bytes, _) = public_key_and_proof_bytes(scalar_bytes(1));
        let (_, proof_bytes) = public_key_and_proof_bytes(scalar_bytes(2));
        let key = UnprovenPublicKey::from_bytes(&key_bytes).unwrap();
        let proof = ProofOfPossession::from_bytes(&proof_bytes).unwrap();

        assert_eq!(
            key.verify_proof(&proof),
            Err(InvalidProofError::VerificationFailed)
        );
    }

    #[cfg(blst_simple_dangerous)]
    #[test]
    fn proof_bypass_matches_proof_verified_key_in_aggregate_verification() {
        let secret = scalar_bytes(1);
        let (bytes, proof_bytes) = public_key_and_proof_bytes(secret);
        let unproven = UnprovenPublicKey::from_bytes(&bytes).unwrap();
        let proof = ProofOfPossession::from_bytes(&proof_bytes).unwrap();
        let proof_verified = unproven.verify_proof(&proof).unwrap();
        let bypassed = crate::dangerous::assume_proof_verified(unproven);
        let message = b"message";
        let first_signature = crate::test_util::signature(secret, message);
        let (other_key, other_signature) = crate::test_util::participant(scalar_bytes(2), message);
        let mut signatures = crate::AggregateSignatureBuilder::new(&first_signature);
        signatures.add(&other_signature);
        let signature = signatures.finish();
        let proof_verified_keys = [proof_verified, other_key];
        let bypassed_keys = [bypassed, other_key];
        let proof_verified_result =
            signature.verify_message_with_keys(&proof_verified_keys, message);

        assert_eq!(&*bypassed, &unproven);
        assert_eq!(bypassed.to_bytes(), bytes);
        assert!(proof_verified_result);
        assert_eq!(
            signature.verify_message_with_keys(&bypassed_keys, message),
            proof_verified_result
        );
    }

    #[test]
    fn combined_constructor_preserves_error_context() {
        let (key_bytes, proof_bytes) = public_key_and_proof_bytes(scalar_bytes(1));
        let (_, wrong_proof) = public_key_and_proof_bytes(scalar_bytes(2));
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
