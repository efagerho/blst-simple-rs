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

    /// Treats this key as though its proof of possession was verified.
    ///
    /// Bypassing proof verification can make aggregate signatures forgeable.
    /// The caller must have verified a valid proof for this exact key through
    /// another trusted mechanism.
    #[cfg(feature = "dangerous-proof-bypass")]
    #[must_use]
    pub fn assume_proof_verified(self) -> PublicKey {
        PublicKey { unverified: self }
    }
}

impl Hash for UnverifiedPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for coordinate in [&self.point.x, &self.point.y] {
            coordinate.l.hash(state);
        }
    }
}

/// A public key carrying the capability that possession was verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    pub(crate) unverified: UnverifiedPublicKey,
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

    /// Borrows the decoded key without its proof-verification capability.
    #[must_use]
    pub fn as_unverified(&self) -> &UnverifiedPublicKey {
        &self.unverified
    }
}

#[cfg(test)]
mod tests {
    use core::hash::{Hash, Hasher};

    use std::collections::hash_map::DefaultHasher;

    use super::{PublicKey, UnverifiedPublicKey};
    use crate::suite::PROOF_OF_POSSESSION_DST;
    use crate::{DecodeError, InvalidProofError, ProofOfPossession, ProofVerificationError};

    fn key_and_proof(key_material: [u8; 32]) -> ([u8; 48], [u8; 96]) {
        let secret_key =
            blst::min_pk::SecretKey::key_gen_v5(&key_material, b"test salt", b"").unwrap();
        let public_key = secret_key.sk_to_pk().to_bytes();
        let proof = secret_key
            .sign(&public_key, PROOF_OF_POSSESSION_DST, b"")
            .to_bytes();
        (public_key, proof)
    }

    fn hash(key: &UnverifiedPublicKey) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn round_trips_and_verifies_a_proved_key() {
        let (key_bytes, proof_bytes) = key_and_proof([1; 32]);
        let key = UnverifiedPublicKey::from_bytes(&key_bytes).unwrap();
        let decoded_again = UnverifiedPublicKey::from_bytes(&key.to_bytes()).unwrap();
        let proof = ProofOfPossession::from_bytes(&proof_bytes).unwrap();
        let verified = key.verify_proof(&proof).unwrap();

        assert_eq!(key.to_bytes(), key_bytes);
        assert_eq!(key, decoded_again);
        assert_eq!(hash(&key), hash(&decoded_again));
        assert_eq!(verified.to_bytes(), key_bytes);
        assert_eq!(verified.as_unverified(), &key);
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
        let (key_bytes, _) = key_and_proof([1; 32]);
        let (_, proof_bytes) = key_and_proof([2; 32]);
        let key = UnverifiedPublicKey::from_bytes(&key_bytes).unwrap();
        let proof = ProofOfPossession::from_bytes(&proof_bytes).unwrap();

        assert_eq!(key.verify_proof(&proof), Err(InvalidProofError));
    }

    #[cfg(feature = "dangerous-proof-bypass")]
    #[test]
    fn proof_bypass_preserves_the_admitted_key() {
        let (bytes, _) = key_and_proof([1; 32]);
        let unverified = UnverifiedPublicKey::from_bytes(&bytes).unwrap();

        let key = unverified.assume_proof_verified();

        assert_eq!(key.as_unverified(), &unverified);
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn combined_constructor_preserves_error_context() {
        let (key_bytes, proof_bytes) = key_and_proof([1; 32]);
        let (_, wrong_proof) = key_and_proof([2; 32]);
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
