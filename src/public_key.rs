use crate::{
    DecodeError, InvalidProofError, MissingBlstType, ProofOfPossession, ProofVerificationError,
};

/// A decoded and subgroup-checked public key that has not proved possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnverifiedPublicKey {
    // Missing BLST type: `blst_p1_affine`.
    pub(crate) _missing_blst_p1_affine: MissingBlstType,
}

impl UnverifiedPublicKey {
    /// Uncompresses, subgroup-checks, and rejects the identity.
    pub fn from_bytes(_bytes: &[u8; 48]) -> Result<Self, DecodeError> {
        unimplemented!("public-key decoding requires BLST")
    }

    /// Returns the canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        unimplemented!("public-key compression requires BLST")
    }

    /// Verifies a proof of possession, returning this key with the
    /// verification capability on success.
    pub fn verify_proof(&self, _proof: &ProofOfPossession) -> Result<PublicKey, InvalidProofError> {
        unimplemented!("proof-of-possession verification requires BLST")
    }
}

/// A public key carrying the capability that possession was verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    pub(crate) unverified: UnverifiedPublicKey,
}

impl PublicKey {
    /// Decodes a public key and proof, then verifies the proof of possession.
    pub fn from_bytes_with_proof(
        _bytes: &[u8; 48],
        _proof: &[u8; 96],
    ) -> Result<Self, ProofVerificationError> {
        unimplemented!("public-key decoding and proof verification require BLST")
    }

    /// Returns the canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        unimplemented!("public-key compression requires BLST")
    }

    /// Borrows the decoded key without its proof-verification capability.
    #[must_use]
    pub fn as_unverified(&self) -> &UnverifiedPublicKey {
        &self.unverified
    }
}
