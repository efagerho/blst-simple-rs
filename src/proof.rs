use crate::{DecodeError, MissingBlstType};

/// A decoded, subgroup-checked, non-identity proof of possession in G2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProofOfPossession {
    // Missing BLST type: `blst_p2_affine`.
    pub(crate) _missing_blst_p2_affine: MissingBlstType,
}

impl ProofOfPossession {
    /// Uncompresses, subgroup-checks, and rejects the identity.
    pub fn from_bytes(_bytes: &[u8; 96]) -> Result<Self, DecodeError> {
        unimplemented!("proof-of-possession decoding requires BLST")
    }

    /// Returns the canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        unimplemented!("proof-of-possession compression requires BLST")
    }
}
