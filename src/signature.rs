use crate::{DecodeError, MissingBlstType};

/// A decoded, subgroup-checked, non-identity signature in G2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    // Missing BLST type: `blst_p2_affine`.
    pub(crate) _missing_blst_p2_affine: MissingBlstType,
}

impl Signature {
    /// Uncompresses, subgroup-checks, and rejects the identity.
    pub fn from_bytes(_bytes: &[u8; 96]) -> Result<Self, DecodeError> {
        unimplemented!("signature decoding requires BLST")
    }

    /// Returns the canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        unimplemented!("signature compression requires BLST")
    }
}
