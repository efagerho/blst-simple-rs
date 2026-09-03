use core::fmt;

use crate::{HashedMessage, MissingBlstType, ProofOfPossession, PublicKey, Signature};

pub(crate) const MINIMUM_KEY_MATERIAL_LENGTH: usize = 32;

/// A secret scalar suitable for BLS signing.
///
/// Use [`Self::from_key_material`] for `KeyGen` with the draft-04 compatibility
/// salt, [`crate::keygen::derive`] for explicit parameters,
/// [`crate::hierarchical`] for EIP-2333 derivation, or [`Self::from_bytes`] to
/// import a scalar.
#[derive(Clone)]
pub struct SecretKey {
    // Missing BLST type: `blst_scalar`.
    _missing_blst_scalar: MissingBlstType,
}

impl SecretKey {
    /// Derives a BLS secret key from secret key material.
    ///
    /// This applies `KeyGen` from *BLS Signatures*
    /// (`draft-irtf-cfrg-bls-signature-07`) using HKDF-SHA-256 as defined by
    /// RFC 5869, empty `key_info`, and
    /// `SHA-256("BLS-SIG-KEYGEN-SALT-")` as the salt. That salt reproduces the
    /// output of `draft-irtf-cfrg-bls-signature-04`.
    ///
    /// `key_material` must contain at least 32 bytes, remain secret, and be
    /// infeasible to guess. This method checks only its length. Use
    /// [`crate::keygen::derive`] when the protocol specifies a salt or key-info.
    /// For the same bytes, this produces the same key as
    /// [`crate::hierarchical::master`].
    pub fn from_key_material(key_material: &[u8]) -> Result<Self, KeyMaterialTooShortError> {
        validate_key_material_length(key_material)?;
        Ok(Self::derive_key_material(
            key_material,
            &crate::keygen::COMPATIBILITY_SALT,
            &[],
        ))
    }

    /// Imports a canonical, nonzero big-endian scalar.
    pub fn from_bytes(_bytes: &[u8; 32]) -> Result<Self, SecretKeyError> {
        unimplemented!("secret-key decoding requires BLST")
    }

    /// Exports this scalar as 32 big-endian bytes.
    // TODO: probably hide this behind a dedicated feature enabled only by
    // special tooling, for instance offline key generation for later import,
    // so ordinary builds cannot export secret scalars at all.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        unimplemented!("secret-key encoding requires BLST")
    }

    /// Derives the corresponding proof-capable public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        unimplemented!("public-key derivation requires BLST")
    }

    /// Hashes and signs arbitrary message bytes.
    #[must_use]
    pub fn sign_message(&self, _message: &[u8]) -> Signature {
        unimplemented!("message signing requires BLST")
    }

    /// Signs an already hashed message.
    #[must_use]
    pub fn sign(&self, _message: &HashedMessage) -> Signature {
        unimplemented!("hashed-message signing requires BLST")
    }

    /// Produces a proof of possession for the corresponding public key.
    #[must_use]
    pub fn prove_possession(&self) -> ProofOfPossession {
        unimplemented!("proof-of-possession generation requires BLST")
    }

    pub(crate) fn derive_key_material(
        _key_material: &[u8],
        _salt: &[u8],
        _key_info: &[u8],
    ) -> Self {
        unimplemented!("BLS KeyGen requires BLST")
    }

    pub(crate) fn derive_hierarchical_child(&self, _index: u32) -> Self {
        unimplemented!("EIP-2333 child-key derivation requires BLST")
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // `MissingBlstType` has no secret bytes. A BLST-backed implementation
        // must erase its scalar here.
    }
}

/// An error encountered while decoding a serialized secret scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretKeyError {
    /// The bytes encode zero or a value outside the scalar field.
    InvalidEncoding,
}

impl fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => f.write_str("invalid secret-key encoding"),
        }
    }
}

/// Key material did not meet an algorithm's minimum byte length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyMaterialTooShortError {
    /// The number of bytes supplied by the caller.
    pub supplied: usize,
    /// The minimum accepted number of bytes.
    pub minimum: usize,
}

impl fmt::Display for KeyMaterialTooShortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "key material is too short (supplied {}, minimum {})",
            self.supplied, self.minimum
        )
    }
}

#[cfg(feature = "std")]
impl core::error::Error for SecretKeyError {}

#[cfg(feature = "std")]
impl core::error::Error for KeyMaterialTooShortError {}

pub(crate) fn validate_key_material_length(bytes: &[u8]) -> Result<(), KeyMaterialTooShortError> {
    if bytes.len() < MINIMUM_KEY_MATERIAL_LENGTH {
        Err(KeyMaterialTooShortError {
            supplied: bytes.len(),
            minimum: MINIMUM_KEY_MATERIAL_LENGTH,
        })
    } else {
        Ok(())
    }
}
