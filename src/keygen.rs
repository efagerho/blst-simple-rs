//! Configurable BLS secret-key derivation.
//!
//! This module exposes `KeyGen` from *BLS Signatures*
//! (`draft-irtf-cfrg-bls-signature-07`). The algorithm uses HKDF-SHA-256 as
//! defined by RFC 5869 and the octet-string-to-integer conversion from RFC
//! 8017.
//!
//! With [`Parameters::compatibility`], [`derive()`] produces the same key as
//! [`crate::hierarchical::master`] for the same input. Use different key
//! material or parameters when independent keys are required.

use core::fmt;

use crate::secret::validate_key_material_length;
use crate::{KeyMaterialTooShortError, SecretKey};

/// `SHA-256("BLS-SIG-KEYGEN-SALT-")`.
pub(crate) const COMPATIBILITY_SALT: [u8; 32] = [
    0xaf, 0xf1, 0xb7, 0x03, 0x64, 0x7f, 0xe4, 0xbd, 0x43, 0x3a, 0x89, 0x3a, 0x3d, 0x2b, 0xa5, 0x1a,
    0xbe, 0x26, 0xef, 0x79, 0x4a, 0x83, 0x56, 0xfe, 0xa6, 0x2e, 0x8e, 0x7c, 0x7c, 0x87, 0x75, 0x46,
];

/// Salt and application context for BLS `KeyGen`.
#[derive(Clone, Copy)]
pub struct Parameters<'a> {
    salt: &'a [u8],
    key_info: &'a [u8],
}

impl<'a> Parameters<'a> {
    /// Creates parameters with `salt` and empty `key_info`.
    ///
    /// *BLS Signatures* (`draft-irtf-cfrg-bls-signature-07`) permits an empty
    /// salt. For new protocols, it recommends a fixed, uniformly random
    /// 32-byte value.
    #[must_use]
    pub const fn new(salt: &'a [u8]) -> Self {
        Self {
            salt,
            key_info: &[],
        }
    }

    /// Sets the optional application-specific `key_info` bytes.
    ///
    /// Their interpretation is defined by the protocol using the key.
    #[must_use]
    pub const fn with_info(mut self, key_info: &'a [u8]) -> Self {
        self.key_info = key_info;
        self
    }
}

impl Parameters<'static> {
    /// Creates parameters matching [`SecretKey::from_key_material`].
    ///
    /// The salt is `SHA-256("BLS-SIG-KEYGEN-SALT-")`, which reproduces the
    /// output of `draft-irtf-cfrg-bls-signature-04`; `key_info` is empty. Use
    /// [`Self::with_info`] to derive context-specific keys from the same key
    /// material. Without key-info, this also matches
    /// [`crate::hierarchical::master`].
    #[must_use]
    pub const fn compatibility() -> Self {
        Self {
            salt: &COMPATIBILITY_SALT,
            key_info: &[],
        }
    }
}

impl fmt::Debug for Parameters<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parameters")
            .field("salt_len", &self.salt.len())
            .field("key_info_len", &self.key_info.len())
            .finish()
    }
}

/// Derives a BLS secret key with caller-supplied `KeyGen` parameters.
///
/// This implements `KeyGen` from *BLS Signatures*
/// (`draft-irtf-cfrg-bls-signature-07`) using HKDF-SHA-256 from RFC 5869.
/// `key_material` must contain at least 32 bytes, remain secret, and be
/// infeasible to guess. This function checks only its length.
pub fn derive(
    key_material: &[u8],
    parameters: Parameters<'_>,
) -> Result<SecretKey, KeyMaterialTooShortError> {
    validate_key_material_length(key_material)?;
    Ok(SecretKey::derive_key_material(
        key_material,
        parameters.salt,
        parameters.key_info,
    ))
}
