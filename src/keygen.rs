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

/// Maximum number of application-context bytes accepted by [`Parameters`].
pub const MAX_KEY_INFO_LENGTH: usize = 1024;

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
    /// Their interpretation is defined by the protocol using the key. Returns
    /// an error when `key_info` exceeds [`MAX_KEY_INFO_LENGTH`].
    pub const fn with_info(mut self, key_info: &'a [u8]) -> Result<Self, KeyInfoTooLongError> {
        if key_info.len() > MAX_KEY_INFO_LENGTH {
            return Err(KeyInfoTooLongError {
                supplied: key_info.len(),
                maximum: MAX_KEY_INFO_LENGTH,
            });
        }

        self.key_info = key_info;
        Ok(self)
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

/// Application context exceeded the supported length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyInfoTooLongError {
    /// The number of bytes supplied by the caller.
    pub supplied: usize,
    /// The maximum accepted number of bytes.
    pub maximum: usize,
}

impl fmt::Display for KeyInfoTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "key info is too long (supplied {}, maximum {})",
            self.supplied, self.maximum
        )
    }
}

impl core::error::Error for KeyInfoTooLongError {}

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

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::{KeyInfoTooLongError, MAX_KEY_INFO_LENGTH, Parameters, derive};

    #[test]
    fn accepts_empty_salt_and_key_info() {
        let parameters = Parameters::new(b"").with_info(b"").unwrap();
        let actual = derive(&[42; 32], parameters).unwrap();
        let expected = blst::min_pk::SecretKey::key_gen_v5(&[42; 32], b"", b"").unwrap();

        assert_eq!(actual.to_bytes_for_test(), expected.to_bytes());
    }

    #[test]
    fn limits_key_info_length() {
        let maximum = [0; MAX_KEY_INFO_LENGTH];
        let parameters = Parameters::new(b"salt").with_info(&maximum).unwrap();
        let actual = derive(&[42; 32], parameters).unwrap();
        let expected = blst::min_pk::SecretKey::key_gen_v5(&[42; 32], b"salt", &maximum).unwrap();

        assert_eq!(actual.to_bytes_for_test(), expected.to_bytes());

        let excessive = [0; MAX_KEY_INFO_LENGTH + 1];
        assert_eq!(
            Parameters::new(b"salt").with_info(&excessive).unwrap_err(),
            KeyInfoTooLongError {
                supplied: MAX_KEY_INFO_LENGTH + 1,
                maximum: MAX_KEY_INFO_LENGTH,
            }
        );
    }

    #[test]
    fn debug_reports_lengths_without_contents() {
        let parameters = Parameters::new(b"secret salt")
            .with_info(b"secret context")
            .unwrap();

        let debug = format!("{parameters:?}");

        assert_eq!(debug, "Parameters { salt_len: 11, key_info_len: 14 }");
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn key_info_error_reports_both_limits() {
        let error = KeyInfoTooLongError {
            supplied: MAX_KEY_INFO_LENGTH + 1,
            maximum: MAX_KEY_INFO_LENGTH,
        };

        assert_eq!(
            format!("{error}"),
            "key info is too long (supplied 1025, maximum 1024)"
        );
    }
}
