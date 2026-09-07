//! Parameters for configurable BLS secret-key derivation.
//!
//! [`crate::SecretKey::from_key_material_with_parameters`] implements `KeyGen`
//! from *BLS Signatures* (`draft-irtf-cfrg-bls-signature-07`). The algorithm
//! uses HKDF-SHA-256 as defined by RFC 5869 and the octet-string-to-integer
//! conversion from RFC 8017.

use core::fmt;

/// Maximum number of application-context bytes accepted by
/// [`KeyGenerationParameters`].
///
/// BLST copies `key_info` and its length encoding into a variable-size native
/// stack buffer during key generation. This limit keeps caller-controlled
/// context from causing unbounded stack usage at the FFI boundary.
pub const MAX_KEY_INFO_LENGTH: usize = 1024;

/// `SHA-256("BLS-SIG-KEYGEN-SALT-")`.
const DRAFT04_COMPATIBILITY_SALT: [u8; 32] = [
    0xaf, 0xf1, 0xb7, 0x03, 0x64, 0x7f, 0xe4, 0xbd, 0x43, 0x3a, 0x89, 0x3a, 0x3d, 0x2b, 0xa5, 0x1a,
    0xbe, 0x26, 0xef, 0x79, 0x4a, 0x83, 0x56, 0xfe, 0xa6, 0x2e, 0x8e, 0x7c, 0x7c, 0x87, 0x75, 0x46,
];

/// Salt and application context for BLS `KeyGen`.
#[derive(Clone, Copy)]
pub struct KeyGenerationParameters<'a> {
    pub(crate) salt: &'a [u8],
    pub(crate) key_info: &'a [u8],
}

impl<'a> KeyGenerationParameters<'a> {
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

    /// Creates parameters using the draft-04 compatibility salt and empty
    /// `key_info`.
    ///
    /// This is the parameter set used by
    /// [`SecretKey::from_key_material`](crate::SecretKey::from_key_material).
    /// Use [`Self::with_info`] to retain that salt while supplying application
    /// context.
    #[must_use]
    pub const fn draft04_compatibility() -> Self {
        Self::new(&DRAFT04_COMPATIBILITY_SALT)
    }
}

impl fmt::Debug for KeyGenerationParameters<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGenerationParameters")
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

#[cfg(test)]
mod tests {
    use std::format;

    use super::{
        DRAFT04_COMPATIBILITY_SALT, KeyGenerationParameters, KeyInfoTooLongError,
        MAX_KEY_INFO_LENGTH,
    };
    use crate::SecretKey;

    #[test]
    fn explicit_parameters_match_blst() {
        let key_material = [42; 32];
        let cases = [
            ("empty salt and info", &b""[..], &b""[..]),
            ("salt only", &b"salt"[..], &b""[..]),
            ("info only", &b""[..], &b"context"[..]),
            ("salt and info", &b"salt"[..], &b"context"[..]),
        ];

        for (case, salt, key_info) in cases {
            let parameters = KeyGenerationParameters::new(salt)
                .with_info(key_info)
                .unwrap();
            let actual =
                SecretKey::from_key_material_with_parameters(&key_material, parameters).unwrap();
            let expected =
                blst::min_pk::SecretKey::key_gen_v5(&key_material, salt, key_info).unwrap();

            assert_eq!(actual.to_bytes(), expected.to_bytes(), "{case}");
        }
    }

    #[test]
    fn compatibility_parameters_match_default_key_generation() {
        let key_material = [42; 32];
        let context = *b"context";
        let default = SecretKey::from_key_material(&key_material).unwrap();
        let explicit = SecretKey::from_key_material_with_parameters(
            &key_material,
            KeyGenerationParameters::draft04_compatibility(),
        )
        .unwrap();

        assert_eq!(explicit.to_bytes(), default.to_bytes());

        let with_info = SecretKey::from_key_material_with_parameters(
            &key_material,
            KeyGenerationParameters::draft04_compatibility()
                .with_info(&context)
                .unwrap(),
        )
        .unwrap();
        let expected = blst::min_pk::SecretKey::key_gen_v5(
            &key_material,
            &DRAFT04_COMPATIBILITY_SALT,
            &context,
        )
        .unwrap();

        assert_eq!(with_info.to_bytes(), expected.to_bytes());
    }

    #[test]
    fn limits_key_info_length() {
        let maximum = [0; MAX_KEY_INFO_LENGTH];
        let parameters = KeyGenerationParameters::new(b"salt")
            .with_info(&maximum)
            .unwrap();
        let actual = SecretKey::from_key_material_with_parameters(&[42; 32], parameters).unwrap();
        let expected = blst::min_pk::SecretKey::key_gen_v5(&[42; 32], b"salt", &maximum).unwrap();

        assert_eq!(actual.to_bytes(), expected.to_bytes());

        let excessive = [0; MAX_KEY_INFO_LENGTH + 1];
        assert_eq!(
            KeyGenerationParameters::new(b"salt")
                .with_info(&excessive)
                .unwrap_err(),
            KeyInfoTooLongError {
                supplied: MAX_KEY_INFO_LENGTH + 1,
                maximum: MAX_KEY_INFO_LENGTH,
            }
        );
    }

    #[test]
    fn debug_reports_lengths_without_contents() {
        let parameters = KeyGenerationParameters::new(b"secret salt")
            .with_info(b"secret context")
            .unwrap();

        let debug = format!("{parameters:?}");

        assert_eq!(
            debug,
            "KeyGenerationParameters { salt_len: 11, key_info_len: 14 }"
        );
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn key_info_error_reports_supplied_and_maximum_lengths() {
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
