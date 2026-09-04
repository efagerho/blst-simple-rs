use core::fmt;

use crate::ffi::{self, Scalar};
use crate::{HashedMessage, ProofOfPossession, PublicKey, Signature};

pub(crate) const MINIMUM_KEY_MATERIAL_LENGTH: usize = 32;

/// A secret scalar suitable for BLS signing.
///
/// Use [`Self::from_key_material`] for `KeyGen` with the draft-04 compatibility
/// salt, [`crate::keygen::derive`] for explicit parameters,
/// [`crate::hierarchical`] for EIP-2333 derivation, or [`Self::from_bytes`] to
/// import a scalar.
#[derive(Clone)]
pub struct SecretKey {
    scalar: Scalar,
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
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SecretKeyError> {
        ffi::decode_scalar(bytes)
            .map(|scalar| Self { scalar })
            .ok_or(SecretKeyError::InvalidEncoding)
    }

    /// Exports this scalar as 32 big-endian bytes.
    ///
    /// The caller is responsible for erasing the returned bytes.
    // TODO: probably hide this behind a dedicated feature enabled only by
    // special tooling, for instance offline key generation for later import,
    // so ordinary builds cannot export secret scalars at all.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        ffi::encode_scalar(&self.scalar)
    }

    /// Derives the corresponding proof-capable public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret(ffi::derive_public_key(&self.scalar))
    }

    /// Hashes and signs arbitrary message bytes.
    #[must_use]
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        Signature {
            point: ffi::sign_message(&self.scalar, message),
        }
    }

    /// Signs an already hashed message.
    #[must_use]
    pub fn sign(&self, message: &HashedMessage) -> Signature {
        Signature {
            point: ffi::sign_hashed_message(&self.scalar, &message.point),
        }
    }

    /// Produces a proof of possession for the corresponding public key.
    #[must_use]
    pub fn prove_possession(&self) -> ProofOfPossession {
        ProofOfPossession {
            point: ffi::prove_possession(&self.scalar),
        }
    }

    pub(crate) fn derive_key_material(key_material: &[u8], salt: &[u8], key_info: &[u8]) -> Self {
        Self {
            scalar: ffi::derive_key_material(key_material, salt, key_info),
        }
    }

    pub(crate) fn derive_hierarchical_child(&self, index: u32) -> Self {
        Self {
            scalar: ffi::derive_hierarchical_child(&self.scalar, index),
        }
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        ffi::zeroize_scalar(&mut self.scalar);
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

impl core::error::Error for SecretKeyError {}

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

#[cfg(test)]
mod tests {
    extern crate std;

    use core::mem::size_of;

    use std::format;

    use super::{KeyMaterialTooShortError, SecretKey, SecretKeyError};
    use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};
    use crate::{HashedMessage, hierarchical, keygen};

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hexadecimal digit"),
            }
        }

        assert_eq!(input.len(), N * 2);
        let mut output = [0; N];
        for (byte, digits) in output.iter_mut().zip(input.as_bytes().chunks_exact(2)) {
            *byte = (nibble(digits[0]) << 4) | nibble(digits[1]);
        }
        output
    }

    #[test]
    fn rejects_short_key_material() {
        let key_material = [7; 31];
        let expected = KeyMaterialTooShortError {
            supplied: 31,
            minimum: 32,
        };

        assert_eq!(
            SecretKey::from_key_material(&key_material).unwrap_err(),
            expected
        );
        assert_eq!(
            keygen::derive(&key_material, keygen::Parameters::new(b"salt")).unwrap_err(),
            expected
        );
        assert_eq!(hierarchical::master(&key_material).unwrap_err(), expected);
    }

    #[test]
    fn validates_canonical_scalar_encodings() {
        let zero = [0; 32];
        let order = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        let largest_valid = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");

        assert!(matches!(
            SecretKey::from_bytes(&zero),
            Err(SecretKeyError::InvalidEncoding)
        ));
        assert!(matches!(
            SecretKey::from_bytes(&order),
            Err(SecretKeyError::InvalidEncoding)
        ));

        let secret_key = SecretKey::from_bytes(&largest_valid).unwrap();
        assert_eq!(secret_key.to_bytes(), largest_valid);
    }

    #[test]
    fn matches_hierarchical_derivation_vector() {
        let seed: [u8; 64] = hex(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        );
        let expected_master =
            hex("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let expected_child =
            hex("2d18bd6c14e6d15bf8b5085c9b74f3daae3b03cc2014770a599d8c1539e50f8e");

        let master = hierarchical::master(&seed).unwrap();
        assert_eq!(master.to_bytes(), expected_master);
        assert_eq!(
            SecretKey::from_key_material(&seed).unwrap().to_bytes(),
            expected_master
        );
        assert_eq!(hierarchical::child(&master, 0).to_bytes(), expected_child);
    }

    #[test]
    fn configurable_key_generation_forwards_all_parameters() {
        let key_material = [42; 32];
        let empty = keygen::derive(&key_material, keygen::Parameters::new(b"")).unwrap();
        let salted = keygen::derive(&key_material, keygen::Parameters::new(b"salt")).unwrap();
        let informed = keygen::derive(
            &key_material,
            keygen::Parameters::new(b"").with_info(b"context").unwrap(),
        )
        .unwrap();

        let upstream = blst::min_pk::SecretKey::key_gen_v5(&key_material, b"", b"context").unwrap();
        assert_eq!(informed.to_bytes(), upstream.to_bytes());

        assert_ne!(empty.to_bytes(), salted.to_bytes());
        assert_ne!(empty.to_bytes(), informed.to_bytes());

        let simple = SecretKey::from_key_material(&key_material).unwrap();
        let compatible =
            keygen::derive(&key_material, keygen::Parameters::compatibility()).unwrap();
        assert_eq!(simple.to_bytes(), compatible.to_bytes());
    }

    #[test]
    fn derives_the_public_key() {
        let scalar = hex("0000000000000000000000000000000000000000000000000000000000000001");
        let secret_key = SecretKey::from_bytes(&scalar).unwrap();
        let upstream = blst::min_pk::SecretKey::from_bytes(&scalar).unwrap();

        assert_eq!(
            secret_key.public_key().to_bytes(),
            upstream.sk_to_pk().to_bytes()
        );
    }

    #[test]
    fn signs_raw_and_hashed_messages() {
        let scalar = hex("000000000000000000000000000000000000000000000000000000000000002a");
        let secret_key = SecretKey::from_bytes(&scalar).unwrap();
        let upstream = blst::min_pk::SecretKey::from_bytes(&scalar).unwrap();

        for message in [&b""[..], &b"a\0\xffb"[..]] {
            let expected = upstream.sign(message, SIGNATURE_DST, b"").to_bytes();
            let hashed = HashedMessage::new(message);

            assert_eq!(secret_key.sign_message(message).to_bytes(), expected);
            assert_eq!(secret_key.sign(&hashed).to_bytes(), expected);
        }
    }

    #[test]
    fn proves_possession_of_the_public_key() {
        let scalar = hex("000000000000000000000000000000000000000000000000000000000000002a");
        let secret_key = SecretKey::from_bytes(&scalar).unwrap();
        let upstream = blst::min_pk::SecretKey::from_bytes(&scalar).unwrap();
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes();
        let proof = secret_key.prove_possession();
        let expected = upstream
            .sign(&public_key_bytes, PROOF_OF_POSSESSION_DST, b"")
            .to_bytes();

        assert_eq!(proof.to_bytes(), expected);
        assert_eq!(
            public_key.as_unverified().verify_proof(&proof).unwrap(),
            public_key
        );
    }

    #[test]
    fn debug_is_redacted_and_representation_is_compact() {
        let secret_key = SecretKey::from_key_material(&[7; 32]).unwrap();

        assert_eq!(format!("{secret_key:?}"), "SecretKey(REDACTED)");
        assert_eq!(size_of::<SecretKey>(), 32);
    }
}
