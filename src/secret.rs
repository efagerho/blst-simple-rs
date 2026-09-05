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
    /// Dropping the key overwrites its owned scalar storage, but moves and
    /// compiler-generated temporaries may leave copies elsewhere. The caller
    /// is responsible for erasing the returned bytes.
    #[cfg(feature = "secret-key-export")]
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

#[cfg(test)]
impl SecretKey {
    pub(crate) fn to_bytes_for_test(&self) -> [u8; 32] {
        ffi::encode_scalar(&self.scalar)
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
    use core::mem::size_of;

    use std::format;

    use super::{KeyMaterialTooShortError, SecretKey, SecretKeyError};
    use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};
    use crate::test_util::{hex, hex_bytes};
    use crate::{HashedMessage, hierarchical, keygen};

    #[test]
    fn rejects_short_key_material() {
        let empty = [];
        let short = [7; 31];

        for key_material in [&empty[..], &short[..]] {
            let expected = KeyMaterialTooShortError {
                supplied: key_material.len(),
                minimum: 32,
            };

            assert_eq!(
                SecretKey::from_key_material(key_material).unwrap_err(),
                expected
            );
            assert_eq!(
                keygen::derive(key_material, keygen::Parameters::new(b"salt")).unwrap_err(),
                expected
            );
            assert_eq!(hierarchical::master(key_material).unwrap_err(), expected);
        }
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
        assert_eq!(secret_key.to_bytes_for_test(), largest_valid);
    }

    #[test]
    fn matches_hierarchical_derivation_vectors() {
        let cases = [
            (
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
                 1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070",
                0,
                "2d18bd6c14e6d15bf8b5085c9b74f3daae3b03cc2014770a599d8c1539e50f8e",
            ),
            (
                "3141592653589793238462643383279502884197169399375105820974944592",
                "41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7",
                3_141_592_653,
                "384843fad5f3d777ea39de3e47a8f999ae91f89e42bffa993d91d9782d152a0f",
            ),
            (
                "0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00",
                "3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80",
                u32::MAX,
                "40e86285582f35b28821340f6a53b448588efa575bc4d88c32ef8567b8d9479b",
            ),
            (
                "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                "2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca",
                42,
                "455c0dc9fccb3395825d92a60d2672d69416be1c2578a87a7a3d3ced11ebb88d",
            ),
        ];

        for (case_number, (seed, expected_master, child_index, expected_child)) in
            cases.into_iter().enumerate()
        {
            let seed = hex_bytes(seed);
            let expected_master = hex(expected_master);
            let expected_child = hex(expected_child);
            let master = hierarchical::master(&seed).unwrap();

            assert_eq!(
                master.to_bytes_for_test(),
                expected_master,
                "master key for test case {case_number}"
            );
            assert_eq!(
                SecretKey::from_key_material(&seed)
                    .unwrap()
                    .to_bytes_for_test(),
                expected_master,
                "master-key convenience API for test case {case_number}"
            );
            assert_eq!(
                hierarchical::child(&master, child_index).to_bytes_for_test(),
                expected_child,
                "child key for test case {case_number}"
            );
        }
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
        assert_eq!(informed.to_bytes_for_test(), upstream.to_bytes());

        assert_ne!(empty.to_bytes_for_test(), salted.to_bytes_for_test());
        assert_ne!(empty.to_bytes_for_test(), informed.to_bytes_for_test());

        let simple = SecretKey::from_key_material(&key_material).unwrap();
        let compatible =
            keygen::derive(&key_material, keygen::Parameters::compatibility()).unwrap();
        assert_eq!(simple.to_bytes_for_test(), compatible.to_bytes_for_test());
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

    #[cfg(feature = "secret-key-export")]
    #[test]
    fn exports_the_secret_scalar() {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let secret_key = SecretKey::from_bytes(&scalar).unwrap();

        assert_eq!(secret_key.to_bytes(), scalar);
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
        assert_eq!(public_key.verify_proof(&proof).unwrap(), public_key);
    }

    #[test]
    fn matches_chia_pop_known_answer_vector() {
        let scalar = hex("258787ef728c898e43bc76244d70f468c9c7e1338a107b18b42da0d86b663c26");
        let secret_key = SecretKey::from_bytes(&scalar).unwrap();
        let expected: [u8; 96] = hex(concat!(
            "84f709159435f0dc73b3e8bf6c78d85282d19231555a8ee3b6e2573aaf66872d92",
            "03fefa1ef",
            "700e34e7c3f3fb28210100558c6871c53f1ef6055b9f06b0d1abe22ad584ad3b95",
            "7f3018a8f5",
            "8227c6c716b1e15791459850f2289168fa0cf9115",
        ));
        let proof = secret_key.prove_possession();
        let public_key = secret_key.public_key();

        assert_eq!(proof.to_bytes(), expected);
        assert_eq!(public_key.verify_proof(&proof), Ok(public_key));
    }

    #[test]
    fn debug_is_redacted_and_representation_is_compact() {
        let secret_key = SecretKey::from_key_material(&[7; 32]).unwrap();

        assert_eq!(format!("{secret_key:?}"), "SecretKey(REDACTED)");
        assert_eq!(size_of::<SecretKey>(), 32);
    }

    #[test]
    fn errors_report_the_rejected_input() {
        assert_eq!(
            format!("{}", SecretKeyError::InvalidEncoding),
            "invalid secret-key encoding"
        );
        assert_eq!(
            format!(
                "{}",
                KeyMaterialTooShortError {
                    supplied: 31,
                    minimum: 32,
                }
            ),
            "key material is too short (supplied 31, minimum 32)"
        );
    }
}
