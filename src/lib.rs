#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(missing_docs, missing_debug_implementations)]

//! Safe Rust API for the minimal-public-key-size proof-of-possession scheme in
//! *BLS Signatures* (`draft-irtf-cfrg-bls-signature-07`).
//!
//! Signatures use
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Proofs of possession use
//! `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

mod aggregate;
mod error;
mod ffi;
mod message;
mod proof;
mod public_key;
#[cfg(feature = "signing")]
mod secret;
mod signature;
mod suite;
#[cfg(test)]
mod test_util;
mod trait_assertions;
mod verify;

/// APIs that bypass validation enforced by the crate's safe types.
///
/// This module is available only when the crate is compiled with
/// `--cfg blst_simple_dangerous`.
#[cfg(blst_simple_dangerous)]
pub mod dangerous;
#[cfg(feature = "signing")]
pub mod hierarchical;
#[cfg(feature = "signing")]
pub mod keygen;

pub use aggregate::{
    AggregatePublicKey, AggregatePublicKeyBuilder, AggregateSignature, AggregateSignatureBuilder,
};
pub use error::{
    AggregateError, DecodeError, InvalidProofError, ProofVerificationError,
    TooManyDistinctMessagesError,
};
#[cfg(feature = "signing")]
pub use keygen::KeyInfoTooLongError;
pub use message::{HashedMessage, PreparedMessage};
pub use proof::ProofOfPossession;
pub use public_key::{PublicKey, UnverifiedPublicKey};
#[cfg(feature = "signing")]
pub use secret::{KeyMaterialTooShortError, SecretKey, SecretKeyError};
pub use signature::Signature;
pub use verify::AggregateVerifier;
