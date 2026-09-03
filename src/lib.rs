#![no_std]
// Stub phase: constants and helpers are wired up only when the BLST
// implementations land. Dead-code and unused warnings are noise until then.
// TODO: remove this allow together with the last `unimplemented!()`.
#![allow(dead_code)]

//! Safe Rust API for the minimal-public-key-size proof-of-possession scheme in
//! *BLS Signatures* (`draft-irtf-cfrg-bls-signature-07`).
//!
//! Signatures use
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Proofs of possession use
//! `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.
//!
//! BLST bindings are omitted. Operations that require BLST panic with
//! `unimplemented!()`.

extern crate alloc;

mod aggregate;
mod error;
mod message;
mod proof;
mod public_key;
#[cfg(feature = "signing")]
mod secret;
mod signature;
mod suite;
mod verify;

pub mod dangerous;
#[cfg(feature = "signing")]
pub mod hierarchical;
#[cfg(feature = "signing")]
pub mod keygen;

pub use aggregate::{
    AggregatePublicKey, AggregatePublicKeyBuilder, AggregateSignature, AggregateSignatureBuilder,
};
pub use error::{AggregateError, DecodeError, InvalidProofError, ProofVerificationError};
pub use message::{HashedMessage, PreparedMessage};
pub use proof::ProofOfPossession;
pub use public_key::{PublicKey, UnverifiedPublicKey};
#[cfg(feature = "signing")]
pub use secret::{KeyMaterialTooShortError, SecretKey, SecretKeyError};
pub use signature::Signature;
pub use verify::AggregateVerifier;

/// Internal placeholder for omitted BLST value representations.
///
/// Private fields of this type keep the public wrapper types opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MissingBlstType;
