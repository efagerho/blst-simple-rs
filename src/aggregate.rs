use core::fmt;

use crate::{AggregateError, DecodeError, MissingBlstType, PublicKey, Signature};

/// A decoded aggregate signature in G2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AggregateSignature {
    // Missing BLST type: `blst_p2_affine`.
    pub(crate) _missing_blst_p2_affine: MissingBlstType,
}

impl AggregateSignature {
    /// Uncompresses and subgroup-checks an aggregate signature, allowing the
    /// identity.
    pub fn from_bytes(_bytes: &[u8; 96]) -> Result<Self, DecodeError> {
        unimplemented!("aggregate-signature decoding requires BLST")
    }

    /// Returns the canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        unimplemented!("aggregate-signature compression requires BLST")
    }
}

impl From<&Signature> for AggregateSignature {
    /// Converts one signature into a one-element aggregate.
    fn from(_signature: &Signature) -> Self {
        unimplemented!("signature aggregation requires BLST")
    }
}

impl From<Signature> for AggregateSignature {
    /// Converts one signature into a one-element aggregate.
    fn from(signature: Signature) -> Self {
        Self::from(&signature)
    }
}

/// A non-empty projective signature accumulator.
#[derive(Clone)]
pub struct AggregateSignatureBuilder {
    // Missing BLST type: `blst_p2`.
    _missing_blst_p2: MissingBlstType,
}

impl AggregateSignatureBuilder {
    /// Starts an accumulator with one signature.
    #[must_use]
    pub fn new(_first: &Signature) -> Self {
        unimplemented!("signature aggregation requires BLST")
    }

    /// Starts an accumulator from an existing aggregate signature.
    #[must_use]
    pub fn from_aggregate(_first: &AggregateSignature) -> Self {
        unimplemented!("signature aggregation requires BLST")
    }

    /// Adds one signature to the accumulator.
    pub fn add(&mut self, _signature: &Signature) {
        unimplemented!("signature aggregation requires BLST")
    }

    /// Adds one existing aggregate signature to the accumulator.
    pub fn add_aggregate(&mut self, _aggregate: &AggregateSignature) {
        unimplemented!("signature aggregation requires BLST")
    }

    /// Adds all signatures in encounter order.
    pub fn extend(&mut self, _signatures: &[Signature]) {
        unimplemented!("signature aggregation requires BLST")
    }

    /// Adds all aggregate signatures in encounter order.
    pub fn extend_aggregates(&mut self, _aggregates: &[AggregateSignature]) {
        unimplemented!("signature aggregation requires BLST")
    }

    /// Converts this non-empty accumulator to an affine aggregate signature.
    #[must_use]
    pub fn finish(self) -> AggregateSignature {
        unimplemented!("signature aggregation requires BLST")
    }
}

impl fmt::Debug for AggregateSignatureBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateSignatureBuilder")
            .finish_non_exhaustive()
    }
}

/// An aggregate of public keys that all carry proof-verification capability.
///
/// This type is intentionally not serializable: its value alone cannot prove
/// that every summand supplied a proof of possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AggregatePublicKey {
    // Missing BLST type: `blst_p1_affine`.
    pub(crate) _missing_blst_p1_affine: MissingBlstType,
}

impl AggregatePublicKey {
    /// Aggregates a key slice, returning an error for empty input or when the
    /// sum cancels to the identity.
    pub fn from_keys(_keys: &[PublicKey]) -> Result<Self, AggregateError> {
        unimplemented!("public-key aggregation requires BLST")
    }
}

impl From<&PublicKey> for AggregatePublicKey {
    /// Converts one proof-verified public key into a one-element aggregate.
    fn from(_key: &PublicKey) -> Self {
        unimplemented!("public-key aggregation requires BLST")
    }
}

impl From<PublicKey> for AggregatePublicKey {
    /// Converts one proof-verified public key into a one-element aggregate.
    fn from(key: PublicKey) -> Self {
        Self::from(&key)
    }
}

/// A non-empty projective public-key accumulator.
#[derive(Clone)]
pub struct AggregatePublicKeyBuilder {
    // Missing BLST type: `blst_p1`.
    _missing_blst_p1: MissingBlstType,
}

impl AggregatePublicKeyBuilder {
    /// Starts an accumulator with one proof-verified public key.
    #[must_use]
    pub fn new(_first: &PublicKey) -> Self {
        unimplemented!("public-key aggregation requires BLST")
    }

    /// Starts an accumulator from an existing aggregate public key.
    #[must_use]
    pub fn from_aggregate(_first: &AggregatePublicKey) -> Self {
        unimplemented!("public-key aggregation requires BLST")
    }

    /// Adds one proof-verified public key.
    pub fn add(&mut self, _key: &PublicKey) {
        unimplemented!("public-key aggregation requires BLST")
    }

    /// Adds one existing aggregate public key.
    pub fn add_aggregate(&mut self, _aggregate: &AggregatePublicKey) {
        unimplemented!("public-key aggregation requires BLST")
    }

    /// Adds all proof-verified public keys in encounter order.
    pub fn extend(&mut self, _keys: &[PublicKey]) {
        unimplemented!("public-key aggregation requires BLST")
    }

    /// Adds all aggregate public keys in encounter order.
    pub fn extend_aggregates(&mut self, _aggregates: &[AggregatePublicKey]) {
        unimplemented!("public-key aggregation requires BLST")
    }

    /// Finishes the aggregate, rejecting a sum that is the identity.
    pub fn finish(self) -> Result<AggregatePublicKey, AggregateError> {
        unimplemented!("public-key aggregation requires BLST")
    }
}

impl fmt::Debug for AggregatePublicKeyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregatePublicKeyBuilder")
            .finish_non_exhaustive()
    }
}
