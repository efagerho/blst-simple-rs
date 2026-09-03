use core::fmt;

use crate::{
    AggregatePublicKey, AggregateSignature, HashedMessage, MissingBlstType, PreparedMessage,
    PublicKey, Signature,
};

impl Signature {
    /// Hashes and verifies a message for one signer.
    #[must_use]
    pub fn verify_message(&self, _key: &PublicKey, _message: &[u8]) -> bool {
        unimplemented!("signature verification requires BLST")
    }

    /// Verifies a previously hashed message for one signer.
    #[must_use]
    pub fn verify(&self, _key: &PublicKey, _message: &HashedMessage) -> bool {
        unimplemented!("signature verification requires BLST")
    }

    /// Verifies a prepared message for one signer.
    #[must_use]
    pub fn verify_prepared(&self, _key: &PublicKey, _message: &PreparedMessage) -> bool {
        unimplemented!("prepared signature verification requires BLST")
    }
}

impl AggregateSignature {
    /// Hashes and verifies one message against an aggregate public key.
    #[must_use]
    pub fn verify_message(&self, _key: &AggregatePublicKey, _message: &[u8]) -> bool {
        unimplemented!("aggregate-signature verification requires BLST")
    }

    /// Verifies one hashed message against an aggregate public key.
    #[must_use]
    pub fn verify(&self, _key: &AggregatePublicKey, _message: &HashedMessage) -> bool {
        unimplemented!("aggregate-signature verification requires BLST")
    }

    /// Verifies one prepared message against an aggregate public key.
    #[must_use]
    pub fn verify_prepared(&self, _key: &AggregatePublicKey, _message: &PreparedMessage) -> bool {
        unimplemented!("prepared aggregate-signature verification requires BLST")
    }

    /// Hashes and verifies one message after aggregating the supplied keys.
    ///
    /// The keys are aggregated on every call. When the same key set recurs,
    /// aggregate once with [`AggregatePublicKey::from_keys`] and use
    /// [`Self::verify_message`] instead.
    #[must_use]
    pub fn verify_message_with_keys(&self, _keys: &[PublicKey], _message: &[u8]) -> bool {
        unimplemented!("fast aggregate verification requires BLST")
    }

    /// Verifies one hashed message after aggregating the supplied keys.
    ///
    /// The keys are aggregated on every call. When the same key set recurs,
    /// aggregate once with [`AggregatePublicKey::from_keys`] and use
    /// [`Self::verify`] instead.
    #[must_use]
    pub fn verify_with_keys(&self, _keys: &[PublicKey], _message: &HashedMessage) -> bool {
        unimplemented!("fast aggregate verification requires BLST")
    }

    /// Verifies one prepared message after aggregating the supplied keys.
    ///
    /// The keys are aggregated on every call. When the same key set recurs,
    /// aggregate once with [`AggregatePublicKey::from_keys`] and use
    /// [`Self::verify_prepared`] instead.
    #[must_use]
    pub fn verify_prepared_with_keys(
        &self,
        _keys: &[PublicKey],
        _message: &PreparedMessage,
    ) -> bool {
        unimplemented!("prepared fast aggregate verification requires BLST")
    }

    /// Verifies a non-empty slice of aggregate-key/hashed-message groups.
    ///
    /// Multiple groups may contain the same message. Each group contributes a
    /// separate term to the pairing equation. Returns `false` for an empty
    /// slice.
    #[must_use]
    pub fn verify_groups(&self, _groups: &[(&AggregatePublicKey, &HashedMessage)]) -> bool {
        unimplemented!("multi-message aggregate verification requires BLST")
    }

    /// Verifies a non-empty slice of aggregate-key/prepared-message groups.
    ///
    /// Multiple groups may contain the same message. Each group contributes a
    /// separate term to the pairing equation. Returns `false` for an empty
    /// slice.
    #[must_use]
    pub fn verify_prepared_groups(
        &self,
        _groups: &[(&AggregatePublicKey, &PreparedMessage)],
    ) -> bool {
        unimplemented!("prepared multi-message aggregate verification requires BLST")
    }
}

/// An allocation-free streaming aggregate verifier.
///
/// The verifier accepts repeated messages and has no group-count capacity.
/// [`finish`](Self::finish) returns `false` if no groups were added.
pub struct AggregateVerifier {
    // Missing BLST types: `blst_p2_affine`, `blst_fp12`,
    // `[blst_p1_affine; 16]`, and `[blst_p2_affine; 16]`.
    _missing_blst_verification_state: MissingBlstType,
}

impl AggregateVerifier {
    /// Starts verification for an aggregate signature.
    #[must_use]
    pub fn new(_signature: &AggregateSignature) -> Self {
        unimplemented!("streaming aggregate verification requires BLST")
    }

    /// Adds one aggregate-key/hashed-message group.
    pub fn add(&mut self, _key: &AggregatePublicKey, _message: &HashedMessage) {
        unimplemented!("streaming aggregate verification requires BLST")
    }

    /// Adds one aggregate-key/prepared-message group.
    pub fn add_prepared(&mut self, _key: &AggregatePublicKey, _message: &PreparedMessage) {
        unimplemented!("prepared streaming aggregate verification requires BLST")
    }

    /// Adds aggregate-key/hashed-message groups in slice order.
    pub fn extend(&mut self, _groups: &[(&AggregatePublicKey, &HashedMessage)]) {
        unimplemented!("streaming aggregate verification requires BLST")
    }

    /// Adds aggregate-key/prepared-message groups in slice order.
    pub fn extend_prepared(&mut self, _groups: &[(&AggregatePublicKey, &PreparedMessage)]) {
        unimplemented!("prepared streaming aggregate verification requires BLST")
    }

    /// Flushes pending groups and decides the pairing equation.
    ///
    /// Returns `true` only if at least one group was added and the aggregate
    /// pairing equation holds. Returns `false` for an empty verifier or a
    /// failed pairing equation.
    #[must_use]
    pub fn finish(self) -> bool {
        unimplemented!("streaming aggregate verification requires BLST")
    }
}

impl fmt::Debug for AggregateVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateVerifier").finish_non_exhaustive()
    }
}
