use core::fmt;

use crate::ffi::{self, G1Affine, G2Affine, MILLER_LOOP_BATCH_SIZE, MillerLoopResult};
use crate::{
    AggregatePublicKey, AggregateSignature, HashedMessage, PreparedMessage, PublicKey, Signature,
};

impl Signature {
    /// Hashes and verifies a message for one signer.
    #[must_use]
    pub fn verify_message(&self, key: &PublicKey, message: &[u8]) -> bool {
        self.verify(key, &HashedMessage::new(message))
    }

    /// Verifies a previously hashed message for one signer.
    #[must_use]
    pub fn verify(&self, key: &PublicKey, message: &HashedMessage) -> bool {
        ffi::verify_signature(&key.unverified.point, &message.point, &self.point)
    }

    /// Verifies a prepared message for one signer.
    #[must_use]
    pub fn verify_prepared(&self, key: &PublicKey, message: &PreparedMessage) -> bool {
        ffi::verify_prepared_signature(&key.unverified.point, &message.lines, &self.point)
    }
}

impl AggregateSignature {
    /// Hashes and verifies one message against an aggregate public key.
    #[must_use]
    pub fn verify_message(&self, key: &AggregatePublicKey, message: &[u8]) -> bool {
        self.verify(key, &HashedMessage::new(message))
    }

    /// Verifies one hashed message against an aggregate public key.
    #[must_use]
    pub fn verify(&self, key: &AggregatePublicKey, message: &HashedMessage) -> bool {
        ffi::verify_signature(&key.point, &message.point, &self.point)
    }

    /// Verifies one prepared message against an aggregate public key.
    #[must_use]
    pub fn verify_prepared(&self, key: &AggregatePublicKey, message: &PreparedMessage) -> bool {
        ffi::verify_prepared_signature(&key.point, &message.lines, &self.point)
    }

    /// Hashes and verifies one message after aggregating the supplied keys.
    ///
    /// The keys are aggregated on every call. When the same key set recurs,
    /// aggregate once with [`AggregatePublicKey::from_keys`] and use
    /// [`Self::verify_message`] instead.
    #[must_use]
    pub fn verify_message_with_keys(&self, keys: &[PublicKey], message: &[u8]) -> bool {
        AggregatePublicKey::from_keys(keys).is_ok_and(|key| self.verify_message(&key, message))
    }

    /// Verifies one hashed message after aggregating the supplied keys.
    ///
    /// The keys are aggregated on every call. When the same key set recurs,
    /// aggregate once with [`AggregatePublicKey::from_keys`] and use
    /// [`Self::verify`] instead.
    #[must_use]
    pub fn verify_with_keys(&self, keys: &[PublicKey], message: &HashedMessage) -> bool {
        AggregatePublicKey::from_keys(keys).is_ok_and(|key| self.verify(&key, message))
    }

    /// Verifies one prepared message after aggregating the supplied keys.
    ///
    /// The keys are aggregated on every call. When the same key set recurs,
    /// aggregate once with [`AggregatePublicKey::from_keys`] and use
    /// [`Self::verify_prepared`] instead.
    #[must_use]
    pub fn verify_prepared_with_keys(&self, keys: &[PublicKey], message: &PreparedMessage) -> bool {
        AggregatePublicKey::from_keys(keys).is_ok_and(|key| self.verify_prepared(&key, message))
    }

    /// Verifies a non-empty slice of aggregate-key/hashed-message groups.
    ///
    /// Multiple groups may contain the same message. Each group contributes a
    /// separate term to the pairing equation. Returns `false` for an empty
    /// slice.
    #[must_use]
    pub fn verify_groups(&self, groups: &[(&AggregatePublicKey, &HashedMessage)]) -> bool {
        let mut verifier = AggregateVerifier::new(self);
        verifier.extend(groups);
        verifier.finish()
    }

    /// Verifies a non-empty slice of aggregate-key/prepared-message groups.
    ///
    /// Multiple groups may contain the same message. Each group contributes a
    /// separate term to the pairing equation. Returns `false` for an empty
    /// slice.
    #[must_use]
    pub fn verify_prepared_groups(
        &self,
        groups: &[(&AggregatePublicKey, &PreparedMessage)],
    ) -> bool {
        let mut verifier = AggregateVerifier::new(self);
        verifier.extend_prepared(groups);
        verifier.finish()
    }
}

/// An allocation-free streaming aggregate verifier.
///
/// The verifier accepts repeated messages and has no group-count capacity.
/// [`finish`](Self::finish) returns `false` if no groups were added.
pub struct AggregateVerifier {
    signature: G2Affine,
    accumulator: MillerLoopResult,
    staged_keys: [G1Affine; MILLER_LOOP_BATCH_SIZE],
    staged_messages: [G2Affine; MILLER_LOOP_BATCH_SIZE],
    staged: usize,
    groups: usize,
}

impl AggregateVerifier {
    /// Starts verification for an aggregate signature.
    #[must_use]
    pub fn new(signature: &AggregateSignature) -> Self {
        Self {
            signature: signature.point,
            accumulator: ffi::miller_loop_identity(),
            staged_keys: [G1Affine::default(); MILLER_LOOP_BATCH_SIZE],
            staged_messages: [G2Affine::default(); MILLER_LOOP_BATCH_SIZE],
            staged: 0,
            groups: 0,
        }
    }

    /// Adds one aggregate-key/hashed-message group.
    pub fn add(&mut self, key: &AggregatePublicKey, message: &HashedMessage) {
        self.staged_keys[self.staged] = key.point;
        self.staged_messages[self.staged] = message.point;
        self.staged += 1;
        self.groups += 1;

        if self.staged == MILLER_LOOP_BATCH_SIZE {
            self.flush();
        }
    }

    /// Adds one aggregate-key/prepared-message group.
    pub fn add_prepared(&mut self, key: &AggregatePublicKey, message: &PreparedMessage) {
        let term = ffi::miller_loop_prepared(&key.point, &message.lines);
        ffi::multiply_miller_loop(&mut self.accumulator, &term);
        self.groups += 1;
    }

    /// Adds aggregate-key/hashed-message groups in slice order.
    pub fn extend(&mut self, groups: &[(&AggregatePublicKey, &HashedMessage)]) {
        for &(key, message) in groups {
            self.add(key, message);
        }
    }

    /// Adds aggregate-key/prepared-message groups in slice order.
    pub fn extend_prepared(&mut self, groups: &[(&AggregatePublicKey, &PreparedMessage)]) {
        for &(key, message) in groups {
            self.add_prepared(key, message);
        }
    }

    /// Flushes pending groups and decides the pairing equation.
    ///
    /// Returns `true` only if at least one group was added and the aggregate
    /// pairing equation holds. Returns `false` for an empty verifier or a
    /// failed pairing equation.
    #[must_use]
    pub fn finish(mut self) -> bool {
        if self.groups == 0 {
            return false;
        }

        self.flush();
        ffi::verify_miller_loop_product(&self.accumulator, &self.signature)
    }

    fn flush(&mut self) {
        if self.staged == 0 {
            return;
        }

        let term = ffi::miller_loop_many(
            &self.staged_keys[..self.staged],
            &self.staged_messages[..self.staged],
        );
        ffi::multiply_miller_loop(&mut self.accumulator, &term);
        self.staged = 0;
    }
}

impl fmt::Debug for AggregateVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateVerifier").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;
    use std::vec::Vec;

    use super::AggregateVerifier;
    use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};
    use crate::{
        AggregatePublicKey, AggregateSignature, AggregateSignatureBuilder, HashedMessage,
        PublicKey, Signature,
    };

    fn scalar(value: u8) -> [u8; 32] {
        let mut scalar = [0; 32];
        scalar[31] = value;
        scalar
    }

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

    fn participant(secret: [u8; 32], message: &[u8]) -> (PublicKey, Signature) {
        let secret = blst::min_pk::SecretKey::from_bytes(&secret).unwrap();
        let key = secret.sk_to_pk().to_bytes();
        let proof = secret.sign(&key, PROOF_OF_POSSESSION_DST, b"").to_bytes();
        let signature = secret.sign(message, SIGNATURE_DST, b"").to_bytes();

        (
            PublicKey::from_bytes_with_proof(&key, &proof).unwrap(),
            Signature::from_bytes(&signature).unwrap(),
        )
    }

    fn aggregate_signatures(signatures: &[Signature]) -> AggregateSignature {
        let (first, rest) = signatures.split_first().unwrap();
        let mut builder = AggregateSignatureBuilder::new(first);
        builder.extend(rest);
        builder.finish()
    }

    #[test]
    fn verifies_single_signatures_at_every_message_rung() {
        let (key, signature) = participant(scalar(1), b"message");
        let (other_key, _) = participant(scalar(2), b"message");
        let message = HashedMessage::new(b"message");
        let prepared = message.prepare();
        let wrong_message = HashedMessage::new(b"wrong message");
        let wrong_prepared = wrong_message.prepare();

        assert!(signature.verify_message(&key, b"message"));
        assert!(signature.verify(&key, &message));
        assert!(signature.verify_prepared(&key, &prepared));

        assert!(!signature.verify_message(&key, b"wrong message"));
        assert!(!signature.verify(&key, &wrong_message));
        assert!(!signature.verify_prepared(&key, &wrong_prepared));
        assert!(!signature.verify(&other_key, &message));
    }

    #[test]
    fn verifies_fast_aggregates_at_every_message_rung() {
        let message_bytes = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message_bytes);
        let (second_key, second_signature) = participant(scalar(2), message_bytes);
        let keys = [first_key, second_key];
        let signature = aggregate_signatures(&[first_signature, second_signature]);
        let key = AggregatePublicKey::from_keys(&keys).unwrap();
        let message = HashedMessage::new(message_bytes);
        let prepared = message.prepare();

        assert!(signature.verify_message(&key, message_bytes));
        assert!(signature.verify(&key, &message));
        assert!(signature.verify_prepared(&key, &prepared));
        assert!(signature.verify_message_with_keys(&keys, message_bytes));
        assert!(signature.verify_with_keys(&keys, &message));
        assert!(signature.verify_prepared_with_keys(&keys, &prepared));

        assert!(!signature.verify_message(&key, b"wrong message"));
        assert!(!signature.verify_message_with_keys(&[], message_bytes));
        assert!(!signature.verify_with_keys(&[], &message));
        assert!(!signature.verify_prepared_with_keys(&[], &prepared));
    }

    #[test]
    fn verifies_multi_message_and_mixed_streaming_aggregates() {
        let (first_key, first_signature) = participant(scalar(1), b"one");
        let (second_key, second_signature) = participant(scalar(2), b"two");
        let (third_key, third_signature) = participant(scalar(3), b"one");
        let signature = aggregate_signatures(&[first_signature, second_signature, third_signature]);
        let keys = [
            AggregatePublicKey::from(first_key),
            AggregatePublicKey::from(second_key),
            AggregatePublicKey::from(third_key),
        ];
        let messages = [
            HashedMessage::new(b"one"),
            HashedMessage::new(b"two"),
            HashedMessage::new(b"one"),
        ];
        let prepared = [
            messages[0].prepare(),
            messages[1].prepare(),
            messages[2].prepare(),
        ];

        assert!(signature.verify_groups(&[
            (&keys[0], &messages[0]),
            (&keys[1], &messages[1]),
            (&keys[2], &messages[2]),
        ]));
        assert!(signature.verify_prepared_groups(&[
            (&keys[0], &prepared[0]),
            (&keys[1], &prepared[1]),
            (&keys[2], &prepared[2]),
        ]));
        assert!(!signature.verify_groups(&[
            (&keys[0], &messages[1]),
            (&keys[1], &messages[0]),
            (&keys[2], &messages[2]),
        ]));
        assert!(!signature.verify_groups(&[]));
        assert!(!signature.verify_prepared_groups(&[]));

        let mut verifier = AggregateVerifier::new(&signature);
        verifier.add(&keys[0], &messages[0]);
        verifier.add_prepared(&keys[1], &prepared[1]);
        verifier.extend(&[(&keys[2], &messages[2])]);
        assert!(verifier.finish());

        let mut verifier = AggregateVerifier::new(&signature);
        verifier.extend_prepared(&[
            (&keys[0], &prepared[0]),
            (&keys[1], &prepared[1]),
            (&keys[2], &prepared[2]),
        ]);
        assert!(verifier.finish());
    }

    #[test]
    fn flushes_full_and_partial_miller_loop_batches() {
        let mut keys = Vec::new();
        let mut messages = Vec::new();
        let mut signatures = Vec::new();

        for value in 1..=33 {
            let message = [value];
            let (key, signature) = participant(scalar(value), &message);
            keys.push(AggregatePublicKey::from(key));
            messages.push(HashedMessage::new(&message));
            signatures.push(signature);
        }

        let signature = aggregate_signatures(&signatures);
        let groups: Vec<_> = keys.iter().zip(&messages).collect();

        assert!(signature.verify_groups(&groups));

        let mut verifier = AggregateVerifier::new(&signature);
        verifier.extend(&groups);
        assert!(verifier.finish());
    }

    #[test]
    fn handles_identity_aggregate_signatures_without_accepting_empty_input() {
        let message = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            message,
        );
        let signature = aggregate_signatures(&[first_signature, inverse_signature]);
        let first_key = AggregatePublicKey::from(first_key);
        let inverse_key = AggregatePublicKey::from(inverse_key);
        let hashed = HashedMessage::new(message);
        let prepared = hashed.prepare();

        assert_eq!(signature.to_bytes()[0], 0xc0);
        assert!(signature.to_bytes()[1..].iter().all(|byte| *byte == 0));
        assert!(signature.verify_groups(&[(&first_key, &hashed), (&inverse_key, &hashed),]));
        assert!(
            signature
                .verify_prepared_groups(&[(&first_key, &prepared), (&inverse_key, &prepared),])
        );

        let verifier = AggregateVerifier::new(&signature);
        assert!(!verifier.finish());
    }

    #[test]
    fn fast_verification_rejects_keys_that_cancel_to_identity() {
        let message = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            message,
        );
        let signature = aggregate_signatures(&[first_signature, inverse_signature]);
        let keys = [first_key, inverse_key];
        let hashed = HashedMessage::new(message);
        let prepared = hashed.prepare();

        assert!(!signature.verify_message_with_keys(&keys, message));
        assert!(!signature.verify_with_keys(&keys, &hashed));
        assert!(!signature.verify_prepared_with_keys(&keys, &prepared));
    }

    #[test]
    fn verifier_debug_omits_pairing_and_staging_state() {
        let (_, signature) = participant(scalar(1), b"message");
        let aggregate = AggregateSignature::from(signature);
        let debug = format!("{:?}", AggregateVerifier::new(&aggregate));

        assert_eq!(debug, "AggregateVerifier { .. }");
    }
}
