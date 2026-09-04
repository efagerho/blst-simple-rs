use core::fmt;
use std::collections::{HashMap, hash_map::Entry};

use crate::ffi::{
    self, G1Affine, G1Projective, G2Affine, MILLER_LOOP_BATCH_SIZE, MillerLoopResult, PreparedLines,
};
use crate::{
    AggregatePublicKey, AggregateSignature, HashedMessage, PreparedMessage, PublicKey, Signature,
    TooManyDistinctMessagesError,
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
    /// Public keys for equal hashed messages are combined and an identity sum
    /// is rejected. Finding equal messages takes quadratic time in the worst
    /// case but does not allocate. Returns `false` for an empty slice.
    #[must_use]
    pub fn verify_groups(&self, groups: &[(&AggregatePublicKey, &HashedMessage)]) -> bool {
        verify_group_slice(self, groups)
    }

    /// Verifies a non-empty slice of aggregate-key/prepared-message groups.
    ///
    /// Public keys for equal hashed messages are combined and an identity sum
    /// is rejected. Finding equal messages takes quadratic time in the worst
    /// case but does not allocate. Returns `false` for an empty slice.
    #[must_use]
    pub fn verify_prepared_groups(
        &self,
        groups: &[(&AggregatePublicKey, &PreparedMessage)],
    ) -> bool {
        verify_group_slice(self, groups)
    }
}

trait PairingMessage {
    fn hashed_message(&self) -> &HashedMessage;

    fn add_pairing(&self, pairings: &mut PairingAccumulator, key: &G1Affine);
}

impl PairingMessage for HashedMessage {
    fn hashed_message(&self) -> &HashedMessage {
        self
    }

    fn add_pairing(&self, pairings: &mut PairingAccumulator, key: &G1Affine) {
        pairings.add(key, &self.point);
    }
}

impl PairingMessage for PreparedMessage {
    fn hashed_message(&self) -> &HashedMessage {
        self.as_hashed_message()
    }

    fn add_pairing(&self, pairings: &mut PairingAccumulator, key: &G1Affine) {
        pairings.add_prepared(key, &self.lines);
    }
}

fn verify_group_slice<M: PairingMessage>(
    signature: &AggregateSignature,
    groups: &[(&AggregatePublicKey, &M)],
) -> bool {
    if groups.is_empty() {
        return false;
    }

    let mut pairings = PairingAccumulator::new();

    for (index, &(key, message)) in groups.iter().enumerate() {
        let hashed_message = message.hashed_message();
        if groups[..index]
            .iter()
            .any(|&(_, previous)| previous.hashed_message() == hashed_message)
        {
            continue;
        }

        let mut grouped_key = None;
        for &(next_key, next_message) in &groups[index + 1..] {
            if next_message.hashed_message() == hashed_message {
                let sum = grouped_key.get_or_insert_with(|| ffi::g1_from_affine(&key.point));
                ffi::add_g1_affine(sum, &next_key.point);
            }
        }

        if let Some(grouped_key) = grouped_key {
            if ffi::g1_is_identity(&grouped_key) {
                return false;
            }
            message.add_pairing(&mut pairings, &ffi::g1_to_affine(&grouped_key));
        } else {
            message.add_pairing(&mut pairings, &key.point);
        }
    }

    pairings.verify(&signature.point)
}

struct PairingAccumulator {
    accumulator: MillerLoopResult,
    staged_keys: [G1Affine; MILLER_LOOP_BATCH_SIZE],
    staged_messages: [G2Affine; MILLER_LOOP_BATCH_SIZE],
    staged: usize,
}

impl PairingAccumulator {
    fn new() -> Self {
        Self {
            accumulator: ffi::miller_loop_identity(),
            staged_keys: [G1Affine::default(); MILLER_LOOP_BATCH_SIZE],
            staged_messages: [G2Affine::default(); MILLER_LOOP_BATCH_SIZE],
            staged: 0,
        }
    }

    fn add(&mut self, key: &G1Affine, message: &G2Affine) {
        self.staged_keys[self.staged] = *key;
        self.staged_messages[self.staged] = *message;
        self.staged += 1;

        if self.staged == MILLER_LOOP_BATCH_SIZE {
            self.flush();
        }
    }

    fn add_prepared(&mut self, key: &G1Affine, message: &PreparedLines) {
        let term = ffi::miller_loop_prepared(key, message);
        ffi::multiply_miller_loop(&mut self.accumulator, &term);
    }

    fn verify(&mut self, signature: &G2Affine) -> bool {
        self.flush();
        ffi::verify_miller_loop_product(&self.accumulator, signature)
    }

    fn reset(&mut self) {
        self.accumulator = ffi::miller_loop_identity();
        self.staged = 0;
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

/// A reusable streaming aggregate verifier.
///
/// Pairing work is accumulated as groups arrive. Public keys for equal hashed
/// messages are also accumulated so their final sum can be validated. The
/// caller-selected distinct-message limit bounds the retained grouping state.
/// Repeated messages do not consume additional slots.
/// [`finish_and_reset`](Self::finish_and_reset) clears the groups while
/// retaining the hash table's allocation for reuse.
pub struct AggregateVerifier {
    pairings: PairingAccumulator,
    grouped_keys: HashMap<[u8; 96], G1Projective>,
    maximum_distinct_messages: usize,
    overflowed: bool,
}

impl AggregateVerifier {
    /// Creates a verifier with a hard distinct-message limit and no initial
    /// allocation.
    ///
    /// The hash table grows as messages arrive, up to
    /// `maximum_distinct_messages`. A maximum of zero rejects every group.
    #[must_use]
    pub fn new(maximum_distinct_messages: usize) -> Self {
        Self::with_initial_capacity(maximum_distinct_messages, 0)
    }

    /// Creates a verifier with a hard distinct-message limit and an allocation
    /// sized for the expected number of distinct messages.
    ///
    /// `initial_capacity` is capped at `maximum_distinct_messages`. The table
    /// grows as needed until the maximum is reached.
    #[must_use]
    pub fn with_initial_capacity(
        maximum_distinct_messages: usize,
        initial_capacity: usize,
    ) -> Self {
        let initial_capacity = initial_capacity.min(maximum_distinct_messages);
        Self {
            pairings: PairingAccumulator::new(),
            grouped_keys: HashMap::with_capacity(initial_capacity),
            maximum_distinct_messages,
            overflowed: false,
        }
    }

    /// Adds one aggregate-key/hashed-message group.
    ///
    /// An excess distinct message poisons the current verification. Further
    /// additions do no pairing work and return the same error until
    /// [`Self::finish_and_reset`] is called.
    pub fn add(
        &mut self,
        key: &AggregatePublicKey,
        message: &HashedMessage,
    ) -> Result<(), TooManyDistinctMessagesError> {
        self.try_accumulate_key_for_message(key, message)?;
        self.pairings.add(&key.point, &message.point);
        Ok(())
    }

    /// Adds one aggregate-key/prepared-message group.
    ///
    /// An excess distinct message poisons the current verification. Further
    /// additions do no pairing work and return the same error until
    /// [`Self::finish_and_reset`] is called.
    pub fn add_prepared(
        &mut self,
        key: &AggregatePublicKey,
        message: &PreparedMessage,
    ) -> Result<(), TooManyDistinctMessagesError> {
        self.try_accumulate_key_for_message(key, message.as_hashed_message())?;
        self.pairings.add_prepared(&key.point, &message.lines);
        Ok(())
    }

    /// Adds aggregate-key/hashed-message groups in slice order.
    ///
    /// An excess distinct message poisons the current verification after the
    /// preceding groups have been added.
    pub fn extend(
        &mut self,
        groups: &[(&AggregatePublicKey, &HashedMessage)],
    ) -> Result<(), TooManyDistinctMessagesError> {
        for &(key, message) in groups {
            self.add(key, message)?;
        }
        Ok(())
    }

    /// Adds aggregate-key/prepared-message groups in slice order.
    ///
    /// An excess distinct message poisons the current verification after the
    /// preceding groups have been added.
    pub fn extend_prepared(
        &mut self,
        groups: &[(&AggregatePublicKey, &PreparedMessage)],
    ) -> Result<(), TooManyDistinctMessagesError> {
        for &(key, message) in groups {
            self.add_prepared(key, message)?;
        }
        Ok(())
    }

    /// Decides the pairing equation and resets the verifier for reuse.
    ///
    /// The hash table retains its capacity. Returns `false` if the current
    /// verification exceeded its distinct-message limit, no groups were
    /// added, any equal-message public-key sum is the identity, or the pairing
    /// equation fails.
    #[must_use]
    pub fn finish_and_reset(&mut self, signature: &AggregateSignature) -> bool {
        let valid = !self.overflowed
            && !self.grouped_keys.is_empty()
            && !self.grouped_keys.values().any(ffi::g1_is_identity)
            && self.pairings.verify(&signature.point);

        self.reset();
        valid
    }

    fn reset(&mut self) {
        self.pairings.reset();
        self.grouped_keys.clear();
        self.overflowed = false;
    }

    fn try_accumulate_key_for_message(
        &mut self,
        key: &AggregatePublicKey,
        message: &HashedMessage,
    ) -> Result<(), TooManyDistinctMessagesError> {
        if self.overflowed {
            return Err(self.limit_error());
        }

        let message = ffi::compress_g2(&message.point);
        let at_limit = self.grouped_keys.len() >= self.maximum_distinct_messages;
        let limit_error = TooManyDistinctMessagesError {
            maximum: self.maximum_distinct_messages,
        };

        match self.grouped_keys.entry(message) {
            Entry::Occupied(mut entry) => {
                ffi::add_g1_affine(entry.get_mut(), &key.point);
                Ok(())
            }
            Entry::Vacant(_) if at_limit => {
                self.overflowed = true;
                Err(limit_error)
            }
            Entry::Vacant(entry) => {
                entry.insert(ffi::g1_from_affine(&key.point));
                Ok(())
            }
        }
    }

    fn limit_error(&self) -> TooManyDistinctMessagesError {
        TooManyDistinctMessagesError {
            maximum: self.maximum_distinct_messages,
        }
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
    use crate::ffi::MILLER_LOOP_BATCH_SIZE;
    use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};
    use crate::{
        AggregatePublicKey, AggregateSignature, AggregateSignatureBuilder, HashedMessage,
        PublicKey, Signature, TooManyDistinctMessagesError,
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
    fn verifies_empty_message_buffers() {
        let (first_key, first_signature) = participant(scalar(1), b"");
        let (second_key, second_signature) = participant(scalar(2), b"");

        assert!(first_signature.verify_message(&first_key, b""));

        let keys = [first_key, second_key];
        let aggregate_key = AggregatePublicKey::from_keys(&keys).unwrap();
        let aggregate_signature = aggregate_signatures(&[first_signature, second_signature]);

        assert!(aggregate_signature.verify_message(&aggregate_key, b""));
        assert!(aggregate_signature.verify_message_with_keys(&keys, b""));
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
        assert!(!signature.verify_message(&other_key, b"message"));
        assert!(!signature.verify(&other_key, &message));
        assert!(!signature.verify_prepared(&other_key, &prepared));
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
        let wrong_message = HashedMessage::new(b"wrong message");
        let wrong_prepared = wrong_message.prepare();

        assert!(signature.verify_message(&key, message_bytes));
        assert!(signature.verify(&key, &message));
        assert!(signature.verify_prepared(&key, &prepared));
        assert!(signature.verify_message_with_keys(&keys, message_bytes));
        assert!(signature.verify_with_keys(&keys, &message));
        assert!(signature.verify_prepared_with_keys(&keys, &prepared));

        assert!(!signature.verify_message(&key, b"wrong message"));
        assert!(!signature.verify(&key, &wrong_message));
        assert!(!signature.verify_prepared(&key, &wrong_prepared));
        assert!(!signature.verify_message_with_keys(&keys, b"wrong message"));
        assert!(!signature.verify_with_keys(&keys, &wrong_message));
        assert!(!signature.verify_prepared_with_keys(&keys, &wrong_prepared));
        assert!(!signature.verify_message_with_keys(&[], message_bytes));
        assert!(!signature.verify_with_keys(&[], &message));
        assert!(!signature.verify_prepared_with_keys(&[], &prepared));

        let duplicated_keys = [first_key, first_key];
        let duplicated_signature = aggregate_signatures(&[first_signature, first_signature]);
        assert!(duplicated_signature.verify_message_with_keys(&duplicated_keys, message_bytes));
    }

    #[test]
    fn verifies_one_element_aggregates() {
        let message_bytes = b"message";
        let (key, signature) = participant(scalar(1), message_bytes);
        let keys = [key];
        let aggregate_key = AggregatePublicKey::from(key);
        let aggregate_signature = AggregateSignature::from(signature);
        let message = HashedMessage::new(message_bytes);
        let prepared = message.prepare();

        assert!(aggregate_signature.verify_message(&aggregate_key, message_bytes));
        assert!(aggregate_signature.verify(&aggregate_key, &message));
        assert!(aggregate_signature.verify_prepared(&aggregate_key, &prepared));
        assert!(aggregate_signature.verify_message_with_keys(&keys, message_bytes));
        assert!(aggregate_signature.verify_with_keys(&keys, &message));
        assert!(aggregate_signature.verify_prepared_with_keys(&keys, &prepared));
        assert!(aggregate_signature.verify_groups(&[(&aggregate_key, &message)]));
        assert!(aggregate_signature.verify_prepared_groups(&[(&aggregate_key, &prepared)]));
    }

    #[test]
    fn identity_aggregate_signature_never_verifies() {
        let message_bytes = b"message";
        let (key, _) = participant(scalar(1), message_bytes);
        let keys = [key];
        let aggregate_key = AggregatePublicKey::from(key);
        let message = HashedMessage::new(message_bytes);
        let prepared = message.prepare();
        let mut identity = [0; 96];
        identity[0] = 0xc0;
        let identity = AggregateSignature::from_bytes(&identity).unwrap();

        assert!(!identity.verify_message(&aggregate_key, message_bytes));
        assert!(!identity.verify(&aggregate_key, &message));
        assert!(!identity.verify_prepared(&aggregate_key, &prepared));
        assert!(!identity.verify_message_with_keys(&keys, message_bytes));
        assert!(!identity.verify_with_keys(&keys, &message));
        assert!(!identity.verify_prepared_with_keys(&keys, &prepared));
        assert!(!identity.verify_groups(&[(&aggregate_key, &message)]));
        assert!(!identity.verify_prepared_groups(&[(&aggregate_key, &prepared)]));

        let mut verifier = AggregateVerifier::new(1);
        verifier.add(&aggregate_key, &message).unwrap();
        assert!(!verifier.finish_and_reset(&identity));

        verifier.add_prepared(&aggregate_key, &prepared).unwrap();
        assert!(!verifier.finish_and_reset(&identity));
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
        assert!(!signature.verify_prepared_groups(&[
            (&keys[0], &prepared[1]),
            (&keys[1], &prepared[0]),
            (&keys[2], &prepared[2]),
        ]));
        assert!(!signature.verify_groups(&[]));
        assert!(!signature.verify_prepared_groups(&[]));

        let mut verifier = AggregateVerifier::new(2);
        verifier.add(&keys[0], &messages[0]).unwrap();
        verifier.add_prepared(&keys[1], &prepared[1]).unwrap();
        verifier.extend(&[(&keys[2], &messages[2])]).unwrap();
        assert!(verifier.finish_and_reset(&signature));

        let mut verifier = AggregateVerifier::new(2);
        verifier
            .extend_prepared(&[
                (&keys[0], &prepared[0]),
                (&keys[1], &prepared[1]),
                (&keys[2], &prepared[2]),
            ])
            .unwrap();
        assert!(verifier.finish_and_reset(&signature));
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

        let groups: Vec<_> = keys.iter().zip(&messages).collect();
        let mut verifier = AggregateVerifier::with_initial_capacity(messages.len(), 1);

        for count in [
            1,
            MILLER_LOOP_BATCH_SIZE - 1,
            MILLER_LOOP_BATCH_SIZE,
            MILLER_LOOP_BATCH_SIZE + 1,
            MILLER_LOOP_BATCH_SIZE * 2,
            MILLER_LOOP_BATCH_SIZE * 2 + 1,
        ] {
            let signature = aggregate_signatures(&signatures[..count]);

            assert!(signature.verify_groups(&groups[..count]));

            verifier.extend(&groups[..count]).unwrap();
            assert!(verifier.finish_and_reset(&signature));
        }

        assert!(verifier.grouped_keys.capacity() >= messages.len());
    }

    #[test]
    fn slice_verification_rejects_identity_equal_message_key_sums() {
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
        assert!(!signature.verify_groups(&[(&first_key, &hashed), (&inverse_key, &hashed),]));
        assert!(
            !signature
                .verify_prepared_groups(&[(&first_key, &prepared), (&inverse_key, &prepared),])
        );
    }

    #[test]
    fn streaming_verification_rejects_identity_equal_message_key_sums() {
        let message = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            message,
        );
        let signature = aggregate_signatures(&[first_signature, inverse_signature]);
        let first_key = AggregatePublicKey::from(first_key);
        let inverse_key = AggregatePublicKey::from(inverse_key);
        let message = HashedMessage::new(message);
        let prepared = message.prepare();
        let mut verifier = AggregateVerifier::new(1);

        verifier.add(&first_key, &message).unwrap();
        verifier.add_prepared(&inverse_key, &prepared).unwrap();

        assert!(!verifier.finish_and_reset(&signature));
        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn group_verification_rejects_canceling_groups_appended_to_an_honest_signature() {
        let shared_message = b"attacker-selected message";
        let (first_key, _) = participant(scalar(1), shared_message);
        let (inverse_key, _) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            shared_message,
        );
        let (honest_key, honest_signature) = participant(scalar(2), b"honest message");
        let signature = AggregateSignature::from(honest_signature);
        let keys = [
            AggregatePublicKey::from(first_key),
            AggregatePublicKey::from(inverse_key),
            AggregatePublicKey::from(honest_key),
        ];
        let messages = [
            HashedMessage::new(shared_message),
            HashedMessage::new(shared_message),
            HashedMessage::new(b"honest message"),
        ];
        let prepared = [
            messages[0].prepare(),
            messages[1].prepare(),
            messages[2].prepare(),
        ];
        let mut verifier = AggregateVerifier::new(2);

        assert!(!signature.verify_groups(&[
            (&keys[0], &messages[0]),
            (&keys[1], &messages[1]),
            (&keys[2], &messages[2]),
        ]));
        assert!(!signature.verify_prepared_groups(&[
            (&keys[0], &prepared[0]),
            (&keys[1], &prepared[1]),
            (&keys[2], &prepared[2]),
        ]));

        verifier
            .extend(&[
                (&keys[0], &messages[0]),
                (&keys[1], &messages[1]),
                (&keys[2], &messages[2]),
            ])
            .unwrap();

        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn group_verification_permits_a_temporary_identity() {
        let message_bytes = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message_bytes);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            message_bytes,
        );
        let (last_key, last_signature) = participant(scalar(2), message_bytes);
        let signature = aggregate_signatures(&[first_signature, inverse_signature, last_signature]);
        let keys = [
            AggregatePublicKey::from(first_key),
            AggregatePublicKey::from(inverse_key),
            AggregatePublicKey::from(last_key),
        ];
        let message = HashedMessage::new(message_bytes);
        let prepared = message.prepare();
        let mut verifier = AggregateVerifier::new(1);

        assert!(signature.verify_groups(&[
            (&keys[0], &message),
            (&keys[1], &message),
            (&keys[2], &message),
        ]));
        assert!(signature.verify_prepared_groups(&[
            (&keys[0], &prepared),
            (&keys[1], &prepared),
            (&keys[2], &prepared),
        ]));

        verifier.add(&keys[0], &message).unwrap();
        verifier.add(&keys[1], &message).unwrap();
        verifier.add_prepared(&keys[2], &prepared).unwrap();

        assert!(verifier.finish_and_reset(&signature));
    }

    #[test]
    fn streaming_verifier_retains_capacity_and_resets_after_every_outcome() {
        let (key, signature) = participant(scalar(1), b"message");
        let (_, wrong_signature) = participant(scalar(2), b"other message");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let wrong_signature = AggregateSignature::from(wrong_signature);
        let message = HashedMessage::new(b"message");
        let prepared = message.prepare();
        let mut verifier = AggregateVerifier::with_initial_capacity(4, 4);
        let capacity = verifier.grouped_keys.capacity();

        assert!(capacity >= 4);

        verifier.add(&key, &message).unwrap();
        assert!(!verifier.finish_and_reset(&wrong_signature));
        assert_eq!(verifier.grouped_keys.capacity(), capacity);
        assert!(verifier.grouped_keys.is_empty());
        assert_eq!(verifier.pairings.staged, 0);

        verifier.add_prepared(&key, &prepared).unwrap();
        assert!(verifier.finish_and_reset(&signature));
        assert_eq!(verifier.grouped_keys.capacity(), capacity);

        assert!(!verifier.finish_and_reset(&signature));
        assert_eq!(verifier.grouped_keys.capacity(), capacity);

        verifier.add(&key, &message).unwrap();
        assert!(verifier.finish_and_reset(&signature));
    }

    #[test]
    fn verifier_capacity_grows_lazily_and_is_retained() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let messages = [
            HashedMessage::new(b"one"),
            HashedMessage::new(b"two"),
            HashedMessage::new(b"three"),
            HashedMessage::new(b"four"),
        ];
        let mut verifier = AggregateVerifier::new(messages.len());

        assert_eq!(verifier.grouped_keys.capacity(), 0);

        for message in &messages {
            verifier.add(&key, message).unwrap();
        }
        let grown_capacity = verifier.grouped_keys.capacity();

        assert!(grown_capacity >= messages.len());

        assert!(!verifier.finish_and_reset(&signature));
        assert_eq!(verifier.grouped_keys.capacity(), grown_capacity);
    }

    #[test]
    fn initial_capacity_is_capped_at_the_distinct_message_limit() {
        let verifier = AggregateVerifier::with_initial_capacity(0, usize::MAX);

        assert_eq!(verifier.maximum_distinct_messages, 0);
        assert_eq!(verifier.grouped_keys.capacity(), 0);
    }

    #[test]
    fn repeated_messages_are_accepted_at_the_limit() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = aggregate_signatures(&[signature, signature]);
        let message = HashedMessage::new(b"message");
        let prepared = message.prepare();
        let mut verifier = AggregateVerifier::new(1);

        verifier.add(&key, &message).unwrap();
        verifier.add_prepared(&key, &prepared).unwrap();

        assert_eq!(verifier.grouped_keys.len(), 1);
        assert!(verifier.finish_and_reset(&signature));
    }

    #[test]
    fn an_excess_distinct_message_poisons_until_finish_and_reset() {
        let (key, signature) = participant(scalar(1), b"first");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let first = HashedMessage::new(b"first");
        let second = HashedMessage::new(b"second");
        let error = TooManyDistinctMessagesError { maximum: 1 };
        let mut verifier = AggregateVerifier::new(1);

        verifier.add(&key, &first).unwrap();
        let staged = verifier.pairings.staged;
        let capacity = verifier.grouped_keys.capacity();

        assert_eq!(verifier.add(&key, &second), Err(error));
        assert_eq!(verifier.add(&key, &first), Err(error));
        assert_eq!(verifier.grouped_keys.len(), 1);
        assert_eq!(verifier.grouped_keys.capacity(), capacity);
        assert_eq!(verifier.pairings.staged, staged);
        assert!(!verifier.finish_and_reset(&signature));
        assert!(verifier.grouped_keys.is_empty());
        assert_eq!(verifier.grouped_keys.capacity(), capacity);
        assert!(!verifier.overflowed);

        verifier.add(&key, &first).unwrap();
        assert!(verifier.finish_and_reset(&signature));
    }

    #[test]
    fn bulk_addition_reports_distinct_message_overflow() {
        let (key, signature) = participant(scalar(1), b"first");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let first = HashedMessage::new(b"first");
        let second = HashedMessage::new(b"second");
        let first_prepared = first.prepare();
        let second_prepared = second.prepare();
        let error = TooManyDistinctMessagesError { maximum: 1 };
        let mut verifier = AggregateVerifier::new(1);

        assert_eq!(
            verifier.extend(&[(&key, &first), (&key, &second)]),
            Err(error)
        );
        assert!(!verifier.finish_and_reset(&signature));

        assert_eq!(
            verifier.extend_prepared(&[(&key, &first_prepared), (&key, &second_prepared),]),
            Err(error)
        );
        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn zero_limit_rejects_the_first_message() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let message = HashedMessage::new(b"message");
        let error = TooManyDistinctMessagesError { maximum: 0 };
        let mut verifier = AggregateVerifier::new(0);

        assert_eq!(verifier.add(&key, &message), Err(error));
        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn overflow_after_a_pairing_flush_fails_closed() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let error = TooManyDistinctMessagesError {
            maximum: MILLER_LOOP_BATCH_SIZE,
        };
        let mut verifier = AggregateVerifier::new(MILLER_LOOP_BATCH_SIZE);

        for value in 0..MILLER_LOOP_BATCH_SIZE {
            verifier
                .add(&key, &HashedMessage::new(&value.to_le_bytes()))
                .unwrap();
        }

        assert_eq!(verifier.pairings.staged, 0);
        assert_eq!(
            verifier.add(&key, &HashedMessage::new(b"excess")),
            Err(error)
        );
        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn empty_bulk_additions_leave_the_verifier_empty() {
        let (_, signature) = participant(scalar(1), b"message");
        let signature = AggregateSignature::from(signature);
        let mut verifier = AggregateVerifier::new(1);

        assert_eq!(verifier.extend(&[]), Ok(()));
        assert_eq!(verifier.extend_prepared(&[]), Ok(()));
        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn prepared_streaming_grouping_rejects_canceling_keys() {
        let message = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            message,
        );
        let signature = aggregate_signatures(&[first_signature, inverse_signature]);
        let first_key = AggregatePublicKey::from(first_key);
        let inverse_key = AggregatePublicKey::from(inverse_key);
        let prepared = HashedMessage::new(message).prepare();
        let mut verifier = AggregateVerifier::new(1);

        verifier
            .extend_prepared(&[(&first_key, &prepared), (&inverse_key, &prepared)])
            .unwrap();

        assert!(!verifier.finish_and_reset(&signature));
    }

    #[test]
    fn reset_discards_unflushed_groups() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let message = HashedMessage::new(b"message");
        let mut verifier = AggregateVerifier::new(1);

        verifier
            .add(&key, &HashedMessage::new(b"wrong message"))
            .unwrap();
        assert!(!verifier.finish_and_reset(&signature));

        verifier.add(&key, &message).unwrap();
        assert!(verifier.finish_and_reset(&signature));
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
    fn verifier_debug_omits_pairing_staging_and_grouping_state() {
        let debug = format!("{:?}", AggregateVerifier::new(1));

        assert_eq!(debug, "AggregateVerifier { .. }");
    }
}
