use core::fmt;
use std::collections::{HashMap, TryReserveError, hash_map::Entry};
use std::sync::Arc;

use crate::ffi::{
    self, G1Affine, G1Projective, G2Affine, MILLER_LOOP_BATCH_SIZE, MillerLoopResult, PreparedLines,
};
use crate::{
    AggregatePublicKey, AggregateSignature, HashedMessage, PreparedMessage, PublicKey, Signature,
    TooManyDistinctMessagesError, UnverifiedPublicKey,
};

impl Signature {
    /// Hashes and verifies a message for one signer.
    ///
    /// Proof of possession is not required because no public keys are
    /// aggregated.
    #[must_use]
    pub fn verify_message(&self, key: &UnverifiedPublicKey, message: &[u8]) -> bool {
        self.verify(key, &HashedMessage::new(message))
    }

    /// Verifies a previously hashed message for one signer.
    #[must_use]
    pub fn verify(&self, key: &UnverifiedPublicKey, message: &HashedMessage) -> bool {
        ffi::verify_signature(&key.point, &message.point, &self.point)
    }

    /// Verifies a prepared message for one signer.
    #[must_use]
    pub fn verify_prepared(&self, key: &UnverifiedPublicKey, message: &PreparedMessage) -> bool {
        ffi::verify_prepared_signature(&key.point, &message.lines, &self.point)
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
            accumulator: MillerLoopResult::default(),
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
        self.accumulator *= term;
    }

    fn verify(mut self, signature: &G2Affine) -> bool {
        self.flush();
        ffi::verify_miller_loop_product(&self.accumulator, signature)
    }

    fn flush(&mut self) {
        if self.staged == 0 {
            return;
        }

        let term = ffi::miller_loop_many(
            &self.staged_keys[..self.staged],
            &self.staged_messages[..self.staged],
        );
        self.accumulator *= term;
        self.staged = 0;
    }
}

/// A reusable streaming aggregate verifier.
///
/// Public keys for equal hashed messages are combined as groups arrive.
/// [`finish_and_reset`](Self::finish_and_reset) validates the final key sums
/// and performs one pairing per distinct message. All pairing work is deferred
/// until then.
///
/// The caller-selected distinct-message limit bounds the retained grouping
/// state. Repeated messages do not consume additional slots. Hashed messages
/// are copied; prepared line tables are shared without copying or allocating
/// another table. At most one table is retained per distinct message.
///
/// Completion and [`reset`](Self::reset) release the retained tables and keep
/// the hash table's allocation for reuse.
pub struct AggregateVerifier {
    groups: HashMap<HashedMessage, MessageGroup>,
    maximum_distinct_messages: usize,
    overflowed: bool,
}

struct MessageGroup {
    key: G1Projective,
    prepared_lines: Option<Arc<PreparedLines>>,
}

impl AggregateVerifier {
    /// Creates a verifier with a hard distinct-message limit and no initial
    /// allocation.
    ///
    /// The hash table grows as messages arrive, up to
    /// `maximum_distinct_messages`. A maximum of zero rejects every group.
    #[must_use]
    pub fn new(maximum_distinct_messages: usize) -> Self {
        Self {
            groups: HashMap::new(),
            maximum_distinct_messages,
            overflowed: false,
        }
    }

    /// Creates a verifier with a hard distinct-message limit and an allocation
    /// sized for the expected number of distinct messages.
    ///
    /// `initial_capacity` is capped at `maximum_distinct_messages`. The table
    /// grows as needed until the maximum is reached. Returns an error if the
    /// requested capacity exceeds the collection's limit or allocation fails.
    pub fn try_with_initial_capacity(
        maximum_distinct_messages: usize,
        initial_capacity: usize,
    ) -> Result<Self, TryReserveError> {
        let initial_capacity = initial_capacity.min(maximum_distinct_messages);
        let mut verifier = Self::new(maximum_distinct_messages);
        verifier.groups.try_reserve(initial_capacity)?;
        Ok(verifier)
    }

    /// Adds one aggregate-key/hashed-message group.
    ///
    /// Copies the hashed message and combines keys for equal messages without
    /// doing pairing work.
    ///
    /// An excess distinct message poisons the current verification. Further
    /// additions leave the state unchanged and return the same error until
    /// [`Self::reset`] or [`Self::finish_and_reset`] is called.
    pub fn add(
        &mut self,
        key: &AggregatePublicKey,
        message: &HashedMessage,
    ) -> Result<(), TooManyDistinctMessagesError> {
        self.add_group(key, message, None)
    }

    /// Adds one aggregate-key/prepared-message group.
    ///
    /// Shares the line table until completion or reset, so `message` can be
    /// dropped after this call. Equal messages use the first prepared table
    /// supplied, even if their earlier contributions were unprepared. No
    /// pairing work is done here.
    ///
    /// An excess distinct message poisons the current verification. Further
    /// additions leave the state unchanged and return the same error until
    /// [`Self::reset`] or [`Self::finish_and_reset`] is called.
    pub fn add_prepared(
        &mut self,
        key: &AggregatePublicKey,
        message: &PreparedMessage,
    ) -> Result<(), TooManyDistinctMessagesError> {
        self.add_group(key, message.as_hashed_message(), Some(&message.lines))
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
    /// Releases retained prepared tables and keeps the hash table's capacity.
    /// Returns `false` if the current verification exceeded its
    /// distinct-message limit, no groups were added, any equal-message
    /// public-key sum is the identity, or the pairing equation fails.
    #[must_use]
    pub fn finish_and_reset(&mut self, signature: &AggregateSignature) -> bool {
        let valid = if self.overflowed
            || self.groups.is_empty()
            || self
                .groups
                .values()
                .any(|group| ffi::g1_is_identity(&group.key))
        {
            false
        } else {
            let mut pairings = PairingAccumulator::new();
            for (message, group) in &self.groups {
                let key = ffi::g1_to_affine(&group.key);
                if let Some(lines) = &group.prepared_lines {
                    pairings.add_prepared(&key, lines);
                } else {
                    pairings.add(&key, &message.point);
                }
            }
            pairings.verify(&signature.point)
        };

        self.reset();
        valid
    }

    /// Discards the current groups and releases their prepared tables while
    /// retaining the hash table's capacity for reuse.
    ///
    /// This also clears a distinct-message-limit error.
    pub fn reset(&mut self) {
        self.groups.clear();
        self.overflowed = false;
    }

    fn add_group(
        &mut self,
        key: &AggregatePublicKey,
        message: &HashedMessage,
        prepared_lines: Option<&Arc<PreparedLines>>,
    ) -> Result<(), TooManyDistinctMessagesError> {
        let error = TooManyDistinctMessagesError {
            maximum: self.maximum_distinct_messages,
        };
        if self.overflowed {
            return Err(error);
        }

        let at_limit = self.groups.len() >= self.maximum_distinct_messages;
        match self.groups.entry(*message) {
            Entry::Occupied(mut entry) => {
                let group = entry.get_mut();
                ffi::add_g1_affine(&mut group.key, &key.point);
                if group.prepared_lines.is_none() {
                    group.prepared_lines = prepared_lines.cloned();
                }
                Ok(())
            }
            Entry::Vacant(_) if at_limit => {
                self.overflowed = true;
                Err(error)
            }
            Entry::Vacant(entry) => {
                entry.insert(MessageGroup {
                    key: ffi::g1_from_affine(&key.point),
                    prepared_lines: prepared_lines.cloned(),
                });
                Ok(())
            }
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
    use std::format;
    use std::sync::Arc;
    use std::vec::Vec;

    use super::AggregateVerifier;
    use crate::ffi::MILLER_LOOP_BATCH_SIZE;
    use crate::test_util::{hex, participant, scalar};
    use crate::{
        AggregatePublicKey, AggregateSignature, AggregateSignatureBuilder, HashedMessage,
        Signature, TooManyDistinctMessagesError,
    };

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
    fn verifies_multi_message_group_slices() {
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
    }

    #[test]
    fn verifies_streaming_batch_cases() {
        #[derive(Clone, Copy)]
        enum Preparation {
            Hashed,
            Prepared,
            Mixed,
        }
        use Preparation::{Hashed, Mixed, Prepared};

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

        let prepared: Vec<_> = messages.iter().map(HashedMessage::prepare).collect();
        let batch = MILLER_LOOP_BATCH_SIZE;
        let cases = [
            ("one group", 1, 1, Hashed),
            ("partial batch", batch - 1, 1, Hashed),
            ("full batch", batch, 1, Hashed),
            ("full and partial batches", batch + 1, 1, Hashed),
            ("two full batches", batch * 2, 1, Hashed),
            ("two full and one partial batch", batch * 2 + 1, 1, Hashed),
            ("repeated hashed messages", batch + 1, 4, Hashed),
            ("repeated prepared messages", batch + 1, 4, Prepared),
            ("repeated mixed messages", batch + 1, 4, Mixed),
        ];

        for (case, distinct_messages, repetitions, preparation) in cases {
            let groups: Vec<_> = keys[..distinct_messages]
                .iter()
                .zip(&messages[..distinct_messages])
                .collect();
            let groups = groups.repeat(repetitions);
            let prepared_groups: Vec<_> = keys[..distinct_messages]
                .iter()
                .zip(&prepared[..distinct_messages])
                .collect();
            let prepared_groups = prepared_groups.repeat(repetitions);
            let signature =
                aggregate_signatures(&signatures[..distinct_messages].repeat(repetitions));
            let mut verifier =
                AggregateVerifier::try_with_initial_capacity(distinct_messages, 1).unwrap();

            match preparation {
                Hashed => verifier.extend(&groups).unwrap(),
                Prepared => verifier.extend_prepared(&prepared_groups).unwrap(),
                Mixed => {
                    for (contribution, (&(key, message), &(_, prepared_message))) in
                        groups.iter().zip(&prepared_groups).enumerate()
                    {
                        if contribution % distinct_messages % 2 == 0 {
                            verifier.add_prepared(key, prepared_message).unwrap();
                        } else {
                            verifier.add(key, message).unwrap();
                        }
                    }
                }
            }

            assert_eq!(verifier.groups.len(), distinct_messages, "{case}");
            if let Mixed = preparation {
                let prepared_count = verifier
                    .groups
                    .values()
                    .filter(|group| group.prepared_lines.is_some())
                    .count();
                assert!(
                    prepared_count > 0 && prepared_count < distinct_messages,
                    "{case}"
                );
            }
            assert!(signature.verify_groups(&groups), "slice: {case}");
            assert!(verifier.finish_and_reset(&signature), "stream: {case}");
        }
    }

    #[test]
    fn streaming_verifier_shares_one_preparation_per_message_until_completion() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = aggregate_signatures(&[signature; 4]);
        let message = HashedMessage::new(b"message");

        for prepared_first in [false, true] {
            let mut verifier = AggregateVerifier::new(1);
            let first = message.prepare();
            let second = message.prepare();
            let first_lines = Arc::downgrade(&first.lines);
            let second_lines = Arc::downgrade(&second.lines);

            if prepared_first {
                verifier.add_prepared(&key, &first).unwrap();
                verifier.add(&key, &message).unwrap();
            } else {
                verifier.add(&key, &message).unwrap();
                verifier.add_prepared(&key, &first).unwrap();
            }
            verifier.add_prepared(&key, &second).unwrap();
            verifier.add_prepared(&key, &first).unwrap();
            drop(first);
            drop(second);

            assert_eq!(first_lines.strong_count(), 1);
            assert_eq!(second_lines.strong_count(), 0);
            assert!(verifier.finish_and_reset(&signature));
            assert_eq!(first_lines.strong_count(), 0);
        }
    }

    #[test]
    fn verification_rejects_identity_equal_message_key_sums() {
        let message_bytes = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), message_bytes);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            message_bytes,
        );
        let signature = aggregate_signatures(&[first_signature, inverse_signature]);
        let keys = [first_key, inverse_key];
        let aggregate_keys = keys.map(AggregatePublicKey::from);
        let hashed = HashedMessage::new(message_bytes);
        let prepared = hashed.prepare();
        let groups = [(&aggregate_keys[0], &hashed), (&aggregate_keys[1], &hashed)];
        let prepared_groups = [
            (&aggregate_keys[0], &prepared),
            (&aggregate_keys[1], &prepared),
        ];
        let mut verifier = AggregateVerifier::new(1);

        verifier.extend(&groups).unwrap();
        let hashed_stream = verifier.finish_and_reset(&signature);
        verifier.extend_prepared(&prepared_groups).unwrap();
        let prepared_stream = verifier.finish_and_reset(&signature);
        verifier.add(&aggregate_keys[0], &hashed).unwrap();
        verifier
            .add_prepared(&aggregate_keys[1], &prepared)
            .unwrap();
        let mixed_stream = verifier.finish_and_reset(&signature);

        assert_eq!(signature.to_bytes()[0], 0xc0);
        assert!(signature.to_bytes()[1..].iter().all(|byte| *byte == 0));
        for (path, result) in [
            (
                "raw message with keys",
                signature.verify_message_with_keys(&keys, message_bytes),
            ),
            (
                "hashed message with keys",
                signature.verify_with_keys(&keys, &hashed),
            ),
            (
                "prepared message with keys",
                signature.verify_prepared_with_keys(&keys, &prepared),
            ),
            ("hashed group slice", signature.verify_groups(&groups)),
            (
                "prepared group slice",
                signature.verify_prepared_groups(&prepared_groups),
            ),
            ("hashed stream", hashed_stream),
            ("prepared stream", prepared_stream),
            ("mixed stream", mixed_stream),
        ] {
            assert!(!result, "{path}");
        }
    }

    #[test]
    fn streaming_grouping_rejects_cancellation_after_many_distinct_messages() {
        let shared_message = b"shared message";
        let (first_key, first_signature) = participant(scalar(1), shared_message);
        let (inverse_key, inverse_signature) = participant(
            hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),
            shared_message,
        );
        let shared_message = HashedMessage::new(shared_message);
        let mut signatures = vec![first_signature];
        let mut verifier = AggregateVerifier::new(MILLER_LOOP_BATCH_SIZE);

        verifier
            .add(&AggregatePublicKey::from(first_key), &shared_message)
            .unwrap();

        for value in 2..=MILLER_LOOP_BATCH_SIZE as u8 {
            let message_bytes = [value];
            let (key, signature) = participant(scalar(value), &message_bytes);
            verifier
                .add(
                    &AggregatePublicKey::from(key),
                    &HashedMessage::new(&message_bytes),
                )
                .unwrap();
            signatures.push(signature);
        }

        verifier
            .add(&AggregatePublicKey::from(inverse_key), &shared_message)
            .unwrap();
        signatures.push(inverse_signature);

        assert_eq!(verifier.groups.len(), MILLER_LOOP_BATCH_SIZE);
        assert!(!verifier.finish_and_reset(&aggregate_signatures(&signatures)));
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
        let mut verifier = AggregateVerifier::try_with_initial_capacity(4, 4).unwrap();
        let capacity = verifier.groups.capacity();

        assert!(capacity >= 4);

        verifier.add_prepared(&key, &prepared).unwrap();
        assert!(!verifier.finish_and_reset(&wrong_signature));
        assert_eq!(verifier.groups.capacity(), capacity);
        assert!(verifier.groups.is_empty());
        assert_eq!(Arc::strong_count(&prepared.lines), 1);

        verifier.add_prepared(&key, &prepared).unwrap();
        assert!(verifier.finish_and_reset(&signature));
        assert_eq!(verifier.groups.capacity(), capacity);
        assert_eq!(Arc::strong_count(&prepared.lines), 1);

        assert!(!verifier.finish_and_reset(&signature));
        assert_eq!(verifier.groups.capacity(), capacity);

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

        assert_eq!(verifier.groups.capacity(), 0);

        for message in &messages {
            verifier.add(&key, message).unwrap();
        }
        let grown_capacity = verifier.groups.capacity();

        assert!(grown_capacity >= messages.len());

        assert!(!verifier.finish_and_reset(&signature));
        assert_eq!(verifier.groups.capacity(), grown_capacity);
    }

    #[test]
    fn initial_capacity_is_capped_at_the_distinct_message_limit() {
        let verifier = AggregateVerifier::try_with_initial_capacity(0, usize::MAX).unwrap();

        assert_eq!(verifier.maximum_distinct_messages, 0);
        assert_eq!(verifier.groups.capacity(), 0);
    }

    #[test]
    fn unrepresentable_initial_capacity_returns_an_error() {
        assert!(AggregateVerifier::try_with_initial_capacity(usize::MAX, usize::MAX).is_err());
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
        let grouped_key = verifier.groups[&first].key;
        let capacity = verifier.groups.capacity();

        assert_eq!(verifier.add(&key, &second), Err(error));
        assert_eq!(verifier.add(&key, &first), Err(error));
        assert_eq!(verifier.groups.len(), 1);
        assert_eq!(verifier.groups.capacity(), capacity);
        assert_eq!(verifier.groups[&first].key, grouped_key);
        assert!(!verifier.finish_and_reset(&signature));
        assert!(verifier.groups.is_empty());
        assert_eq!(verifier.groups.capacity(), capacity);
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
    fn overflow_rejects_an_otherwise_valid_batch() {
        let mut signatures = Vec::new();
        let error = TooManyDistinctMessagesError {
            maximum: MILLER_LOOP_BATCH_SIZE,
        };
        let mut verifier = AggregateVerifier::new(MILLER_LOOP_BATCH_SIZE);

        for value in 1..=MILLER_LOOP_BATCH_SIZE as u8 {
            let (key, signature) = participant(scalar(value), &[value]);
            verifier
                .add(
                    &AggregatePublicKey::from(key),
                    &HashedMessage::new(&[value]),
                )
                .unwrap();
            signatures.push(signature);
        }

        let (key, _) = participant(scalar(1), b"excess");
        let key = AggregatePublicKey::from(key);
        assert_eq!(
            verifier.add(&key, &HashedMessage::new(b"excess")),
            Err(error)
        );
        assert!(!verifier.finish_and_reset(&aggregate_signatures(&signatures)));
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
    fn reset_discards_pending_groups() {
        let (key, signature) = participant(scalar(1), b"message");
        let key = AggregatePublicKey::from(key);
        let signature = AggregateSignature::from(signature);
        let message = HashedMessage::new(b"message");
        let error = TooManyDistinctMessagesError { maximum: 1 };
        let mut verifier = AggregateVerifier::try_with_initial_capacity(1, 1).unwrap();
        let capacity = verifier.groups.capacity();

        let wrong_message = HashedMessage::new(b"wrong message").prepare();
        let lines = Arc::downgrade(&wrong_message.lines);
        verifier.add_prepared(&key, &wrong_message).unwrap();
        drop(wrong_message);
        assert_eq!(lines.strong_count(), 1);
        assert_eq!(verifier.add(&key, &message), Err(error));
        verifier.reset();

        assert_eq!(lines.strong_count(), 0);
        assert!(verifier.groups.is_empty());
        assert_eq!(verifier.groups.capacity(), capacity);
        assert!(!verifier.overflowed);

        verifier.add(&key, &message).unwrap();
        assert!(verifier.finish_and_reset(&signature));
    }

    #[test]
    fn verifier_debug_omits_grouping_state() {
        let debug = format!("{:?}", AggregateVerifier::new(1));

        assert_eq!(debug, "AggregateVerifier { .. }");
    }
}
