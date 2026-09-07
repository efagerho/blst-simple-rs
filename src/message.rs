use core::fmt;
use core::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::ffi::{self, G2Affine, PreparedLines};

/// A message hashed to G2 under the fixed signature ciphersuite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashedMessage {
    pub(crate) point: G2Affine,
}

impl HashedMessage {
    /// Hashes arbitrary bytes to G2 using RFC 9380 and the fixed signature DST.
    #[must_use]
    pub fn new(message: &[u8]) -> Self {
        Self {
            point: ffi::hash_message(message),
        }
    }

    /// Precomputes reusable Miller-loop line coefficients for this message.
    ///
    /// Preparation lets later verifications reuse these coefficients, but the
    /// performance crossover depends on the workload. In particular, aggregate
    /// verification can batch distinct hashed messages, while prepared messages
    /// are processed individually. Benchmark representative workloads. For one
    /// verification, using the [`HashedMessage`] directly avoids this method's
    /// heap allocation.
    #[must_use]
    pub fn prepare(&self) -> PreparedMessage {
        PreparedMessage {
            hashed_message: *self,
            lines: ffi::precompute_lines(&self.point),
        }
    }
}

impl Hash for HashedMessage {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ffi::hash_g2_coordinates(&self.point, state);
    }
}

/// A hashed message with heap-backed reusable Miller-loop line coefficients.
///
/// This type does not implement `Clone`. Its line table is approximately 19
/// KiB and shared with any [`crate::AggregateVerifier`] that retains it for
/// deferred verification. The table is freed when the message and all such
/// verifiers release it.
pub struct PreparedMessage {
    hashed_message: HashedMessage,
    pub(crate) lines: Arc<PreparedLines>,
}

impl PreparedMessage {
    /// Hashes a message and prepares its line coefficients in one allocation.
    ///
    /// As with [`HashedMessage::prepare`], whether preparation pays off depends
    /// on the verification workload.
    #[must_use]
    pub fn hash_and_prepare(message: &[u8]) -> Self {
        HashedMessage::new(message).prepare()
    }

    /// Returns the hashed-message rung underlying this preparation.
    #[must_use]
    pub fn as_hashed_message(&self) -> &HashedMessage {
        &self.hashed_message
    }
}

impl fmt::Debug for PreparedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedMessage")
            .field("hashed_message", &self.hashed_message)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::format;

    use super::{HashedMessage, PreparedMessage};
    use crate::ffi;
    use crate::test_util::decode_hex_array;
    use serde::Deserialize;

    const SCALAR_ONE_VECTOR: &str = include_str!(
        "../tests/vectors/ethereum/v0.1.0/verify/verifycase_one_privkey_47117849458281be.json"
    );

    #[derive(Deserialize)]
    struct VerificationVector {
        input: VerificationInput,
        output: bool,
    }

    #[derive(Deserialize)]
    struct VerificationInput {
        message: String,
        signature: String,
    }

    #[test]
    fn preparation_retains_empty_and_binary_messages() {
        let cases = [("empty", &b""[..]), ("binary", &b"a\0\xffb"[..])];

        for (case, message) in cases {
            let hashed = HashedMessage::new(message);

            assert_eq!(
                hashed.prepare().as_hashed_message(),
                &hashed,
                "prepare: {case}"
            );
            assert_eq!(
                PreparedMessage::hash_and_prepare(message).as_hashed_message(),
                &hashed,
                "hash and prepare: {case}"
            );
        }
    }

    #[test]
    fn equal_messages_work_as_hash_map_keys() {
        let first = HashedMessage::new(b"same message");
        let second = HashedMessage::new(b"same message");
        let different = HashedMessage::new(b"different message");
        let mut messages = HashMap::new();
        messages.insert(first, "same");

        assert_eq!(first, second);
        assert_ne!(first, different);
        assert_eq!(messages.get(&second), Some(&"same"));
        assert_eq!(messages.get(&different), None);
    }

    #[test]
    fn hashes_with_the_signature_ciphersuite() {
        let message = HashedMessage::new(b"a\0\xffb");
        let actual = ffi::compress_g2(&message.point);
        let expected = [
            145, 174, 185, 55, 24, 103, 238, 38, 66, 47, 216, 72, 105, 175, 236, 20, 165, 115, 56,
            101, 234, 45, 193, 49, 26, 86, 144, 62, 203, 109, 136, 65, 254, 152, 76, 167, 135, 233,
            153, 153, 47, 194, 240, 227, 89, 155, 221, 176, 16, 94, 48, 89, 174, 193, 66, 171, 89,
            229, 43, 28, 8, 248, 12, 105, 136, 24, 177, 125, 22, 103, 3, 160, 72, 18, 63, 163, 148,
            218, 16, 179, 135, 147, 251, 12, 221, 135, 69, 122, 254, 250, 67, 152, 83, 184, 58,
            166,
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn hash_matches_the_scalar_one_signature_vector() {
        let vector: VerificationVector = serde_json::from_str(SCALAR_ONE_VECTOR).unwrap();
        let message: [u8; 32] = decode_hex_array(&vector.input.message);
        let expected: [u8; 96] = decode_hex_array(&vector.input.signature);
        let hashed = HashedMessage::new(&message);

        assert!(vector.output);
        assert_eq!(ffi::compress_g2(&hashed.point), expected);
    }

    #[test]
    fn prepared_debug_omits_the_line_table() {
        let prepared = PreparedMessage::hash_and_prepare(b"prepared message");
        let debug = format!("{prepared:?}");

        assert!(debug.starts_with("PreparedMessage"));
        assert!(!debug.contains("lines"));
    }
}
