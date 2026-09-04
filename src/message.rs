use alloc::boxed::Box;
use core::fmt;
use core::hash::{Hash, Hasher};

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
    /// Preparation pays off from the second verification of the same message
    /// onward. For a message verified once, verify the [`HashedMessage`]
    /// directly: BLST performs this same precomputation internally, so
    /// preparing first does identical work plus a heap allocation.
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
        for coordinate in [&self.point.x, &self.point.y] {
            for component in &coordinate.fp {
                component.l.hash(state);
            }
        }
    }
}

/// A hashed message with heap-backed reusable Miller-loop line coefficients.
///
/// This type does not implement `Clone`. Its line table is approximately 19
/// KiB and heap-backed.
pub struct PreparedMessage {
    hashed_message: HashedMessage,
    pub(crate) lines: Box<PreparedLines>,
}

impl PreparedMessage {
    /// Hashes a message and prepares its line coefficients in one allocation.
    ///
    /// As with [`HashedMessage::prepare`], this pays off only when the message
    /// is verified more than once.
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
    extern crate std;

    use core::hash::{Hash, Hasher};

    use std::collections::hash_map::DefaultHasher;
    use std::format;

    use super::{HashedMessage, PreparedMessage};
    use crate::ffi;

    fn hash(message: &HashedMessage) -> u64 {
        let mut hasher = DefaultHasher::new();
        message.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn hashes_empty_and_binary_messages() {
        let empty = HashedMessage::new(b"");
        let prepared_empty = PreparedMessage::hash_and_prepare(b"");

        assert_eq!(prepared_empty.as_hashed_message(), &empty);
        let _ = HashedMessage::new(b"a\0\xffb");
    }

    #[test]
    fn equal_messages_compare_and_hash_equally() {
        let first = HashedMessage::new(b"same message");
        let second = HashedMessage::new(b"same message");

        assert_eq!(first, second);
        assert_eq!(hash(&first), hash(&second));
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
    fn prepare_retains_the_hashed_message() {
        let hashed = HashedMessage::new(b"prepared message");
        let prepared = hashed.prepare();

        assert_eq!(prepared.as_hashed_message(), &hashed);
    }

    #[test]
    fn hash_and_prepare_retains_the_expected_hashed_message() {
        let prepared = PreparedMessage::hash_and_prepare(b"prepared message");
        let hashed = HashedMessage::new(b"prepared message");

        assert_eq!(prepared.as_hashed_message(), &hashed);
    }

    #[test]
    fn prepared_debug_omits_the_line_table() {
        let prepared = PreparedMessage::hash_and_prepare(b"prepared message");
        let debug = format!("{prepared:?}");

        assert!(debug.starts_with("PreparedMessage"));
        assert!(!debug.contains("lines"));
    }
}
