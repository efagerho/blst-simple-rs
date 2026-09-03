use core::fmt;

use crate::MissingBlstType;

/// A message hashed to G2 under the fixed signature ciphersuite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HashedMessage {
    // Missing BLST type: `blst_p2_affine`.
    _missing_blst_p2_affine: MissingBlstType,
}

impl HashedMessage {
    /// Hashes arbitrary bytes to G2 using RFC 9380 and the fixed signature DST.
    #[must_use]
    pub fn new(_message: &[u8]) -> Self {
        unimplemented!("message hashing requires BLST")
    }

    /// Precomputes reusable Miller-loop line coefficients for this message.
    ///
    /// Preparation pays off from the second verification of the same message
    /// onward. For a message verified once, verify the [`HashedMessage`]
    /// directly: BLST performs this same precomputation internally, so
    /// preparing first does identical work plus a heap allocation.
    #[must_use]
    pub fn prepare(&self) -> PreparedMessage {
        unimplemented!("message preparation requires BLST")
    }
}

/// A hashed message with heap-backed reusable Miller-loop line coefficients.
///
/// This type does not implement `Clone`. The omitted BLST line table is
/// approximately 19 KiB and heap-backed.
pub struct PreparedMessage {
    hashed_message: HashedMessage,
    // Missing BLST type: `Box<[blst_fp6; 68]>`.
    _missing_blst_fp6_lines: MissingBlstType,
}

impl PreparedMessage {
    /// Hashes a message and prepares its line coefficients in one allocation.
    ///
    /// As with [`HashedMessage::prepare`], this pays off only when the message
    /// is verified more than once.
    #[must_use]
    pub fn hash_and_prepare(_message: &[u8]) -> Self {
        unimplemented!("message hashing and preparation require BLST")
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
