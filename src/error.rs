use core::fmt;

/// An error encountered while decoding a compressed curve point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The compressed representation is malformed.
    BadEncoding,
    /// The decoded point is not on the expected curve.
    NotOnCurve,
    /// The decoded point is not in the expected prime-order subgroup.
    NotInGroup,
    /// The decoded point is the identity where the identity is forbidden.
    PointAtInfinity,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadEncoding => "invalid compressed point encoding",
            Self::NotOnCurve => "point is not on the curve",
            Self::NotInGroup => "point is not in the prime-order subgroup",
            Self::PointAtInfinity => "point at infinity is not allowed",
        })
    }
}

/// A decoded proof of possession that did not verify for its public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidProofError {
    /// The proof did not verify for its public key.
    VerificationFailed,
}

impl fmt::Display for InvalidProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed => f.write_str("proof of possession verification failed"),
        }
    }
}

/// An error encountered while decoding or verifying a proof of possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofVerificationError {
    /// The public key could not be decoded or validated.
    PublicKeyDecode(DecodeError),
    /// The proof could not be decoded or validated.
    ProofDecode(DecodeError),
    /// The proof does not verify for the supplied public key.
    InvalidProof,
}

impl From<InvalidProofError> for ProofVerificationError {
    fn from(_: InvalidProofError) -> Self {
        Self::InvalidProof
    }
}

impl fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyDecode(error) => write!(f, "invalid public key: {error}"),
            Self::ProofDecode(error) => write!(f, "invalid proof of possession: {error}"),
            Self::InvalidProof => f.write_str("proof of possession verification failed"),
        }
    }
}

/// An error encountered while constructing an aggregate public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyAggregationError {
    /// No public keys were supplied.
    EmptyInput,
    /// The supplied public keys cancel to the identity.
    KeysCancelToIdentity,
}

impl fmt::Display for PublicKeyAggregationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("cannot aggregate an empty public-key slice"),
            Self::KeysCancelToIdentity => f.write_str("public keys cancel to the identity"),
        }
    }
}

/// A streaming verifier received more distinct messages than configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TooManyDistinctMessagesError {
    /// The configured maximum number of distinct messages.
    pub maximum: usize,
}

impl fmt::Display for TooManyDistinctMessagesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "distinct message limit exceeded (maximum {})",
            self.maximum
        )
    }
}

impl core::error::Error for DecodeError {}

impl core::error::Error for InvalidProofError {}

impl core::error::Error for ProofVerificationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::PublicKeyDecode(error) | Self::ProofDecode(error) => Some(error),
            Self::InvalidProof => None,
        }
    }
}

impl core::error::Error for PublicKeyAggregationError {}

impl core::error::Error for TooManyDistinctMessagesError {}

#[cfg(test)]
mod tests {
    use core::error::Error;

    use std::format;

    use super::{
        DecodeError, InvalidProofError, ProofVerificationError, PublicKeyAggregationError,
        TooManyDistinctMessagesError,
    };

    #[test]
    fn displays_every_error_variant() {
        let cases = [
            (
                "bad encoding",
                format!("{}", DecodeError::BadEncoding),
                "invalid compressed point encoding",
            ),
            (
                "point not on curve",
                format!("{}", DecodeError::NotOnCurve),
                "point is not on the curve",
            ),
            (
                "point not in group",
                format!("{}", DecodeError::NotInGroup),
                "point is not in the prime-order subgroup",
            ),
            (
                "point at infinity",
                format!("{}", DecodeError::PointAtInfinity),
                "point at infinity is not allowed",
            ),
            (
                "invalid proof",
                format!("{}", InvalidProofError::VerificationFailed),
                "proof of possession verification failed",
            ),
            (
                "public key decode",
                format!(
                    "{}",
                    ProofVerificationError::PublicKeyDecode(DecodeError::NotOnCurve)
                ),
                "invalid public key: point is not on the curve",
            ),
            (
                "proof decode",
                format!(
                    "{}",
                    ProofVerificationError::ProofDecode(DecodeError::NotInGroup)
                ),
                "invalid proof of possession: point is not in the prime-order subgroup",
            ),
            (
                "proof verification",
                format!("{}", ProofVerificationError::InvalidProof),
                "proof of possession verification failed",
            ),
            (
                "empty aggregate",
                format!("{}", PublicKeyAggregationError::EmptyInput),
                "cannot aggregate an empty public-key slice",
            ),
            (
                "key cancellation",
                format!("{}", PublicKeyAggregationError::KeysCancelToIdentity),
                "public keys cancel to the identity",
            ),
            (
                "distinct message limit",
                format!("{}", TooManyDistinctMessagesError { maximum: 4 }),
                "distinct message limit exceeded (maximum 4)",
            ),
        ];

        for (case, actual, expected) in cases {
            assert_eq!(actual, expected, "{case}");
        }
    }

    #[test]
    fn proof_verification_errors_expose_only_decode_sources() {
        let public_key = ProofVerificationError::PublicKeyDecode(DecodeError::BadEncoding);
        let proof = ProofVerificationError::ProofDecode(DecodeError::NotInGroup);
        let invalid = ProofVerificationError::from(InvalidProofError::VerificationFailed);

        assert!(public_key.source().is_some());
        assert!(proof.source().is_some());
        assert!(invalid.source().is_none());
        assert_eq!(invalid, ProofVerificationError::InvalidProof);
    }
}
