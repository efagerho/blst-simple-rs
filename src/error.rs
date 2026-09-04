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
pub struct InvalidProofError;

impl fmt::Display for InvalidProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proof of possession verification failed")
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
pub enum AggregateError {
    /// The input is empty or its public keys cancel to the identity.
    InvalidKeyCombination,
}

impl fmt::Display for AggregateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyCombination => {
                f.write_str("public keys form an invalid aggregate combination")
            }
        }
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

impl core::error::Error for AggregateError {}
