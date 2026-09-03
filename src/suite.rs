//! Fixed proof-of-possession ciphersuite parameters.

pub(crate) const SIGNATURE_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub(crate) const PROOF_OF_POSSESSION_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
