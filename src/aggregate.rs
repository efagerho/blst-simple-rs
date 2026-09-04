use core::fmt;
use core::hash::{Hash, Hasher};

use crate::ffi::{self, G1Affine, G1Projective, G2Affine, G2Projective};
use crate::{AggregateError, DecodeError, PublicKey, Signature};

/// A decoded aggregate signature in G2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateSignature {
    pub(crate) point: G2Affine,
}

impl AggregateSignature {
    /// Uncompresses and subgroup-checks an aggregate signature, allowing the
    /// identity.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, DecodeError> {
        ffi::decode_g2(bytes).map(|point| Self { point })
    }

    /// Returns the canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 96] {
        ffi::compress_g2(&self.point)
    }
}

impl Hash for AggregateSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_g2(&self.point, state);
    }
}

impl From<&Signature> for AggregateSignature {
    /// Converts one signature into a one-element aggregate.
    fn from(signature: &Signature) -> Self {
        Self {
            point: signature.point,
        }
    }
}

impl From<Signature> for AggregateSignature {
    /// Converts one signature into a one-element aggregate.
    fn from(signature: Signature) -> Self {
        Self::from(&signature)
    }
}

/// A non-empty projective signature accumulator.
#[derive(Clone)]
pub struct AggregateSignatureBuilder {
    point: G2Projective,
}

impl AggregateSignatureBuilder {
    /// Starts an accumulator with one signature.
    #[must_use]
    pub fn new(first: &Signature) -> Self {
        Self {
            point: ffi::g2_from_affine(&first.point),
        }
    }

    /// Starts an accumulator from an existing aggregate signature.
    #[must_use]
    pub fn from_aggregate(first: &AggregateSignature) -> Self {
        Self {
            point: ffi::g2_from_affine(&first.point),
        }
    }

    /// Adds one signature to the accumulator.
    pub fn add(&mut self, signature: &Signature) {
        ffi::add_g2_affine(&mut self.point, &signature.point);
    }

    /// Adds one existing aggregate signature to the accumulator.
    pub fn add_aggregate(&mut self, aggregate: &AggregateSignature) {
        ffi::add_g2_affine(&mut self.point, &aggregate.point);
    }

    /// Adds all signatures in encounter order.
    pub fn extend(&mut self, signatures: &[Signature]) {
        for signature in signatures {
            self.add(signature);
        }
    }

    /// Adds all aggregate signatures in encounter order.
    pub fn extend_aggregates(&mut self, aggregates: &[AggregateSignature]) {
        for aggregate in aggregates {
            self.add_aggregate(aggregate);
        }
    }

    /// Converts this non-empty accumulator to an affine aggregate signature.
    #[must_use]
    pub fn finish(self) -> AggregateSignature {
        AggregateSignature {
            point: ffi::g2_to_affine(&self.point),
        }
    }
}

impl fmt::Debug for AggregateSignatureBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateSignatureBuilder")
            .finish_non_exhaustive()
    }
}

/// An aggregate of public keys that all carry proof-verification capability.
///
/// This type is intentionally not serializable: its value alone cannot prove
/// that every summand supplied a proof of possession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregatePublicKey {
    pub(crate) point: G1Affine,
}

impl AggregatePublicKey {
    /// Aggregates a key slice, returning an error for empty input or when the
    /// sum cancels to the identity.
    pub fn from_keys(keys: &[PublicKey]) -> Result<Self, AggregateError> {
        let Some((first, rest)) = keys.split_first() else {
            return Err(AggregateError::InvalidKeyCombination);
        };

        let mut builder = AggregatePublicKeyBuilder::new(first);
        builder.extend(rest);
        builder.finish()
    }
}

impl Hash for AggregatePublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_g1(&self.point, state);
    }
}

impl From<&PublicKey> for AggregatePublicKey {
    /// Converts one proof-verified public key into a one-element aggregate.
    fn from(key: &PublicKey) -> Self {
        Self {
            point: key.unverified.point,
        }
    }
}

impl From<PublicKey> for AggregatePublicKey {
    /// Converts one proof-verified public key into a one-element aggregate.
    fn from(key: PublicKey) -> Self {
        Self::from(&key)
    }
}

/// A non-empty projective public-key accumulator.
#[derive(Clone)]
pub struct AggregatePublicKeyBuilder {
    point: G1Projective,
}

impl AggregatePublicKeyBuilder {
    /// Starts an accumulator with one proof-verified public key.
    #[must_use]
    pub fn new(first: &PublicKey) -> Self {
        Self {
            point: ffi::g1_from_affine(&first.unverified.point),
        }
    }

    /// Starts an accumulator from an existing aggregate public key.
    #[must_use]
    pub fn from_aggregate(first: &AggregatePublicKey) -> Self {
        Self {
            point: ffi::g1_from_affine(&first.point),
        }
    }

    /// Adds one proof-verified public key.
    pub fn add(&mut self, key: &PublicKey) {
        ffi::add_g1_affine(&mut self.point, &key.unverified.point);
    }

    /// Adds one existing aggregate public key.
    pub fn add_aggregate(&mut self, aggregate: &AggregatePublicKey) {
        ffi::add_g1_affine(&mut self.point, &aggregate.point);
    }

    /// Adds all proof-verified public keys in encounter order.
    pub fn extend(&mut self, keys: &[PublicKey]) {
        for key in keys {
            self.add(key);
        }
    }

    /// Adds all aggregate public keys in encounter order.
    pub fn extend_aggregates(&mut self, aggregates: &[AggregatePublicKey]) {
        for aggregate in aggregates {
            self.add_aggregate(aggregate);
        }
    }

    /// Finishes the aggregate, rejecting a sum that is the identity.
    pub fn finish(self) -> Result<AggregatePublicKey, AggregateError> {
        if ffi::g1_is_identity(&self.point) {
            return Err(AggregateError::InvalidKeyCombination);
        }

        Ok(AggregatePublicKey {
            point: ffi::g1_to_affine(&self.point),
        })
    }
}

impl fmt::Debug for AggregatePublicKeyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregatePublicKeyBuilder")
            .finish_non_exhaustive()
    }
}

fn hash_g1<H: Hasher>(point: &G1Affine, state: &mut H) {
    for coordinate in [&point.x, &point.y] {
        coordinate.l.hash(state);
    }
}

fn hash_g2<H: Hasher>(point: &G2Affine, state: &mut H) {
    for coordinate in [&point.x, &point.y] {
        for component in &coordinate.fp {
            component.l.hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::hash::{Hash, Hasher};

    use std::collections::hash_map::DefaultHasher;
    use std::format;
    use std::vec::Vec;

    use super::{
        AggregatePublicKey, AggregatePublicKeyBuilder, AggregateSignature,
        AggregateSignatureBuilder,
    };
    use crate::ffi;
    use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};
    use crate::{AggregateError, DecodeError, PublicKey, Signature};

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

    fn signature(secret: [u8; 32], message: &[u8]) -> Signature {
        let secret = blst::min_pk::SecretKey::from_bytes(&secret).unwrap();
        let bytes = secret.sign(message, SIGNATURE_DST, b"").to_bytes();
        Signature::from_bytes(&bytes).unwrap()
    }

    fn public_key(secret: [u8; 32]) -> PublicKey {
        let secret = blst::min_pk::SecretKey::from_bytes(&secret).unwrap();
        let key = secret.sk_to_pk().to_bytes();
        let proof = secret.sign(&key, PROOF_OF_POSSESSION_DST, b"").to_bytes();
        PublicKey::from_bytes_with_proof(&key, &proof).unwrap()
    }

    fn upstream_signature_sum(signatures: &[Signature]) -> [u8; 96] {
        let signatures: Vec<_> = signatures
            .iter()
            .map(|signature| blst::min_pk::Signature::from_bytes(&signature.to_bytes()).unwrap())
            .collect();
        let references: Vec<_> = signatures.iter().collect();

        blst::min_pk::AggregateSignature::aggregate(&references, false)
            .unwrap()
            .to_signature()
            .to_bytes()
    }

    fn upstream_key_sum(keys: &[PublicKey]) -> [u8; 48] {
        let keys: Vec<_> = keys
            .iter()
            .map(|key| blst::min_pk::PublicKey::from_bytes(&key.to_bytes()).unwrap())
            .collect();
        let references: Vec<_> = keys.iter().collect();

        blst::min_pk::AggregatePublicKey::aggregate(&references, false)
            .unwrap()
            .to_public_key()
            .to_bytes()
    }

    fn hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn aggregates_signatures_with_complete_addition() {
        let first = signature(scalar(1), b"message");
        let second = signature(scalar(2), b"message");

        let mut builder = AggregateSignatureBuilder::new(&first);
        builder.add(&second);
        let aggregate = builder.finish();
        assert_eq!(
            aggregate.to_bytes(),
            upstream_signature_sum(&[first, second])
        );

        let mut duplicate = AggregateSignatureBuilder::new(&first);
        duplicate.add(&first);
        assert_eq!(
            duplicate.finish().to_bytes(),
            upstream_signature_sum(&[first, first])
        );

        assert_eq!(
            AggregateSignature::from(first),
            AggregateSignatureBuilder::new(&first).finish()
        );
    }

    #[test]
    fn combines_aggregate_signatures() {
        let signatures = [
            signature(scalar(1), b"one"),
            signature(scalar(2), b"two"),
            signature(scalar(3), b"three"),
            signature(scalar(4), b"four"),
        ];

        let mut left = AggregateSignatureBuilder::new(&signatures[0]);
        left.extend(&signatures[1..2]);
        let left = left.finish();
        let mut right = AggregateSignatureBuilder::new(&signatures[2]);
        right.add(&signatures[3]);
        let right = right.finish();

        let mut combined = AggregateSignatureBuilder::from_aggregate(&left);
        combined.add_aggregate(&right);
        let combined = combined.finish();

        let mut extended = AggregateSignatureBuilder::from_aggregate(&left);
        extended.extend_aggregates(&[right]);

        assert_eq!(combined.to_bytes(), upstream_signature_sum(&signatures));
        assert_eq!(extended.finish(), combined);
    }

    #[test]
    fn empty_signature_extensions_are_noops() {
        let signature = signature(scalar(1), b"message");
        let expected = AggregateSignature::from(&signature);
        let mut identity_bytes = [0; 96];
        identity_bytes[0] = 0xc0;
        let identity = AggregateSignature::from_bytes(&identity_bytes).unwrap();
        let mut builder = AggregateSignatureBuilder::new(&signature);

        builder.extend(&[]);
        builder.extend_aggregates(&[]);
        builder.add_aggregate(&identity);

        assert_eq!(builder.finish(), expected);
        assert_eq!(AggregateSignature::from(signature), expected);

        let mut builder = AggregateSignatureBuilder::from_aggregate(&identity);
        builder.add(&signature);
        assert_eq!(builder.finish(), expected);
    }

    #[test]
    fn decodes_aggregate_signatures_and_allows_identity() {
        let first = signature(scalar(1), b"one");
        let second = signature(scalar(2), b"two");
        let mut builder = AggregateSignatureBuilder::new(&first);
        builder.add(&second);
        let aggregate = builder.finish();
        let decoded = AggregateSignature::from_bytes(&aggregate.to_bytes()).unwrap();

        let mut identity = [0; 96];
        identity[0] = 0xc0;
        let identity = AggregateSignature::from_bytes(&identity).unwrap();

        assert_eq!(decoded, aggregate);
        assert_eq!(hash(&decoded), hash(&aggregate));
        assert_eq!(identity.to_bytes()[0], 0xc0);
        assert!(identity.to_bytes()[1..].iter().all(|byte| *byte == 0));
        assert_eq!(
            AggregateSignatureBuilder::from_aggregate(&identity).finish(),
            identity
        );
    }

    #[test]
    fn rejects_invalid_aggregate_signature_encodings() {
        let uncompressed = [0; 96];
        let mut malformed_identity = [0; 96];
        malformed_identity[0] = 0xc0;
        malformed_identity[95] = 1;
        let mut not_on_curve = [0; 96];
        not_on_curve[0] = 0x80;
        let mut not_in_group = not_on_curve;
        not_in_group[95] = 2;

        assert_eq!(
            AggregateSignature::from_bytes(&uncompressed).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            AggregateSignature::from_bytes(&malformed_identity).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            AggregateSignature::from_bytes(&not_on_curve).unwrap_err(),
            DecodeError::NotOnCurve
        );
        assert_eq!(
            AggregateSignature::from_bytes(&not_in_group).unwrap_err(),
            DecodeError::NotInGroup
        );
    }

    #[test]
    fn aggregates_public_keys_with_complete_addition() {
        let first = public_key(scalar(1));
        let second = public_key(scalar(2));
        let keys = [first, second];
        let expected = upstream_key_sum(&keys);

        let aggregate = AggregatePublicKey::from_keys(&keys).unwrap();
        assert_eq!(ffi::compress_g1(&aggregate.point), expected);

        let mut builder = AggregatePublicKeyBuilder::new(&first);
        builder.add(&second);
        assert_eq!(builder.finish().unwrap(), aggregate);

        let mut duplicate = AggregatePublicKeyBuilder::new(&first);
        duplicate.add(&first);
        assert_eq!(
            ffi::compress_g1(&duplicate.finish().unwrap().point),
            upstream_key_sum(&[first, first])
        );

        assert_eq!(
            AggregatePublicKey::from(first),
            AggregatePublicKeyBuilder::new(&first).finish().unwrap()
        );
        assert_eq!(
            AggregatePublicKey::from_keys(&[]),
            Err(AggregateError::InvalidKeyCombination)
        );
    }

    #[test]
    fn combines_aggregate_public_keys() {
        let keys = [
            public_key(scalar(1)),
            public_key(scalar(2)),
            public_key(scalar(3)),
            public_key(scalar(4)),
        ];
        let left = AggregatePublicKey::from_keys(&keys[..2]).unwrap();
        let right = AggregatePublicKey::from_keys(&keys[2..]).unwrap();
        let expected = AggregatePublicKey::from_keys(&keys).unwrap();

        let mut combined = AggregatePublicKeyBuilder::from_aggregate(&left);
        combined.add_aggregate(&right);
        let combined = combined.finish().unwrap();

        let mut extended = AggregatePublicKeyBuilder::from_aggregate(&left);
        extended.extend_aggregates(&[right]);

        assert_eq!(combined, expected);
        assert_eq!(hash(&combined), hash(&expected));
        assert_eq!(extended.finish().unwrap(), expected);
    }

    #[test]
    fn one_key_and_empty_extensions_preserve_the_key() {
        let key = public_key(scalar(1));
        let expected = AggregatePublicKey::from(&key);
        let mut builder = AggregatePublicKeyBuilder::new(&key);

        builder.extend(&[]);
        builder.extend_aggregates(&[]);

        assert_eq!(AggregatePublicKey::from_keys(&[key]).unwrap(), expected);
        assert_eq!(builder.finish().unwrap(), expected);
        assert_eq!(AggregatePublicKey::from(key), expected);
    }

    #[test]
    fn rejects_public_keys_that_cancel_to_identity() {
        let generator = public_key(scalar(1));
        let negative_generator = public_key(hex(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
        ));

        assert_eq!(
            AggregatePublicKey::from_keys(&[generator, negative_generator]),
            Err(AggregateError::InvalidKeyCombination)
        );

        let mut builder = AggregatePublicKeyBuilder::new(&generator);
        builder.add(&negative_generator);
        assert_eq!(builder.finish(), Err(AggregateError::InvalidKeyCombination));
    }

    #[test]
    fn builder_debug_omits_curve_points() {
        let signature = signature(scalar(1), b"message");
        let key = public_key(scalar(1));

        assert_eq!(
            format!("{:?}", AggregateSignatureBuilder::new(&signature)),
            "AggregateSignatureBuilder { .. }"
        );
        assert_eq!(
            format!("{:?}", AggregatePublicKeyBuilder::new(&key)),
            "AggregatePublicKeyBuilder { .. }"
        );
    }
}
