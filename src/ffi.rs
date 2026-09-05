use core::hash::{Hash, Hasher};
use core::mem::MaybeUninit;
use core::ptr;
#[cfg(feature = "signing")]
use core::sync::atomic::{Ordering, compiler_fence};

use crate::DecodeError;
use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};

pub(crate) type G1Affine = blst::blst_p1_affine;
pub(crate) type G1Projective = blst::blst_p1;
pub(crate) type G2Affine = blst::blst_p2_affine;
pub(crate) type G2Projective = blst::blst_p2;
pub(crate) type MillerLoopResult = blst::blst_fp12;
pub(crate) type PreparedLines = [blst::blst_fp6; 68];
pub(crate) const MILLER_LOOP_BATCH_SIZE: usize = 16;
#[cfg(feature = "signing")]
pub(crate) type Scalar = blst::blst_scalar;

pub(crate) fn hash_g1<H: Hasher>(point: &G1Affine, state: &mut H) {
    for coordinate in [&point.x, &point.y] {
        coordinate.l.hash(state);
    }
}

pub(crate) fn hash_g2<H: Hasher>(point: &G2Affine, state: &mut H) {
    for coordinate in [&point.x, &point.y] {
        for component in &coordinate.fp {
            component.l.hash(state);
        }
    }
}

pub(crate) fn hash_message(message: &[u8]) -> G2Affine {
    hash_to_g2(message, SIGNATURE_DST)
}

fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Affine {
    let projective = hash_to_g2_projective(message, dst);
    let mut affine = MaybeUninit::<G2Affine>::uninit();

    // SAFETY: `projective` is initialized, and BLST writes one complete
    // `G2Affine` to the properly aligned output before it is read.
    unsafe {
        blst::blst_p2_to_affine(affine.as_mut_ptr(), &projective);
        affine.assume_init()
    }
}

fn hash_to_g2_projective(message: &[u8], dst: &[u8]) -> blst::blst_p2 {
    let mut projective = MaybeUninit::<blst::blst_p2>::uninit();

    // SAFETY: The slice pointers are valid for their corresponding lengths.
    // BLST accepts a null augmentation with length zero and initializes the
    // complete projective output.
    unsafe {
        blst::blst_hash_to_g2(
            projective.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            dst.as_ptr(),
            dst.len(),
            ptr::null(),
            0,
        );
        projective.assume_init()
    }
}

pub(crate) fn compress_g1(point: &G1Affine) -> [u8; 48] {
    let mut bytes = [0; 48];

    // SAFETY: `point` is initialized, and `bytes` has the 48 bytes required
    // for a compressed G1 encoding.
    unsafe {
        blst::blst_p1_affine_compress(bytes.as_mut_ptr(), point);
    }

    bytes
}

fn decode_status(status: blst::BLST_ERROR) -> Result<(), DecodeError> {
    match status {
        blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
        blst::BLST_ERROR::BLST_BAD_ENCODING => Err(DecodeError::BadEncoding),
        blst::BLST_ERROR::BLST_POINT_NOT_ON_CURVE => Err(DecodeError::NotOnCurve),
        blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP => Err(DecodeError::NotInGroup),
        blst::BLST_ERROR::BLST_PK_IS_INFINITY => Err(DecodeError::PointAtInfinity),
        _ => Err(DecodeError::BadEncoding),
    }
}

pub(crate) fn decode_non_identity_g1(bytes: &[u8; 48]) -> Result<G1Affine, DecodeError> {
    let mut point = MaybeUninit::<G1Affine>::uninit();

    // SAFETY: `bytes` contains 48 readable bytes and `point` is aligned output
    // storage. A successful uncompress call initializes `point` before the
    // predicates or Rust read it.
    unsafe {
        decode_status(blst::blst_p1_uncompress(point.as_mut_ptr(), bytes.as_ptr()))?;

        let point = point.assume_init();
        if blst::blst_p1_affine_is_inf(&point) {
            return Err(DecodeError::PointAtInfinity);
        }
        if !blst::blst_p1_affine_in_g1(&point) {
            return Err(DecodeError::NotInGroup);
        }
        Ok(point)
    }
}

pub(crate) fn precompute_lines(message: &G2Affine) -> Box<PreparedLines> {
    let mut lines = Box::<PreparedLines>::new_uninit();

    // SAFETY: `message` is initialized, and the aligned boxed output has room
    // for all 68 coefficients that BLST initializes.
    unsafe {
        blst::blst_precompute_lines(lines.as_mut_ptr().cast(), message);
        lines.assume_init()
    }
}

pub(crate) fn compress_g2(point: &G2Affine) -> [u8; 96] {
    let mut bytes = [0; 96];

    // SAFETY: `point` is initialized, and `bytes` has the 96 bytes required
    // for a compressed G2 encoding.
    unsafe {
        blst::blst_p2_affine_compress(bytes.as_mut_ptr(), point);
    }

    bytes
}

pub(crate) fn decode_non_identity_g2(bytes: &[u8; 96]) -> Result<G2Affine, DecodeError> {
    let point = decode_g2(bytes)?;

    // SAFETY: `point` was fully initialized by `decode_g2` and remains valid
    // for the duration of this read-only predicate call.
    unsafe {
        if blst::blst_p2_affine_is_inf(&point) {
            return Err(DecodeError::PointAtInfinity);
        }
    }

    Ok(point)
}

pub(crate) fn decode_g2(bytes: &[u8; 96]) -> Result<G2Affine, DecodeError> {
    let mut point = MaybeUninit::<G2Affine>::uninit();

    // SAFETY: `bytes` contains 96 readable bytes and `point` is aligned output
    // storage. A successful uncompress call initializes `point` before the
    // predicate or Rust reads it.
    unsafe {
        decode_status(blst::blst_p2_uncompress(point.as_mut_ptr(), bytes.as_ptr()))?;

        let point = point.assume_init();
        if !blst::blst_p2_affine_in_g2(&point) {
            return Err(DecodeError::NotInGroup);
        }
        Ok(point)
    }
}

pub(crate) fn g1_from_affine(point: &G1Affine) -> G1Projective {
    let mut projective = MaybeUninit::<G1Projective>::uninit();

    // SAFETY: `point` is initialized, and BLST writes one complete
    // `G1Projective` to the properly aligned output before it is read.
    unsafe {
        blst::blst_p1_from_affine(projective.as_mut_ptr(), point);
        projective.assume_init()
    }
}

pub(crate) fn add_g1_affine(accumulator: &mut G1Projective, point: &G1Affine) {
    // SAFETY: Both points are initialized, and BLST supports aliasing its
    // projective output with its projective input for in-place accumulation.
    unsafe {
        let accumulator = accumulator as *mut G1Projective;
        blst::blst_p1_add_or_double_affine(accumulator, accumulator, point);
    }
}

pub(crate) fn g1_to_affine(point: &G1Projective) -> G1Affine {
    let mut affine = MaybeUninit::<G1Affine>::uninit();

    // SAFETY: `point` is initialized, and BLST writes one complete `G1Affine`
    // to the properly aligned output before it is read.
    unsafe {
        blst::blst_p1_to_affine(affine.as_mut_ptr(), point);
        affine.assume_init()
    }
}

pub(crate) fn g1_is_identity(point: &G1Projective) -> bool {
    // SAFETY: `point` is initialized and valid for this read-only predicate.
    unsafe { blst::blst_p1_is_inf(point) }
}

fn g1_affine_is_identity(point: &G1Affine) -> bool {
    // SAFETY: `point` is initialized and valid for this read-only predicate.
    unsafe { blst::blst_p1_affine_is_inf(point) }
}

pub(crate) fn g2_from_affine(point: &G2Affine) -> G2Projective {
    let mut projective = MaybeUninit::<G2Projective>::uninit();

    // SAFETY: `point` is initialized, and BLST writes one complete
    // `G2Projective` to the properly aligned output before it is read.
    unsafe {
        blst::blst_p2_from_affine(projective.as_mut_ptr(), point);
        projective.assume_init()
    }
}

pub(crate) fn add_g2_affine(accumulator: &mut G2Projective, point: &G2Affine) {
    // SAFETY: Both points are initialized, and BLST supports aliasing its
    // projective output with its projective input for in-place accumulation.
    unsafe {
        let accumulator = accumulator as *mut G2Projective;
        blst::blst_p2_add_or_double_affine(accumulator, accumulator, point);
    }
}

pub(crate) fn g2_to_affine(point: &G2Projective) -> G2Affine {
    let mut affine = MaybeUninit::<G2Affine>::uninit();

    // SAFETY: `point` is initialized, and BLST writes one complete `G2Affine`
    // to the properly aligned output before it is read.
    unsafe {
        blst::blst_p2_to_affine(affine.as_mut_ptr(), point);
        affine.assume_init()
    }
}

fn g2_is_identity(point: &G2Affine) -> bool {
    // SAFETY: `point` is initialized and valid for this read-only predicate.
    unsafe { blst::blst_p2_affine_is_inf(point) }
}

pub(crate) fn verify_signature(key: &G1Affine, message: &G2Affine, signature: &G2Affine) -> bool {
    let product = miller_loop(key, message);
    verify_miller_loop_product(&product, signature)
}

pub(crate) fn verify_prepared_signature(
    key: &G1Affine,
    message: &PreparedLines,
    signature: &G2Affine,
) -> bool {
    let product = miller_loop_prepared(key, message);
    verify_miller_loop_product(&product, signature)
}

pub(crate) fn miller_loop(key: &G1Affine, message: &G2Affine) -> MillerLoopResult {
    let mut result = MaybeUninit::<MillerLoopResult>::uninit();

    // SAFETY: Both input points are initialized. The single-point primitive
    // accepts identity points and writes one complete Miller-loop result to
    // the properly aligned output before it is read.
    unsafe {
        blst::blst_miller_loop(result.as_mut_ptr(), message, key);
        result.assume_init()
    }
}

/// Computes a batch of Miller loops.
///
/// # Panics
///
/// Panics unless the slices have the same nonzero length, fit in one batch,
/// and contain no identity points. The batched primitive does not treat an
/// identity input as the multiplicative identity.
pub(crate) fn miller_loop_many(keys: &[G1Affine], messages: &[G2Affine]) -> MillerLoopResult {
    assert_eq!(
        keys.len(),
        messages.len(),
        "miller-loop key and message counts differ"
    );
    assert!(!keys.is_empty(), "miller-loop batch must not be empty");
    assert!(
        keys.len() <= MILLER_LOOP_BATCH_SIZE,
        "miller-loop batch exceeds maximum size"
    );
    assert!(
        keys.iter().all(|key| !g1_affine_is_identity(key)),
        "miller-loop keys must not contain the identity"
    );
    assert!(
        messages.iter().all(|message| !g2_is_identity(message)),
        "miller-loop messages must not contain the identity"
    );

    let mut key_pointers = [ptr::null::<G1Affine>(); MILLER_LOOP_BATCH_SIZE];
    let mut message_pointers = [ptr::null::<G2Affine>(); MILLER_LOOP_BATCH_SIZE];
    for (index, (key, message)) in keys.iter().zip(messages).enumerate() {
        key_pointers[index] = key;
        message_pointers[index] = message;
    }

    let mut result = MaybeUninit::<MillerLoopResult>::uninit();
    // SAFETY: The assertions bound the nonzero count by both pointer arrays
    // and exclude identity inputs. Their first `keys.len()` entries point to
    // initialized values that remain alive for the call, and BLST initializes
    // the complete output.
    unsafe {
        blst::blst_miller_loop_n(
            result.as_mut_ptr(),
            message_pointers.as_ptr(),
            key_pointers.as_ptr(),
            keys.len(),
        );
        result.assume_init()
    }
}

pub(crate) fn miller_loop_prepared(key: &G1Affine, lines: &PreparedLines) -> MillerLoopResult {
    let mut result = MaybeUninit::<MillerLoopResult>::uninit();

    // SAFETY: `key` and all 68 prepared coefficients are initialized, and BLST
    // writes one complete Miller-loop result before it is read.
    unsafe {
        blst::blst_miller_loop_lines(result.as_mut_ptr(), lines.as_ptr(), key);
        result.assume_init()
    }
}

pub(crate) fn miller_loop_identity() -> MillerLoopResult {
    // SAFETY: BLST returns a non-null pointer to a static, initialized value.
    unsafe { *blst::blst_fp12_one() }
}

pub(crate) fn multiply_miller_loop(accumulator: &mut MillerLoopResult, term: &MillerLoopResult) {
    // SAFETY: Both operands are initialized, and BLST supports aliasing the
    // output with the first input for in-place multiplication.
    unsafe {
        let accumulator = accumulator as *mut MillerLoopResult;
        blst::blst_fp12_mul(accumulator, accumulator, term);
    }
}

pub(crate) fn verify_miller_loop_product(product: &MillerLoopResult, signature: &G2Affine) -> bool {
    // SAFETY: BLST returns a non-null pointer to a static, initialized affine
    // generator.
    let generator = unsafe { &*blst::blst_p1_affine_generator() };
    let signature = miller_loop(generator, signature);

    // SAFETY: Both Miller-loop results are initialized and remain valid for
    // this read-only comparison.
    unsafe { blst::blst_fp12_finalverify(product, &signature) }
}

pub(crate) fn verify_proof(public_key: &G1Affine, proof: &G2Affine) -> bool {
    let public_key_bytes = compress_g1(public_key);
    let message = hash_to_g2(&public_key_bytes, PROOF_OF_POSSESSION_DST);
    let mut message_pairing = MaybeUninit::<blst::blst_fp12>::uninit();
    let mut proof_pairing = MaybeUninit::<blst::blst_fp12>::uninit();

    // SAFETY: The input points and BLST's static generator are initialized.
    // Both Miller-loop calls initialize their outputs before finalverify reads
    // them.
    unsafe {
        blst::blst_miller_loop(message_pairing.as_mut_ptr(), &message, public_key);
        blst::blst_miller_loop(
            proof_pairing.as_mut_ptr(),
            proof,
            blst::blst_p1_affine_generator(),
        );
        blst::blst_fp12_finalverify(message_pairing.as_ptr(), proof_pairing.as_ptr())
    }
}

#[cfg(feature = "signing")]
pub(crate) fn derive_public_key(scalar: &Scalar) -> G1Affine {
    let mut projective = MaybeUninit::<blst::blst_p1>::uninit();
    let mut affine = MaybeUninit::<G1Affine>::uninit();

    // SAFETY: `scalar` is initialized and valid. BLST initializes `projective`
    // before the conversion reads it, then initializes `affine` before Rust
    // reads it.
    unsafe {
        blst::blst_sk_to_pk_in_g1(projective.as_mut_ptr(), scalar);
        blst::blst_p1_to_affine(affine.as_mut_ptr(), projective.as_ptr());
        affine.assume_init()
    }
}

#[cfg(feature = "signing")]
pub(crate) fn sign_message(scalar: &Scalar, message: &[u8]) -> G2Affine {
    let message = hash_to_g2_projective(message, SIGNATURE_DST);
    sign_projective(scalar, &message)
}

#[cfg(feature = "signing")]
pub(crate) fn sign_hashed_message(scalar: &Scalar, message: &G2Affine) -> G2Affine {
    let mut projective = MaybeUninit::<blst::blst_p2>::uninit();

    // SAFETY: `message` is initialized, and BLST initializes the complete
    // projective output before it is passed to `sign_projective`.
    unsafe {
        blst::blst_p2_from_affine(projective.as_mut_ptr(), message);
        sign_projective(scalar, &projective.assume_init())
    }
}

#[cfg(feature = "signing")]
pub(crate) fn prove_possession(scalar: &Scalar) -> G2Affine {
    let public_key = derive_public_key(scalar);
    let public_key = compress_g1(&public_key);
    let message = hash_to_g2_projective(&public_key, PROOF_OF_POSSESSION_DST);
    sign_projective(scalar, &message)
}

#[cfg(feature = "signing")]
fn sign_projective(scalar: &Scalar, message: &blst::blst_p2) -> G2Affine {
    let mut signature = MaybeUninit::<G2Affine>::uninit();

    // SAFETY: `message` and `scalar` are initialized. BLST permits a null
    // serialized-output pointer and initializes the affine signature output.
    unsafe {
        blst::blst_sign_pk2_in_g1(ptr::null_mut(), signature.as_mut_ptr(), message, scalar);
        signature.assume_init()
    }
}

#[cfg(feature = "signing")]
pub(crate) fn decode_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut scalar = MaybeUninit::<Scalar>::uninit();

    // SAFETY: `bytes` contains 32 readable bytes. BLST initializes `scalar`
    // before it is read or passed to the validity predicate.
    unsafe {
        blst::blst_scalar_from_bendian(scalar.as_mut_ptr(), bytes.as_ptr());
        let scalar = scalar.assume_init();
        blst::blst_sk_check(&scalar).then_some(scalar)
    }
}

#[cfg(any(feature = "secret-key-export", all(test, feature = "signing")))]
pub(crate) fn encode_scalar(scalar: &Scalar) -> [u8; 32] {
    let mut bytes = [0; 32];

    // SAFETY: `scalar` is initialized, and `bytes` has the 32 writable bytes
    // required for the big-endian encoding.
    unsafe {
        blst::blst_bendian_from_scalar(bytes.as_mut_ptr(), scalar);
    }

    bytes
}

#[cfg(feature = "signing")]
pub(crate) fn derive_key_material(key_material: &[u8], salt: &[u8], key_info: &[u8]) -> Scalar {
    assert!(key_material.len() >= 32, "key material is too short");

    let mut scalar = MaybeUninit::<Scalar>::uninit();

    // SAFETY: Each slice pointer is valid for its corresponding length, and
    // the asserted key-material length satisfies BLST's precondition. BLST
    // initializes `scalar` before it is read or checked.
    unsafe {
        blst::blst_keygen_v5(
            scalar.as_mut_ptr(),
            key_material.as_ptr(),
            key_material.len(),
            salt.as_ptr(),
            salt.len(),
            key_info.as_ptr(),
            key_info.len(),
        );
        let scalar = scalar.assume_init();
        assert!(
            blst::blst_sk_check(&scalar),
            "BLST returned an invalid secret key"
        );
        scalar
    }
}

#[cfg(feature = "signing")]
pub(crate) fn derive_hierarchical_child(parent: &Scalar, index: u32) -> Scalar {
    let mut scalar = MaybeUninit::<Scalar>::uninit();

    // SAFETY: `parent` is an initialized valid scalar, and BLST initializes
    // the child scalar before it is read or checked.
    unsafe {
        blst::blst_derive_child_eip2333(scalar.as_mut_ptr(), parent, index);
        let scalar = scalar.assume_init();
        assert!(
            blst::blst_sk_check(&scalar),
            "BLST returned an invalid child secret key"
        );
        scalar
    }
}

#[cfg(feature = "signing")]
pub(crate) fn zeroize_scalar(scalar: &mut Scalar) {
    for byte in &mut scalar.b {
        // SAFETY: `byte` is a uniquely borrowed, valid `u8` location. The
        // volatile write stores a valid `u8` value without crossing its bounds.
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        G1Affine, G1Projective, G2Affine, G2Projective, MILLER_LOOP_BATCH_SIZE, MillerLoopResult,
        PreparedLines, compress_g2, decode_g2, decode_status, hash_to_g2, miller_loop,
        miller_loop_identity, miller_loop_many,
    };
    use crate::DecodeError;
    use crate::suite::SIGNATURE_DST;

    #[test]
    fn rust_types_match_blst_struct_sizes() {
        // SAFETY: These functions take no arguments and only return structure
        // sizes from the linked BLST library.
        let (g1, g1_affine, g2, g2_affine, fp12) = unsafe {
            (
                blst::blst_p1_sizeof(),
                blst::blst_p1_affine_sizeof(),
                blst::blst_p2_sizeof(),
                blst::blst_p2_affine_sizeof(),
                blst::blst_fp12_sizeof(),
            )
        };

        assert_eq!(
            size_of::<G1Projective>(),
            g1,
            "G1 projective size differs from BLST"
        );
        assert_eq!(
            size_of::<G1Affine>(),
            g1_affine,
            "G1 affine size differs from BLST"
        );
        assert_eq!(
            size_of::<G2Projective>(),
            g2,
            "G2 projective size differs from BLST"
        );
        assert_eq!(
            size_of::<G2Affine>(),
            g2_affine,
            "G2 affine size differs from BLST"
        );
        assert_eq!(
            size_of::<MillerLoopResult>(),
            fp12,
            "Fp12 size differs from BLST"
        );
        assert_eq!(
            size_of::<PreparedLines>(),
            fp12 * 34,
            "prepared line table size differs from 68 BLST Fp6 values"
        );
    }

    #[test]
    fn maps_every_blst_decode_status() {
        use blst::BLST_ERROR::{
            BLST_AGGR_TYPE_MISMATCH, BLST_BAD_ENCODING, BLST_BAD_SCALAR, BLST_PK_IS_INFINITY,
            BLST_POINT_NOT_IN_GROUP, BLST_POINT_NOT_ON_CURVE, BLST_SUCCESS, BLST_VERIFY_FAIL,
        };

        assert_eq!(decode_status(BLST_SUCCESS), Ok(()));
        assert_eq!(
            decode_status(BLST_BAD_ENCODING),
            Err(DecodeError::BadEncoding)
        );
        assert_eq!(
            decode_status(BLST_POINT_NOT_ON_CURVE),
            Err(DecodeError::NotOnCurve)
        );
        assert_eq!(
            decode_status(BLST_POINT_NOT_IN_GROUP),
            Err(DecodeError::NotInGroup)
        );
        assert_eq!(
            decode_status(BLST_PK_IS_INFINITY),
            Err(DecodeError::PointAtInfinity)
        );

        for status in [BLST_AGGR_TYPE_MISMATCH, BLST_VERIFY_FAIL, BLST_BAD_SCALAR] {
            assert_eq!(decode_status(status), Err(DecodeError::BadEncoding));
        }
    }

    #[test]
    fn hashes_empty_message_and_domain_separation_buffers() {
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let secret = blst::min_pk::SecretKey::from_bytes(&scalar).unwrap();

        for (message, dst) in [(&b""[..], SIGNATURE_DST), (&b"message"[..], &b""[..])] {
            assert_eq!(
                compress_g2(&hash_to_g2(message, dst)),
                secret.sign(message, dst, b"").to_bytes()
            );
        }
    }

    #[test]
    fn single_miller_loop_maps_identity_to_gt_identity() {
        let mut encoded_identity = [0; 96];
        encoded_identity[0] = 0xc0;
        let identity = decode_g2(&encoded_identity).unwrap();

        // SAFETY: BLST returns a non-null pointer to a static, initialized
        // affine generator.
        let generator = unsafe { &*blst::blst_p1_affine_generator() };

        assert_eq!(miller_loop(generator, &identity), miller_loop_identity());
    }

    #[test]
    #[should_panic(expected = "miller-loop key and message counts differ")]
    fn rejects_mismatched_miller_loop_inputs() {
        miller_loop_many(&[], &[G2Affine::default()]);
    }

    #[test]
    #[should_panic(expected = "miller-loop batch must not be empty")]
    fn rejects_empty_miller_loop_inputs() {
        miller_loop_many(&[], &[]);
    }

    #[test]
    #[should_panic(expected = "miller-loop batch exceeds maximum size")]
    fn rejects_oversized_miller_loop_batches() {
        miller_loop_many(
            &[G1Affine::default(); MILLER_LOOP_BATCH_SIZE + 1],
            &[G2Affine::default(); MILLER_LOOP_BATCH_SIZE + 1],
        );
    }

    #[test]
    #[should_panic(expected = "miller-loop keys must not contain the identity")]
    fn rejects_identity_miller_loop_keys() {
        let message = hash_to_g2(b"message", SIGNATURE_DST);

        miller_loop_many(&[G1Affine::default()], &[message]);
    }

    #[test]
    #[should_panic(expected = "miller-loop messages must not contain the identity")]
    fn rejects_identity_miller_loop_messages() {
        // SAFETY: BLST returns a non-null pointer to a static, initialized
        // affine generator.
        let key = unsafe { *blst::blst_p1_affine_generator() };

        miller_loop_many(&[key], &[G2Affine::default()]);
    }

    #[cfg(feature = "signing")]
    #[test]
    #[should_panic(expected = "key material is too short")]
    fn rejects_invalid_internal_key_material() {
        super::derive_key_material(b"", b"", b"");
    }

    #[cfg(feature = "signing")]
    #[test]
    fn zeroizes_scalar_storage() {
        let mut bytes = [0; 32];
        bytes[31] = 1;
        let mut scalar = super::decode_scalar(&bytes).unwrap();

        super::zeroize_scalar(&mut scalar);

        assert!(scalar.b.iter().all(|byte| *byte == 0));
    }
}
