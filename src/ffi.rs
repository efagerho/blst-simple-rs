use alloc::boxed::Box;
use core::mem::MaybeUninit;
use core::ptr;
#[cfg(feature = "signing")]
use core::sync::atomic::{Ordering, compiler_fence};

use crate::DecodeError;
use crate::suite::{PROOF_OF_POSSESSION_DST, SIGNATURE_DST};

pub(crate) type G1Affine = blst::blst_p1_affine;
pub(crate) type G2Affine = blst::blst_p2_affine;
pub(crate) type PreparedLines = [blst::blst_fp6; 68];
#[cfg(feature = "signing")]
pub(crate) type Scalar = blst::blst_scalar;

pub(crate) fn hash_message(message: &[u8]) -> G2Affine {
    hash_to_g2(message, SIGNATURE_DST)
}

fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Affine {
    let projective = hash_to_g2_projective(message, dst);
    let mut affine = MaybeUninit::<G2Affine>::uninit();

    unsafe {
        blst::blst_p2_to_affine(affine.as_mut_ptr(), &projective);
        affine.assume_init()
    }
}

fn hash_to_g2_projective(message: &[u8], dst: &[u8]) -> blst::blst_p2 {
    let mut projective = MaybeUninit::<blst::blst_p2>::uninit();

    unsafe {
        // BLST initializes the output and accepts a null augmentation when its
        // length is zero.
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

    unsafe {
        blst::blst_p1_affine_compress(bytes.as_mut_ptr(), point);
    }

    bytes
}

pub(crate) fn decode_non_identity_g1(bytes: &[u8; 48]) -> Result<G1Affine, DecodeError> {
    let mut point = MaybeUninit::<G1Affine>::uninit();

    unsafe {
        match blst::blst_p1_uncompress(point.as_mut_ptr(), bytes.as_ptr()) {
            blst::BLST_ERROR::BLST_SUCCESS => {}
            blst::BLST_ERROR::BLST_BAD_ENCODING => return Err(DecodeError::BadEncoding),
            blst::BLST_ERROR::BLST_POINT_NOT_ON_CURVE => return Err(DecodeError::NotOnCurve),
            blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP => return Err(DecodeError::NotInGroup),
            blst::BLST_ERROR::BLST_PK_IS_INFINITY => return Err(DecodeError::PointAtInfinity),
            error => unreachable!("unexpected BLST decoding error: {error:?}"),
        }

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

    unsafe {
        // BLST initializes all 68 coefficients in the aligned boxed array.
        blst::blst_precompute_lines(lines.as_mut_ptr().cast(), message);
        lines.assume_init()
    }
}

pub(crate) fn compress_g2(point: &G2Affine) -> [u8; 96] {
    let mut bytes = [0; 96];

    unsafe {
        blst::blst_p2_affine_compress(bytes.as_mut_ptr(), point);
    }

    bytes
}

pub(crate) fn decode_non_identity_g2(bytes: &[u8; 96]) -> Result<G2Affine, DecodeError> {
    let mut point = MaybeUninit::<G2Affine>::uninit();

    unsafe {
        match blst::blst_p2_uncompress(point.as_mut_ptr(), bytes.as_ptr()) {
            blst::BLST_ERROR::BLST_SUCCESS => {}
            blst::BLST_ERROR::BLST_BAD_ENCODING => return Err(DecodeError::BadEncoding),
            blst::BLST_ERROR::BLST_POINT_NOT_ON_CURVE => return Err(DecodeError::NotOnCurve),
            blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP => return Err(DecodeError::NotInGroup),
            blst::BLST_ERROR::BLST_PK_IS_INFINITY => return Err(DecodeError::PointAtInfinity),
            error => unreachable!("unexpected BLST decoding error: {error:?}"),
        }

        let point = point.assume_init();
        if blst::blst_p2_affine_is_inf(&point) {
            return Err(DecodeError::PointAtInfinity);
        }
        if !blst::blst_p2_affine_in_g2(&point) {
            return Err(DecodeError::NotInGroup);
        }
        Ok(point)
    }
}

pub(crate) fn verify_proof(public_key: &G1Affine, proof: &G2Affine) -> bool {
    let public_key_bytes = compress_g1(public_key);
    let message = hash_to_g2(&public_key_bytes, PROOF_OF_POSSESSION_DST);
    let mut message_pairing = MaybeUninit::<blst::blst_fp12>::uninit();
    let mut proof_pairing = MaybeUninit::<blst::blst_fp12>::uninit();

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

    unsafe {
        blst::blst_sign_pk2_in_g1(ptr::null_mut(), signature.as_mut_ptr(), message, scalar);
        signature.assume_init()
    }
}

#[cfg(feature = "signing")]
pub(crate) fn decode_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut scalar = MaybeUninit::<Scalar>::uninit();

    unsafe {
        blst::blst_scalar_from_bendian(scalar.as_mut_ptr(), bytes.as_ptr());
        let scalar = scalar.assume_init();
        blst::blst_sk_check(&scalar).then_some(scalar)
    }
}

#[cfg(feature = "signing")]
pub(crate) fn encode_scalar(scalar: &Scalar) -> [u8; 32] {
    let mut bytes = [0; 32];

    unsafe {
        blst::blst_bendian_from_scalar(bytes.as_mut_ptr(), scalar);
    }

    bytes
}

#[cfg(feature = "signing")]
pub(crate) fn derive_key_material(key_material: &[u8], salt: &[u8], key_info: &[u8]) -> Scalar {
    assert!(key_material.len() >= 32, "key material is too short");

    let mut scalar = MaybeUninit::<Scalar>::uninit();

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
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}
