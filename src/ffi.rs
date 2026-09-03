use alloc::boxed::Box;
use core::mem::MaybeUninit;
use core::ptr;
#[cfg(feature = "signing")]
use core::sync::atomic::{Ordering, compiler_fence};

use crate::suite::SIGNATURE_DST;

pub(crate) type G2Affine = blst::blst_p2_affine;
pub(crate) type PreparedLines = [blst::blst_fp6; 68];
#[cfg(feature = "signing")]
pub(crate) type Scalar = blst::blst_scalar;

pub(crate) fn hash_message(message: &[u8]) -> G2Affine {
    let mut projective = MaybeUninit::<blst::blst_p2>::uninit();
    let mut affine = MaybeUninit::<G2Affine>::uninit();

    unsafe {
        // BLST initializes both outputs and accepts a null augmentation when
        // its length is zero.
        blst::blst_hash_to_g2(
            projective.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            SIGNATURE_DST.as_ptr(),
            SIGNATURE_DST.len(),
            ptr::null(),
            0,
        );
        blst::blst_p2_to_affine(affine.as_mut_ptr(), projective.as_ptr());
        affine.assume_init()
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

#[cfg(test)]
pub(crate) fn compress_g2(point: &G2Affine) -> [u8; 96] {
    let mut bytes = [0; 96];

    unsafe {
        blst::blst_p2_affine_compress(bytes.as_mut_ptr(), point);
    }

    bytes
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
