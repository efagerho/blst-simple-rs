use alloc::boxed::Box;
use core::mem::MaybeUninit;
use core::ptr;

use crate::suite::SIGNATURE_DST;

pub(crate) type G2Affine = blst::blst_p2_affine;
pub(crate) type PreparedLines = [blst::blst_fp6; 68];

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
