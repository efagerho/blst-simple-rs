use blst_simple_rs::{
    AggregateSignature, DecodeError, ProofOfPossession, Signature, UnverifiedPublicKey,
};

#[test]
fn rejects_invalid_g2_encodings() {
    let uncompressed = [0; 96];
    let mut malformed_identity = [0; 96];
    malformed_identity[0] = 0xc0;
    malformed_identity[95] = 1;
    let mut not_on_curve = [0; 96];
    not_on_curve[0] = 0x80;
    let mut not_in_group = not_on_curve;
    not_in_group[95] = 2;
    let mut noncanonical_infinity = [0; 96];
    noncanonical_infinity[0] = 0x40;
    let mut noncanonical_compressed_infinity = [0; 96];
    noncanonical_compressed_infinity[0] = 0xe0;

    for (case, bytes, expected) in [
        ("uncompressed", uncompressed, DecodeError::BadEncoding),
        (
            "malformed identity",
            malformed_identity,
            DecodeError::BadEncoding,
        ),
        ("not on curve", not_on_curve, DecodeError::NotOnCurve),
        ("outside subgroup", not_in_group, DecodeError::NotInGroup),
        (
            "noncanonical infinity",
            noncanonical_infinity,
            DecodeError::BadEncoding,
        ),
        (
            "noncanonical compressed infinity",
            noncanonical_compressed_infinity,
            DecodeError::BadEncoding,
        ),
    ] {
        assert_eq!(
            Signature::from_bytes(&bytes).unwrap_err(),
            expected,
            "signature: {case}"
        );
        assert_eq!(
            ProofOfPossession::from_bytes(&bytes).unwrap_err(),
            expected,
            "proof: {case}"
        );
        assert_eq!(
            AggregateSignature::from_bytes(&bytes).unwrap_err(),
            expected,
            "aggregate signature: {case}"
        );
    }

    let mut identity = [0; 96];
    identity[0] = 0xc0;
    assert_eq!(
        Signature::from_bytes(&identity).unwrap_err(),
        DecodeError::PointAtInfinity
    );
    assert_eq!(
        ProofOfPossession::from_bytes(&identity).unwrap_err(),
        DecodeError::PointAtInfinity
    );
    assert_eq!(
        AggregateSignature::from_bytes(&identity)
            .unwrap()
            .to_bytes(),
        identity
    );
}

#[test]
fn rejects_invalid_g1_encodings() {
    let uncompressed = [0; 48];
    let mut identity = [0; 48];
    identity[0] = 0xc0;
    let mut malformed_identity = identity;
    malformed_identity[47] = 1;
    let mut outside_subgroup = [0; 48];
    outside_subgroup[0] = 0x80;
    let mut not_on_curve = outside_subgroup;
    not_on_curve[47] = 1;
    let mut on_curve_outside_subgroup = outside_subgroup;
    on_curve_outside_subgroup[47] = 4;
    let mut noncanonical_infinity = [0; 48];
    noncanonical_infinity[0] = 0x40;
    let mut noncanonical_compressed_infinity = [0; 48];
    noncanonical_compressed_infinity[0] = 0xe0;

    for (case, bytes, expected) in [
        ("uncompressed", uncompressed, DecodeError::BadEncoding),
        ("identity", identity, DecodeError::PointAtInfinity),
        (
            "malformed identity",
            malformed_identity,
            DecodeError::BadEncoding,
        ),
        (
            "outside subgroup",
            outside_subgroup,
            DecodeError::NotInGroup,
        ),
        ("not on curve", not_on_curve, DecodeError::NotOnCurve),
        (
            "on curve outside subgroup",
            on_curve_outside_subgroup,
            DecodeError::NotInGroup,
        ),
        (
            "noncanonical infinity",
            noncanonical_infinity,
            DecodeError::BadEncoding,
        ),
        (
            "noncanonical compressed infinity",
            noncanonical_compressed_infinity,
            DecodeError::BadEncoding,
        ),
    ] {
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&bytes).unwrap_err(),
            expected,
            "public key: {case}"
        );
    }
}
