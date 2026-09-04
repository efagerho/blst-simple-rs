use blst_simple_rs::{
    AggregateSignature, DecodeError, ProofOfPossession, Signature, UnverifiedPublicKey,
};

#[test]
fn rejects_noncanonical_infinity_encodings() {
    for first_byte in [0x40, 0xe0] {
        let mut public_key = [0; 48];
        public_key[0] = first_byte;
        assert_eq!(
            UnverifiedPublicKey::from_bytes(&public_key).unwrap_err(),
            DecodeError::BadEncoding
        );

        let mut g2_point = [0; 96];
        g2_point[0] = first_byte;
        assert_eq!(
            Signature::from_bytes(&g2_point).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            ProofOfPossession::from_bytes(&g2_point).unwrap_err(),
            DecodeError::BadEncoding
        );
        assert_eq!(
            AggregateSignature::from_bytes(&g2_point).unwrap_err(),
            DecodeError::BadEncoding
        );
    }
}
