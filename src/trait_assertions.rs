use crate::{
    AggregateError, AggregatePublicKey, AggregatePublicKeyBuilder, AggregateSignature,
    AggregateSignatureBuilder, AggregateVerifier, DecodeError, HashedMessage, InvalidProofError,
    PreparedMessage, ProofOfPossession, ProofVerificationError, PublicKey, Signature,
    TooManyDistinctMessagesError, UnverifiedPublicKey,
};

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<AggregateError>();
    assert_send_sync::<AggregatePublicKey>();
    assert_send_sync::<AggregatePublicKeyBuilder>();
    assert_send_sync::<AggregateSignature>();
    assert_send_sync::<AggregateSignatureBuilder>();
    assert_send_sync::<AggregateVerifier>();
    assert_send_sync::<DecodeError>();
    assert_send_sync::<HashedMessage>();
    assert_send_sync::<InvalidProofError>();
    assert_send_sync::<PreparedMessage>();
    assert_send_sync::<ProofOfPossession>();
    assert_send_sync::<ProofVerificationError>();
    assert_send_sync::<PublicKey>();
    assert_send_sync::<Signature>();
    assert_send_sync::<TooManyDistinctMessagesError>();
    assert_send_sync::<UnverifiedPublicKey>();
};

#[cfg(feature = "signing")]
const _: fn() = || {
    use crate::{
        KeyGenerationParameters, KeyInfoTooLongError, KeyMaterialTooShortError, SecretKey,
        SecretKeyError,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<KeyInfoTooLongError>();
    assert_send_sync::<KeyMaterialTooShortError>();
    assert_send_sync::<KeyGenerationParameters<'static>>();
    assert_send_sync::<SecretKey>();
    assert_send_sync::<SecretKeyError>();
};
