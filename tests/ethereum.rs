mod common;

#[cfg(feature = "signing")]
use blst_simple_rs::SecretKey;
#[cfg(feature = "dangerous-proof-bypass")]
use blst_simple_rs::{
    AggregatePublicKey, AggregateVerifier, HashedMessage, PublicKey, Signature, UnverifiedPublicKey,
};
use blst_simple_rs::{AggregateSignature, AggregateSignatureBuilder};
#[cfg(any(feature = "signing", feature = "dangerous-proof-bypass"))]
use common::decode_hex;
use common::decode_hex_array;
#[cfg(feature = "dangerous-proof-bypass")]
use common::{
    SINGLE_VERIFICATION_PATHS, verify_fast_aggregate_at_each_entry_point,
    verify_single_at_each_entry_point,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;

struct Fixture {
    name: &'static str,
    contents: &'static str,
}

macro_rules! fixtures {
    ($directory:literal; $($name:literal),+ $(,)?) => {
        &[
            $(Fixture {
                name: $name,
                contents: include_str!(concat!(
                    "vectors/ethereum/v0.1.0/",
                    $directory,
                    "/",
                    $name,
                    ".json"
                )),
            },)+
        ]
    };
}

#[cfg(feature = "signing")]
const SIGN_FIXTURES: &[Fixture] = fixtures!("sign";
    "sign_case_11b8c7cad5238946",
    "sign_case_142f678a8d05fcd1",
    "sign_case_37286e1a6d1f6eb3",
    "sign_case_7055381f640f2c1d",
    "sign_case_84d45c9c7cca6b92",
    "sign_case_8cd3d4d0d9a5b265",
    "sign_case_c82df61aa3ee60fb",
    "sign_case_d0e28d7e76eb6e9c",
    "sign_case_f2ae1097e7d0e18b",
    "sign_case_zero_privkey",
);

const AGGREGATE_FIXTURES: &[Fixture] = fixtures!("aggregate";
    "aggregate_0x0000000000000000000000000000000000000000000000000000000000000000",
    "aggregate_0x5656565656565656565656565656565656565656565656565656565656565656",
    "aggregate_0xabababababababababababababababababababababababababababababababab",
    "aggregate_infinity_signature",
    "aggregate_na_signatures",
    "aggregate_single_signature",
);

#[cfg(feature = "dangerous-proof-bypass")]
const AGGREGATE_VERIFY_FIXTURES: &[Fixture] = fixtures!("aggregate_verify";
    "aggregate_verify_infinity_pubkey",
    "aggregate_verify_na_pubkeys_and_infinity_signature",
    "aggregate_verify_na_pubkeys_and_na_signature",
    "aggregate_verify_tampered_signature",
    "aggregate_verify_valid",
);

#[cfg(feature = "dangerous-proof-bypass")]
const FAST_AGGREGATE_VERIFY_FIXTURES: &[Fixture] = fixtures!("fast_aggregate_verify";
    "fast_aggregate_verify_extra_pubkey_4f079f946446fabf",
    "fast_aggregate_verify_extra_pubkey_5a38e6b4017fe4dd",
    "fast_aggregate_verify_extra_pubkey_a698ea45b109f303",
    "fast_aggregate_verify_infinity_pubkey",
    "fast_aggregate_verify_na_pubkeys_and_infinity_signature",
    "fast_aggregate_verify_na_pubkeys_and_na_signature",
    "fast_aggregate_verify_tampered_signature_3d7576f3c0e3570a",
    "fast_aggregate_verify_tampered_signature_5e745ad0c6199a6c",
    "fast_aggregate_verify_tampered_signature_652ce62f09290811",
    "fast_aggregate_verify_valid_3d7576f3c0e3570a",
    "fast_aggregate_verify_valid_5e745ad0c6199a6c",
    "fast_aggregate_verify_valid_652ce62f09290811",
);

#[cfg(feature = "dangerous-proof-bypass")]
const VERIFY_FIXTURES: &[Fixture] = fixtures!("verify";
    "verify_infinity_pubkey_and_infinity_signature",
    "verify_tampered_signature_case_195246ee3bd3b6ec",
    "verify_tampered_signature_case_2ea479adf8c40300",
    "verify_tampered_signature_case_2f09d443ab8a3ac2",
    "verify_tampered_signature_case_3208262581c8fc09",
    "verify_tampered_signature_case_6b3b17f6962a490c",
    "verify_tampered_signature_case_6eeb7c52dfd9baf0",
    "verify_tampered_signature_case_8761a0b7e920c323",
    "verify_tampered_signature_case_d34885d766d5f705",
    "verify_tampered_signature_case_e8a50c445c855360",
    "verify_valid_case_195246ee3bd3b6ec",
    "verify_valid_case_2ea479adf8c40300",
    "verify_valid_case_2f09d443ab8a3ac2",
    "verify_valid_case_3208262581c8fc09",
    "verify_valid_case_6b3b17f6962a490c",
    "verify_valid_case_6eeb7c52dfd9baf0",
    "verify_valid_case_8761a0b7e920c323",
    "verify_valid_case_d34885d766d5f705",
    "verify_valid_case_e8a50c445c855360",
    "verify_wrong_pubkey_case_195246ee3bd3b6ec",
    "verify_wrong_pubkey_case_2ea479adf8c40300",
    "verify_wrong_pubkey_case_2f09d443ab8a3ac2",
    "verify_wrong_pubkey_case_3208262581c8fc09",
    "verify_wrong_pubkey_case_6b3b17f6962a490c",
    "verify_wrong_pubkey_case_6eeb7c52dfd9baf0",
    "verify_wrong_pubkey_case_8761a0b7e920c323",
    "verify_wrong_pubkey_case_d34885d766d5f705",
    "verify_wrong_pubkey_case_e8a50c445c855360",
    "verifycase_one_privkey_47117849458281be",
);

#[derive(Deserialize)]
struct TestCase<I, O> {
    input: I,
    output: O,
}

#[cfg(feature = "signing")]
#[derive(Deserialize)]
struct SignInput {
    privkey: String,
    message: String,
}

#[cfg(feature = "dangerous-proof-bypass")]
#[derive(Deserialize)]
struct AggregateVerifyInput {
    pubkeys: Vec<String>,
    messages: Vec<String>,
    signature: String,
}

#[cfg(feature = "dangerous-proof-bypass")]
#[derive(Deserialize)]
struct FastAggregateVerifyInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

#[cfg(feature = "dangerous-proof-bypass")]
#[derive(Deserialize)]
struct VerifyInput {
    pubkey: String,
    message: String,
    signature: String,
}

#[cfg(feature = "signing")]
#[test]
fn signing() {
    for fixture in SIGN_FIXTURES {
        let test: TestCase<SignInput, Option<String>> = parse(fixture);
        let expected = test
            .output
            .as_deref()
            .map(|output| decode_hex_array(output).unwrap());
        let [raw, hashed] = sign_at_each_message_rung(&test.input);

        assert_eq!(raw, expected, "raw-message signing: {}", fixture.name);
        assert_eq!(hashed, expected, "hashed-message signing: {}", fixture.name);
    }
}

#[test]
fn aggregation() {
    for fixture in AGGREGATE_FIXTURES {
        let test: TestCase<Vec<String>, Option<String>> = parse(fixture);
        let expected = test
            .output
            .as_deref()
            .map(|output| decode_hex_array(output).unwrap());
        let actual = aggregate(&test.input);

        assert_eq!(actual, expected, "aggregation: {}", fixture.name);
    }
}

#[cfg(feature = "dangerous-proof-bypass")]
#[test]
fn aggregate_verification() {
    for fixture in AGGREGATE_VERIFY_FIXTURES {
        let test: TestCase<AggregateVerifyInput, bool> = parse(fixture);
        let results = aggregate_verify_at_each_message_rung(&test.input);

        for (path, actual) in [
            "hashed slice",
            "prepared slice",
            "hashed stream",
            "prepared stream",
        ]
        .into_iter()
        .zip(results)
        {
            assert_eq!(actual, test.output, "{path}: {}", fixture.name);
        }
    }
}

#[cfg(feature = "dangerous-proof-bypass")]
#[test]
fn fast_aggregate_verification() {
    for fixture in FAST_AGGREGATE_VERIFY_FIXTURES {
        let test: TestCase<FastAggregateVerifyInput, bool> = parse(fixture);
        let results = fast_aggregate_verify_at_each_entry_point(&test.input);

        for (path, actual) in SINGLE_VERIFICATION_PATHS[3..].iter().copied().zip(results) {
            assert_eq!(actual, test.output, "{path}: {}", fixture.name);
        }
    }
}

#[cfg(feature = "dangerous-proof-bypass")]
#[test]
fn verification() {
    for fixture in VERIFY_FIXTURES {
        let test: TestCase<VerifyInput, bool> = parse(fixture);
        let results = verify_at_each_entry_point(&test.input);

        for (path, actual) in SINGLE_VERIFICATION_PATHS.into_iter().zip(results) {
            assert_eq!(actual, test.output, "{path}: {}", fixture.name);
        }
    }
}

#[cfg(feature = "signing")]
fn sign_at_each_message_rung(input: &SignInput) -> [Option<[u8; 96]>; 2] {
    let Some(secret) = decode_hex_array(&input.privkey) else {
        return [None; 2];
    };
    let Ok(secret) = SecretKey::from_bytes(&secret) else {
        return [None; 2];
    };
    let Some(message) = decode_hex(&input.message) else {
        return [None; 2];
    };
    let hashed = blst_simple_rs::HashedMessage::new(&message);

    [
        Some(secret.sign_message(&message).to_bytes()),
        Some(secret.sign(&hashed).to_bytes()),
    ]
}

fn aggregate(inputs: &[String]) -> Option<[u8; 96]> {
    let signatures: Vec<_> = inputs
        .iter()
        .map(|input| {
            let bytes = decode_hex_array(input)?;
            AggregateSignature::from_bytes(&bytes).ok()
        })
        .collect::<Option<_>>()?;
    let (first, rest) = signatures.split_first()?;
    let mut builder = AggregateSignatureBuilder::from_aggregate(first);
    builder.extend_aggregates(rest);
    Some(builder.finish().to_bytes())
}

#[cfg(feature = "dangerous-proof-bypass")]
fn aggregate_verify_at_each_message_rung(input: &AggregateVerifyInput) -> [bool; 4] {
    if input.pubkeys.len() != input.messages.len() {
        return [false; 4];
    }

    let Some(signature) = decode_aggregate_signature(&input.signature) else {
        return [false; 4];
    };
    let Some(keys) = decode_public_keys(&input.pubkeys) else {
        return [false; 4];
    };
    let Some(messages) = input
        .messages
        .iter()
        .map(|message| decode_hex(message))
        .collect::<Option<Vec<_>>>()
    else {
        return [false; 4];
    };

    let keys: Vec<_> = keys.into_iter().map(AggregatePublicKey::from).collect();
    let messages: Vec<_> = messages
        .iter()
        .map(|message| HashedMessage::new(message))
        .collect();
    let prepared: Vec<_> = messages.iter().map(HashedMessage::prepare).collect();
    let groups: Vec<_> = keys.iter().zip(&messages).collect();
    let prepared_groups: Vec<_> = keys.iter().zip(&prepared).collect();

    let mut verifier = AggregateVerifier::new(messages.len());
    let streamed = verifier.extend(&groups).is_ok() && verifier.finish_and_reset(&signature);
    let mut verifier = AggregateVerifier::new(messages.len());
    let streamed_prepared =
        verifier.extend_prepared(&prepared_groups).is_ok() && verifier.finish_and_reset(&signature);

    [
        signature.verify_groups(&groups),
        signature.verify_prepared_groups(&prepared_groups),
        streamed,
        streamed_prepared,
    ]
}

#[cfg(feature = "dangerous-proof-bypass")]
fn fast_aggregate_verify_at_each_entry_point(input: &FastAggregateVerifyInput) -> [bool; 10] {
    let Some(signature) = decode_aggregate_signature(&input.signature) else {
        return [false; 10];
    };
    let Some(keys) = decode_public_keys(&input.pubkeys) else {
        return [false; 10];
    };
    let Some(message) = decode_hex(&input.message) else {
        return [false; 10];
    };
    verify_fast_aggregate_at_each_entry_point(&keys, &message, &signature)
}

#[cfg(feature = "dangerous-proof-bypass")]
fn verify_at_each_entry_point(input: &VerifyInput) -> [bool; 13] {
    let Some(public_key) = decode_public_key(&input.pubkey) else {
        return [false; 13];
    };
    let Some(signature) =
        decode_hex_array(&input.signature).and_then(|bytes| Signature::from_bytes(&bytes).ok())
    else {
        return [false; 13];
    };
    let Some(message) = decode_hex(&input.message) else {
        return [false; 13];
    };
    verify_single_at_each_entry_point(&public_key, &message, &signature)
}

#[cfg(feature = "dangerous-proof-bypass")]
fn decode_aggregate_signature(input: &str) -> Option<AggregateSignature> {
    let bytes = decode_hex_array(input)?;
    AggregateSignature::from_bytes(&bytes).ok()
}

#[cfg(feature = "dangerous-proof-bypass")]
fn decode_public_keys(inputs: &[String]) -> Option<Vec<PublicKey>> {
    inputs
        .iter()
        .map(|input| decode_public_key(input))
        .collect()
}

#[cfg(feature = "dangerous-proof-bypass")]
fn decode_public_key(input: &str) -> Option<PublicKey> {
    let bytes = decode_hex_array(input)?;
    let key = UnverifiedPublicKey::from_bytes(&bytes).ok()?;

    // The fixtures omit proofs and supply expected pairing results.
    Some(key.assume_proof_verified())
}

fn parse<T: DeserializeOwned>(fixture: &Fixture) -> T {
    serde_json::from_str(fixture.contents)
        .unwrap_or_else(|error| panic!("could not parse {}: {error}", fixture.name))
}
