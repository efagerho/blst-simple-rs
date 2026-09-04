mod common;

use blst_simple_rs::{HashedMessage, Signature, UnverifiedPublicKey};
use common::{decode_hex, decode_hex_array};
use serde::Deserialize;

const VECTORS: &str = include_str!("vectors/wycheproof/bls_sig_g2_pop_verify_test.json");

#[derive(Deserialize)]
struct TestFile {
    algorithm: String,
    schema: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    ciphersuite: String,
    #[serde(rename = "publicKey")]
    public_key: TestPublicKey,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestPublicKey {
    pk: String,
}

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    id: u64,
    comment: String,
    msg: String,
    sig: String,
    result: TestResult,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum TestResult {
    Valid,
    Invalid,
}

#[test]
fn bls_pop_signature_verification() {
    let vectors: TestFile = serde_json::from_str(VECTORS).unwrap();

    assert_eq!(vectors.algorithm, "BLS");
    assert_eq!(vectors.schema, "bls_sig_verify_schema.json");
    assert_eq!(
        vectors.number_of_tests,
        vectors
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>()
    );

    for group in vectors.test_groups {
        assert_eq!(
            group.ciphersuite,
            "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
        );

        for test in group.tests {
            let expected = test.result == TestResult::Valid;
            let [raw, hashed, prepared] =
                verify_at_each_message_rung(&group.public_key.pk, &test.msg, &test.sig);
            let context = format!("test case {}: {}", test.id, test.comment);

            assert_eq!(
                raw, expected,
                "raw-message verification failed for {context}"
            );
            assert_eq!(
                hashed, expected,
                "hashed-message verification failed for {context}"
            );
            assert_eq!(
                prepared, expected,
                "prepared-message verification failed for {context}"
            );
        }
    }
}

fn verify_at_each_message_rung(public_key: &str, message: &str, signature: &str) -> [bool; 3] {
    let Some(public_key) = decode_hex_array(public_key) else {
        return [false; 3];
    };
    let Some(message) = decode_hex(message) else {
        return [false; 3];
    };
    let Some(signature) = decode_hex_array(signature) else {
        return [false; 3];
    };
    let Ok(public_key) = UnverifiedPublicKey::from_bytes(&public_key) else {
        return [false; 3];
    };
    let Ok(signature) = Signature::from_bytes(&signature) else {
        return [false; 3];
    };

    // A single-signature pairing equation does not rely on proof of possession.
    let public_key = public_key.assume_proof_verified();
    let hashed = HashedMessage::new(&message);
    let prepared = hashed.prepare();

    [
        signature.verify_message(&public_key, &message),
        signature.verify(&public_key, &hashed),
        signature.verify_prepared(&public_key, &prepared),
    ]
}
