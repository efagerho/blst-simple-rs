# blst-simple-rs

`blst-simple-rs` provides opinionated Rust bindings over the BLST library for
BLS signatures. Its goal is to make correct usage the natural path by encoding
important cryptographic distinctions and validation state in the type system.

The crate currently implements the minimal-public-key-size proof-of-possession
ciphersuite.

Secret-key export is disabled by default. Enable the `secret-key-export`
feature to make `SecretKey::to_bytes` available. Enabling it also enables
`signing`.

The `dangerous-proof-bypass` feature adds
`UnverifiedPublicKey::assume_proof_verified`. Enabling it permits callers to
bypass proof-of-possession verification and can make aggregate signatures
forgeable if misused. Only use this if you understand the cryptography and
know what you're doing.

## CPU features

On x86_64, BLST automatically detects ADX support on the build host and uses it
when available. Such binaries may not run on older x86_64 processors. Enable
the `portable` feature when building binaries that must run across differing
x86_64 CPU generations:

```text
cargo build --features portable
```
