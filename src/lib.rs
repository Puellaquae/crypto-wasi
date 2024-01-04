//! `crypto-wasi` is subset of apis of nodejs's crypto module for wasm32-wasi,
//! implemented in rust,
//! powered by [WASI Cryptography APIs](https://github.com/WebAssembly/wasi-crypto).
//! This library is developed and tested over [WasmEdge](https://github.com/WasmEdge/WasmEdge) runtime
//!
//! **Note:** The api of this library is **not completely consistent** with the api of nodejs.
//!
//! # Currently Subset Implemented
//!
//! - Hash (sha256, sha512, sha512-256)
//! - Hmac (sha256, sha512)
//! - hkdf (sha256, sha512)
//! - pbkdf2 (sha256, sha512)
//! - scrypt
//! - Cipheriv & Decipheriv (aes-128-gcm, aes-256-gcm, chacha20-poly1305)
//! - `generate_key_pair` (rsa-[2048, 3072, 4096], rsa-pss-[2048, 3072, 4096], ecdsa-[prime256v1, secp256k1, secp384r1], ed25519)
//!
//! # Working In Process
//! - KeyObject
//! - Sign & Verify
//! - ECDH
//! - DiffieHellman
//!
//! # Not Implemented
//! - `createCipher` & `createDecipher`:
//! This function is semantically insecure for all supported ciphers and fatally flawed for ciphers in counter mode (such as CTR, GCM, or CCM).
//! - `generateKey` & `createSecretKey`:
//! In nodejs, `SecretKey` is just store the raw key data.
//! In wasi-crypto, `SymmetricKey` is equivalent to `SecretKey`,
//! which is also just store the raw key data in WasmEdge's implementation.
//! But in wasi-crypto, each key is required to be bound to a kind of algorithms,
//! which cause some complications when managing keys and reusing keys.
//! So we're not going to implement `SecretKey`.

/// Low-level binding to `wasi-crypto`
pub mod raw;

/// Some helpful tools and simpified api
pub mod utils;

mod hash;
pub use hash::{create_hash, create_hmac, Hash, Hmac};

mod kdf;
pub use kdf::{hkdf, hkdf_hmac, pbkdf2};

mod scrypt;
pub use scrypt::scrypt;

mod cipher;
pub use cipher::{Cipheriv, Decipheriv};

mod key;
pub use key::{
    generate_key_pair, KeyEncodingFormat, PrivateKey, PrivateKeyEncodingType, PublicKey,
    PublicKeyEncodingType,
};

pub type CryptoErrno = raw::CryptoErrno;

const NONE_OPTS: raw::OptOptions = raw::OptOptions {
    tag: raw::OPT_OPTIONS_U_NONE.raw(),
    u: raw::OptOptionsUnion { none: () },
};

const NONE_KEY: raw::OptSymmetricKey = raw::OptSymmetricKey {
    tag: raw::OPT_SYMMETRIC_KEY_U_NONE.raw(),
    u: raw::OptSymmetricKeyUnion { none: () },
};
