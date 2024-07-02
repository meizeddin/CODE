//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::Result; // Import the Result type from the crate

use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret}; // Import necessary KEM traits

use super::{KeyMaterial, Public, Secret}; // Import necessary types from the super module
use pqcrypto_kyber::ffi::{
    PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
    PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES, PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES,
}; // Import constants for Kyber1024 from the pqcrypto_kyber crate

/// A struct representing parameters for the Kyber KEM.
pub(crate) struct Parameters;

impl super::Parameters for Parameters {
    /// Length of the public key in bytes.
    const PUBLIC_KEY_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES;
    /// Length of the secret key in bytes.
    const SECRET_KEY_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES;
    /// Length of the ciphertext in bytes.
    const CIPHERTEXT_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    /// Length of the shared secret in bytes.
    const SHARED_SECRET_LENGTH: usize = PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES;

    /// Generate a Kyber keypair and return as KeyMaterial.
    fn generate() -> (KeyMaterial<Public>, KeyMaterial<Secret>) {
        // Generate a Kyber1024 keypair
        let (pk, sk) = pqcrypto_kyber::kyber1024::keypair();
        (
            // Wrap the public key bytes in KeyMaterial
            KeyMaterial::new(pk.as_bytes().into()),
            // Wrap the secret key bytes in KeyMaterial
            KeyMaterial::new(sk.as_bytes().into()),
        )
    }

    /// Encapsulate a shared secret using the provided public key.
    fn encapsulate(pub_key: &KeyMaterial<Public>) -> (super::SharedSecret, super::RawCiphertext) {
        // Convert KeyMaterial into a Kyber1024 public key
        let kyber_pk = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(pub_key)
            .expect("valid kyber1024 public key bytes");
        // Encapsulate a shared secret and ciphertext
        let (kyber_ss, kyber_ct) = pqcrypto_kyber::kyber1024::encapsulate(&kyber_pk);
        (
            // Return the shared secret and ciphertext as byte arrays wrapped in appropriate types
            kyber_ss.as_bytes().into(),
            kyber_ct.as_bytes().into(),
        )
    }

    /// Decapsulate a shared secret using the provided secret key and ciphertext.
    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<super::SharedSecret> {
        // Convert KeyMaterial into a Kyber1024 secret key
        let kyber_sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(secret_key)
            .expect("valid kyber1024 secret key bytes");
        // Convert the byte slice into a Kyber1024 ciphertext
        let kyber_ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ciphertext)
            .expect("valid kyber1024 ciphertext");
        // Decapsulate the shared secret using the secret key and ciphertext
        let kyber_ss = pqcrypto_kyber::kyber1024::decapsulate(&kyber_ct, &kyber_sk);

        // Return the shared secret as a byte array wrapped in the appropriate type
        Ok(kyber_ss.as_bytes().into())
    }
}
