//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use arrayref::array_ref; // Import macro for array references

use crate::{crypto, PrivateKey, PublicKey, Result}; // Import necessary modules and types from the crate
use std::fmt; // Import the fmt module for formatting traits

/// Struct representing the keys used in a message: cipher key, MAC key, IV, and a counter.
pub(crate) struct MessageKeys {
    cipher_key: [u8; 32], // Key used for encryption
    mac_key: [u8; 32], // Key used for message authentication code
    iv: [u8; 16], // Initialization vector for encryption
    counter: u32, // Counter value for message ordering
}

impl MessageKeys {
    /// Derive message keys from input key material using HKDF and a counter.
    pub(crate) fn derive_keys(input_key_material: &[u8], counter: u32) -> Self {
        let mut okm = [0; 80]; // Output key material buffer
        hkdf::Hkdf::<sha2::Sha256>::new(None, input_key_material)
            .expand(b"WhisperMessageKeys", &mut okm)
            .expect("valid output length"); // Derive keys using HKDF with a context string

        MessageKeys {
            cipher_key: *array_ref![okm, 0, 32], // Extract cipher key
            mac_key: *array_ref![okm, 32, 32], // Extract MAC key
            iv: *array_ref![okm, 64, 16], // Extract IV
            counter,
        }
    }

    /// Create a new instance of MessageKeys.
    pub(crate) fn new(cipher_key: [u8; 32], mac_key: [u8; 32], iv: [u8; 16], counter: u32) -> Self {
        MessageKeys {
            cipher_key,
            mac_key,
            iv,
            counter,
        }
    }

    /// Get the cipher key.
    #[inline]
    pub(crate) fn cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    /// Get the MAC key.
    #[inline]
    pub(crate) fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    /// Get the IV.
    #[inline]
    pub(crate) fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Get the counter value.
    #[inline]
    pub(crate) fn counter(&self) -> u32 {
        self.counter
    }
}

/// Struct representing the chain key used in the Double Ratchet algorithm.
#[derive(Clone, Debug)]
pub(crate) struct ChainKey {
    key: [u8; 32], // Chain key material
    index: u32, // Index of the chain key
}

impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8]; // Seed for generating message keys
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8]; // Seed for generating the next chain key

    /// Create a new ChainKey instance.
    pub(crate) fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    /// Get the chain key.
    #[inline]
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the chain key index.
    #[inline]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// Generate the next chain key.
    pub(crate) fn next_chain_key(&self) -> Self {
        Self {
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED), // Calculate next chain key
            index: self.index + 1, // Increment index
        }
    }

    /// Generate message keys from the chain key.
    pub(crate) fn message_keys(&self) -> MessageKeys {
        MessageKeys::derive_keys(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED), // Calculate base material for message keys
            self.index,
        )
    }

    /// Calculate base material using HMAC-SHA256 with the given seed.
    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; 32] {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

/// Struct representing the root key in the Double Ratchet algorithm.
#[derive(Clone, Debug)]
pub(crate) struct RootKey {
    key: [u8; 32], // Root key material
}

impl RootKey {
    /// Create a new RootKey instance.
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Get the root key.
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Create a new chain key from the root key and ratchet keys.
    pub(crate) fn create_chain(
        self,
        their_ratchet_key: &PublicKey, // Public key of the recipient
        our_ratchet_key: &PrivateKey, // Private key of the sender
    ) -> Result<(RootKey, ChainKey)> {
        let shared_secret = our_ratchet_key.calculate_agreement(their_ratchet_key)?; // Calculate the shared secret
        let mut derived_secret_bytes = [0; 64]; // Buffer for derived secrets
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.key), &shared_secret)
            .expand(b"WhisperRatchet", &mut derived_secret_bytes)
            .expect("valid output length"); // Derive keys using HKDF with a context string

        Ok((
            RootKey {
                key: *array_ref![derived_secret_bytes, 0, 32], // Extract the new root key
            },
            ChainKey {
                key: *array_ref![derived_secret_bytes, 32, 32], // Extract the new chain key
                index: 0, // Initialize index
            },
        ))
    }
}

/// Implement the Display trait for RootKey to enable easy printing.
impl fmt::Display for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the derivation of chain keys and message keys.
    #[test]
    fn test_chain_key_derivation() -> Result<()> {
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ]; // Seed for the chain key
        let message_key = [
            0xbfu8, 0x51, 0xe9, 0xd7, 0x5e, 0x0e, 0x31, 0x03, 0x10, 0x51, 0xf8, 0x2a, 0x24, 0x91,
            0xff, 0xc0, 0x84, 0xfa, 0x29, 0x8b, 0x77, 0x93, 0xbd, 0x9d, 0xb6, 0x20, 0x05, 0x6f,
            0xeb, 0xf4, 0x52, 0x17,
        ]; // Expected cipher key
        let mac_key = [
            0xc6u8, 0xc7, 0x7d, 0x6a, 0x73, 0xa3, 0x54, 0x33, 0x7a, 0x56, 0x43, 0x5e, 0x34, 0x60,
            0x7d, 0xfe, 0x48, 0xe3, 0xac, 0xe1, 0x4e, 0x77, 0x31, 0x4d, 0xc6, 0xab, 0xc1, 0x72,
            0xe7, 0xa7, 0x03, 0x0b,
        ]; // Expected MAC key
        let next_chain_key = [
            0x28u8, 0xe8, 0xf8, 0xfe
