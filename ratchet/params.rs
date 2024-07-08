//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{kem, IdentityKey, IdentityKeyPair, KeyPair, PublicKey}; // Import necessary modules and types from the crate

/// Struct representing the parameters required for Alice in the Signal Protocol.
pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair, // Alice's identity key pair //swoosh
    our_base_key_pair: KeyPair, // Alice's base key pair  //kyber IS this the ephemeral key pair??

    their_identity_key: IdentityKey, // Bob's identity key //kyber
    their_signed_pre_key: PublicKey, // Bob's signed pre-key //swoosh
    their_one_time_pre_key: Option<PublicKey>, // Bob's one-time pre-key, if available //kyber
    their_ratchet_key: PublicKey, // Bob's ratchet key //kyber
    their_kyber_pre_key: Option<kem::PublicKey>, // Bob's Kyber pre-key, if available
}

impl AliceSignalProtocolParameters {
    /// Create a new instance of AliceSignalProtocolParameters.
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_ratchet_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key: None, // Initialize without a one-time pre-key
            their_ratchet_key,
            their_kyber_pre_key: None, // Initialize without a Kyber pre-key
        }
    }

    /// Set Bob's one-time pre-key.
    pub fn set_their_one_time_pre_key(&mut self, ec_public: PublicKey) {
        self.their_one_time_pre_key = Some(ec_public);
    }

    /// Set Bob's one-time pre-key and return updated self.
    pub fn with_their_one_time_pre_key(mut self, ec_public: PublicKey) -> Self {
        self.set_their_one_time_pre_key(ec_public);
        self
    }

    /// Set Bob's Kyber pre-key.
    pub fn set_their_kyber_pre_key(&mut self, kyber_public: &kem::PublicKey) {
        self.their_kyber_pre_key = Some(kyber_public.clone());
    }

    /// Set Bob's Kyber pre-key and return updated self.
    pub fn with_their_kyber_pre_key(mut self, kyber_public: &kem::PublicKey) -> Self {
        self.set_their_kyber_pre_key(kyber_public);
        self
    }

    /// Get Alice's identity key pair.
    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    /// Get Alice's base key pair.
    #[inline]
    pub fn our_base_key_pair(&self) -> &KeyPair {
        &self.our_base_key_pair
    }

    /// Get Bob's identity key.
    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    /// Get Bob's signed pre-key.
    #[inline]
    pub fn their_signed_pre_key(&self) -> &PublicKey {
        &self.their_signed_pre_key
    }

    /// Get Bob's one-time pre-key, if available.
    #[inline]
    pub fn their_one_time_pre_key(&self) -> Option<&PublicKey> {
        self.their_one_time_pre_key.as_ref()
    }

    /// Get Bob's Kyber pre-key, if available.
    #[inline]
    pub fn their_kyber_pre_key(&self) -> Option<&kem::PublicKey> {
        self.their_kyber_pre_key.as_ref()
    }

    /// Get Bob's ratchet key.
    #[inline]
    pub fn their_ratchet_key(&self) -> &PublicKey {
        &self.their_ratchet_key
    }
}

/// Struct representing the parameters required for Bob in the Signal Protocol.
pub struct BobSignalProtocolParameters<'a> {
    our_identity_key_pair: IdentityKeyPair, // Bob's identity key pair
    our_signed_pre_key_pair: KeyPair, // Bob's signed pre-key pair
    our_one_time_pre_key_pair: Option<KeyPair>, // Bob's one-time pre-key pair, if available
    our_ratchet_key_pair: KeyPair, // Bob's ratchet key pair
    our_kyber_pre_key_pair: Option<kem::KeyPair>, // Bob's Kyber pre-key pair, if available

    their_identity_key: IdentityKey, // Alice's identity key
    their_base_key: PublicKey, // Alice's base key
    their_kyber_ciphertext: Option<&'a kem::SerializedCiphertext>, // Alice's Kyber ciphertext, if available
}

impl<'a> BobSignalProtocolParameters<'a> {
    /// Create a new instance of BobSignalProtocolParameters.
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        our_kyber_pre_key_pair: Option<kem::KeyPair>,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: Option<&'a kem::SerializedCiphertext>,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_one_time_pre_key_pair,
            our_ratchet_key_pair,
            our_kyber_pre_key_pair,
            their_identity_key,
            their_base_key,
            their_kyber_ciphertext,
        }
    }

    /// Get Bob's identity key pair.
    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    /// Get Bob's signed pre-key pair.
    #[inline]
    pub fn our_signed_pre_key_pair(&self) -> &KeyPair {
        &self.our_signed_pre_key_pair
    }

    /// Get Bob's one-time pre-key pair, if available.
    #[inline]
    pub fn our_one_time_pre_key_pair(&self) -> Option<&KeyPair> {
        self.our_one_time_pre_key_pair.as_ref()
    }

    /// Get Bob's ratchet key pair.
    #[inline]
    pub fn our_ratchet_key_pair(&self) -> &KeyPair {
        &self.our_ratchet_key_pair
    }

    /// Get Bob's Kyber pre-key pair, if available.
    #[inline]
    pub fn our_kyber_pre_key_pair(&self) -> &Option<kem::KeyPair> {
        &self.our_kyber_pre_key_pair
    }

    /// Get Alice's identity key.
    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    /// Get Alice's base key.
    #[inline]
    pub fn their_base_key(&self) -> &PublicKey {
        &self.their_base_key
    }

    /// Get Alice's Kyber ciphertext, if available.
    #[inline]
    pub fn their_kyber_ciphertext(&self) -> Option<&kem::SerializedCiphertext> {
        self.their_kyber_ciphertext
    }
}
