use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{SigningKey, Signature, Signer, VerifyingKey};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug)]
pub struct User {
    pub name: String,
    pub ik_s: EphemeralSecret, // Private identity key
    pub ik_p: X25519PublicKey, // Public identity key
    pub spk_s: EphemeralSecret, // Private signed pre-key
    pub spk_p: X25519PublicKey, // Public signed pre-key
    pub spk_sig: Signature, // Signed pre-key signature
    pub opks: Vec<(EphemeralSecret, X25519PublicKey)>, // One-time pre-keys (private and public)
    pub opks_p: Vec<X25519PublicKey>, // One-time pre-keys (public only)
    pub key_bundles: HashMap<String, Vec<u8>>, // For serialized key bundles (public keys)
    pub dr_keys: HashMap<String, Vec<u8>>, // For derived keys used to encrypt or decrypt messages
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserBundle {
    pub ik_p: X25519PublicKey,
    pub spk_p: X25519PublicKey,
    pub spk_sig: Signature,
    pub opks_p: Vec<X25519PublicKey>,
}

impl User {
    pub fn new(name: String, max_opk_num: usize) -> Self {
        let mut rng = OsRng;

        let ik_s = EphemeralSecret::new(&mut rng);
        let ik_p = X25519PublicKey::from(&ik_s);
        let spk_s = EphemeralSecret::new(&mut rng);
        let spk_p = X25519PublicKey::from(&spk_s);

        // Assuming you have a method to sign using `ed25519-dalek`
        let sk_signing = SigningKey::generate(&mut rng);
        let spk_sig = sk_signing.sign(spk_p.as_bytes());

        let mut opks = Vec::new();
        let mut opks_p = Vec::new();
        for _ in 0..max_opk_num {
            let sk = EphemeralSecret::new(&mut rng);
            let pk = X25519PublicKey::from(&sk);
            opks_p.push(pk);
            opks.push((sk, pk));
        }

        User {
            name,
            ik_s,
            ik_p,
            spk_s,
            spk_p,
            spk_sig,
            opks,
            opks_p,
            key_bundles: HashMap::new(),
            dr_keys: HashMap::new(),
        }
    }

    pub fn publish(&self) -> UserBundle {
        UserBundle {
            ik_p: self.ik_p,
            spk_p: self.spk_p,
            spk_sig: self.spk_sig,
            opks_p: self.opks_p.clone(),
        }
    }
}

fn main() {
    let user = User::new("Alice".to_string(), 10);
    let user_bundle = user.publish();
    println!("{:?}", user_bundle);
}
