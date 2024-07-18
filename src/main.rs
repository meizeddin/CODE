extern crate rand;
extern crate ed25519_dalek;
extern crate hex;

use rand::{Rng, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use ed25519_dalek::{SigningKey, Signature, Signer};
use std::collections::HashMap;
use std::str;
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Serialize, Deserialize};

//use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};

// a user structure that holds the private and public keys, the signature, and other related fields.
pub struct User{
    pub name: String,
    pub ik_s: EphemeralSecret, //private_identity_key
    pub ik_p: PublicKey, //public_identity_key
    pub spk_s: EphemeralSecret, //private_signed_pre_key
    pub spk_p: PublicKey, //public_signed_pre_key
    pub spk_sig: Signature, //signed_pre_key_signature
    pub opks_s: Vec<(EphemeralSecret, PublicKey)>, //one-time pre keys (public and private) 
    pub opks_p: Vec<PublicKey>, //one-time pre keys (public only "published")
    pub key_bundles: HashMap<String, Vec<u8>>, //for serialised key bundles (public keys)
    pub dr_keys: HashMap<String, Vec<u8>> //for derived keys used to encrypt or decrypt messages
}

#[derive(Debug)]
pub struct UserBundle {
    pub ik_p: PublicKey,
    pub spk_p: PublicKey,
    pub spk_sig: Signature,
    pub opks_p: Vec<PublicKey>
}


// Implement HKDF using hkdf crate
fn x3dh_kdf(key_material: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, key_material);
    let mut output = [0u8; 32];
    hkdf.expand(&[], &mut output).expect("HKDF expand error");
    output
}

// user implementation
impl User{
    //A "new" function, a constructor for creating a new User instance It takes two parameters and returns a new user instance
    pub fn new(name: String, max_opk_num: usize) -> User {
        let mut csprng: OsRng = OsRng; // Instance of CSPRNG (cryptographically secure pseudo random number generator)
        let ik_s: EphemeralSecret = EphemeralSecret::random_from_rng(&mut csprng);
        let ik_p: PublicKey = PublicKey::from(&ik_s); // Derives the public key from the private key
        let spk_s: EphemeralSecret = EphemeralSecret::random_from_rng(&mut csprng);
        let spk_p: PublicKey = PublicKey::from(&spk_s);

        //creating and signing the public pre key. need more explaination
        let signing_key: SigningKey = SigningKey::from_bytes(&csprng.gen()); // Generate a new signing key from random bytes
        let spk_sig: Signature = signing_key.sign(spk_p.as_bytes());

        // set the capacity for the one-time pre keys to the max number specified
        let mut opks_s: Vec<(EphemeralSecret, PublicKey)> = Vec::with_capacity(max_opk_num);
        let mut opks_p: Vec<PublicKey> = Vec::with_capacity(max_opk_num);
        
        for _ in 0..max_opk_num{
            let sk: EphemeralSecret = EphemeralSecret::random_from_rng(&mut csprng);
            let pk: PublicKey = PublicKey::from(&sk);
            opks_p.push(pk);
            opks_s.push((sk, pk));
        }

        User {
            name,
            ik_s,
            ik_p,
            spk_s,
            spk_p,
            spk_sig,
            opks_s,
            opks_p,
            key_bundles: HashMap::new(),
            dr_keys: HashMap::new()
        }
    }
    // Publish the public part of the user's key bundle
    pub fn publish(&self) -> UserBundle{
        UserBundle{
            ik_p: self.ik_p,
            spk_p: self.spk_p,
            spk_sig: self.spk_sig.clone(),
            opks_p: self.opks_p.clone(),
        }
    }
    

    // Perform an initial handshake with another user
    pub fn initial_handshake(&mut self, user_name: &str) {
        let mut csprng: OsRng = OsRng;
        let sk: EphemeralSecret = EphemeralSecret::random_from_rng(&mut csprng);
        let key_bundle = self.key_bundles.get_mut(user_name).unwrap();
        key_bundle.ek_p = PublicKey::from(&sk);
    }

    // Function to generate send secret key based on DH exchanges and signature verification
    // pub fn generate_send_secret_key(&mut self, user_name: &str) {
    //     if let Some(key_bundle) = self.key_bundles.get_mut(user_name) {
    //         let dh_1 = self.ik_s.diffie_hellman(&key_bundle.spk_p);
    //         let dh_2 = key_bundle.ek_s.diffie_hellman(&self.ik_p);
    //         let dh_3 = key_bundle.ek_s.diffie_hellman(&self.spk_p);
    //         let dh_4 = key_bundle.ek_s.diffie_hellman(&self.opks_p[0]); // Assuming OPK_p is a Vec and we take the first one

    //         // Verify the signed prekey
    //         let public_key_bytes = key_bundle.spk_p.to_bytes();
    //         let signature_bytes = key_bundle.spk_sig.to_bytes();
    //         if !self.verify_signature(&public_key_bytes, &signature_bytes) {
    //             println!("Unable to verify Signed Prekey");
    //             return;
    //         }

    //         // Concatenate DH results and derive the send secret key
    //         let key_material = [
    //             dh_1.as_bytes(),
    //             dh_2.as_bytes(),
    //             dh_3.as_bytes(),
    //             dh_4.as_bytes(),
    //         ]
    //         .concat();

    //         key_bundle.sk = x3dh_kdf(&key_material);
    //     }
    // }
    // Verify Ed25519 signature
    // fn verify_signature(&self, public_key_bytes: &[u8], signature_bytes: &[u8]) -> bool {
    //     let public_key = ed25519_dalek::PublicKey::from_bytes(public_key_bytes);
    //     let signature = Signature::from_bytes(signature_bytes);

    //     if let (Ok(public_key), Ok(signature)) = (public_key, signature) {
    //         public_key.verify_strict(&self.spk_p.as_bytes(), &signature).is_ok()
    //     } else {
    //         false
    //     }
    // }
}

// Test the mock server interaction
// fn test_mock_server() {
//     // Create a user
//     let mut user: User = User::new("Alice".to_string(), 1);

//     // Create a mock server
//     let server = MockServer::new();

//     // Simulate initial handshake with another user
//     user.initial_handshake(&server, "Alice");

//     // Print out the key bundle for the user
//     let bundle: UserBundle = user.publish();
//     println!("{:?}", bundle);
// }

fn main() {
    let alice: User = User::new("Alice".to_string(), 3);
    let bob: User = User::new("Bob".to_string(), 3);


    let bundle_a: UserBundle = alice.publish();
    let bundle_b: UserBundle = bob.publish();

    // Alice and Bob exchange public keys and compute the shared secret
    let alice_shared_secret: SharedSecret = alice.ik_s.diffie_hellman(&bundle_b.ik_p);
    let bob_shared_secret: SharedSecret = bob.ik_s.diffie_hellman(&bundle_a.ik_p);


    // Assert and print the result of the assertion
    if alice_shared_secret.as_bytes() == bob_shared_secret.as_bytes() {
        println!("The shared secrets are equal.");
    } else {
        println!("The shared secrets are not equal.");
    }

    println!("{:?}\n", bundle_a);  
    println!("{:?}\n", bundle_b);    
  

    //test_mock_server();
}