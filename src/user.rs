use rand::{Rng, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey};
use ed25519_dalek::{SigningKey, Signature, Signer};
use std::collections::HashMap;

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

    pub fn publish(&self) -> UserBundle{
        UserBundle{
            ik_p: self.ik_p,
            spk_p: self.spk_p,
            spk_sig: self.spk_sig,
            opks_p: self.opks_p.clone()
        }
    }

}

fn main() {
    let user: User = User::new("Alice".to_string(), 1);

    let bundle: UserBundle = user.publish();

    println!("{:?}", bundle);
    
    println!("hello world");
    
}