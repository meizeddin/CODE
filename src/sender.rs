use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{Keypair, Signer, Signature};
use std::collection::HashMap;

// a user structure that holds the private and public keys, the signature, and other related fields.
pub struct User{
    pub name: String,
    pub IK_s: StaticSecret, //private_identity_key
    pub IK_p: PublicKey, //public_identity_key
    pub SPK_s: StaticSecret, //private_signed_pre_key
    pub SPK_p: PublicKey, //public_signed_pre_key
    pub SPK_sig: Signature, //signed_pre_key_signature
    pub OPKs_s: Vec<(StaticSecret, PublicKey)>, //one-time pre keys (public and private) 
    pub OPKs_p: vec<PublicKey>, //one-time pre keys (public only "published")
    pub key_bundles: HashMap<String, Vec<u8>>, //for serialised key bundles (public keys)
    pub dr_keys: HashMap<String, Vec<u8>> //for derived keys used to encrypt or decrypt messages
}
// user implementation
impl User{
    //A "new" function, a constructor for creating a new User instance It takes two parameters and returns a new user instance
    pub fn new(name: String, max_opk_num: usize) -> User {
        let mut csprng = OsRng; //instance of CSPRNG (cryptographically secure pseudo random number generator)
        let IK_s = StaticSecret::new(&mut csprng);
        let IK_p = PublicKey::from(&IK_s); //derives the public key from the private key
        let SPK_s = StaticSecret::new(&mut csprng);
        let SPK_p = PublicKey::from(&SPK_s);

        //creating and signing the public pre key. need more explaination
        let keypair = Keypair::from_bytes(&[IK_s.to_bytes(), [0u8; 32]].concat()).unwrap();
        let SPK_sig = keypair.sign(SPK_p.as_bytes());

        // set the capacity for the one-time pre keys to the max number specified
        let mut OPKs_s = Vec::with_capacity(max_opk_num);
        let mut OPKs_p = Vec::with_capacity(max_opk_num);
        
        for _ in 0..max_opk_num{
            let sk = StaticSecret::new(&mut csprng);
            let pk = PublicKey::from(&sk);
            OPKs_p.push(pk);
            OPKs_s.push((sk, pk));
        }

        User {
            name,
            IK_s,
            IK_p,
            SPK_s,
            SPK_p,
            SPK_sig,
            OPKs_s,
            OPKs_p,
            key_bundles: HashMap::new(),
            dr_keys: HashMap::new()
        }
    }

    pub fn publish(&self) -> UserBundle{
        UserBundle{
            IK_p: self.IK_p,
            SPK_p: self.SPK_p,
            SPK_sig: self.SPK_sig,
            OPKs_p: self.OPKs_p.clone()
        }
    }
}

pub struct UserBundle {
    pub IK_p: PublicKey,
    pub SPK_p: PublicKey,
    pub SPK_sig: Signature,
    pub OPKs_p: Vec<PublicKey>
}

fn main() {
    let user = User::new("Alice", 5);
    let bundle = user.publish();
    println!("{:?}", bundle);
}