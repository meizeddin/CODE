use x25519_dalek::{EphemeralSecret, PublicKey};
use rand::rngs::OsRng;

fn main() {
    // Alice generates her key pair
    let alice_secret: EphemeralSecret = EphemeralSecret::random_from_rng(&mut OsRng);
    let alice_public: PublicKey = PublicKey::from(&alice_secret);

    // Bob generates his key pair
    let bob_secret: EphemeralSecret = EphemeralSecret::random_from_rng(&mut OsRng);
    let bob_public: PublicKey = PublicKey::from(&bob_secret);

    // Alice and Bob exchange public keys and compute the shared secret
    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

    // Both shared secrets should be the same
    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());

    // Print the shared secrets
    println!("Alice's shared secret: {:?}", alice_shared_secret.as_bytes());
    println!("Bob's shared secret: {:?}", bob_shared_secret.as_bytes());

    // Assert and print the result of the assertion
    if alice_shared_secret.as_bytes() == bob_shared_secret.as_bytes() {
        println!("The shared secrets are equal.");
    } else {
        println!("The shared secrets are not equal.");
    }
}
