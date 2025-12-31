use std::convert::TryInto;
use threshold_crypto::{PublicKey, SecretKey, Signature, SIG_SIZE};

/// A signed message with IETF-standard serialization.
struct SignedMsg {
    msg: Vec<u8>,
    sig: Signature,
}

impl SignedMsg {
    /// Serialize to bytes: 4-byte length prefix + message + 96-byte IETF signature
    fn to_bytes(&self) -> Vec<u8> {
        let msg_len_bytes = (self.msg.len() as u32).to_be_bytes();
        let mut bytes = Vec::with_capacity(msg_len_bytes.len() + self.msg.len() + SIG_SIZE);
        bytes.extend_from_slice(&msg_len_bytes);
        bytes.extend_from_slice(&self.msg);
        bytes.extend_from_slice(&self.sig.to_bytes());
        bytes
    }

    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 + SIG_SIZE {
            return None;
        }
        let msg_len = u32::from_be_bytes(bytes[0..4].try_into().ok()?) as usize;
        if bytes.len() != 4 + msg_len + SIG_SIZE {
            return None;
        }
        let msg = bytes[4..4 + msg_len].to_vec();
        let sig_bytes: [u8; SIG_SIZE] = bytes[4 + msg_len..].try_into().ok()?;
        let sig = Signature::from_bytes(&sig_bytes).ok()?;
        Some(SignedMsg { msg, sig })
    }
}

#[derive(Debug)]
struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl KeyPair {
    fn random() -> Self {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        KeyPair { sk, pk }
    }

    fn create_signed_msg(&self, msg: &[u8]) -> SignedMsg {
        let sig = self.sk.sign(msg);
        let msg = msg.to_vec();
        SignedMsg { msg, sig }
    }
}

fn main() {
    // Alice and Bob each generate a public/private key-pair.
    //
    // Note: it is against best practices to use the same key-pair for both encryption/decryption
    // and signing. The following example could be interpreted as advocating this, which it is not
    // meant to. This is just a basic example. In this example, Bob's key-pair is used for signing
    // where as Alice's is used for encryption/decryption.
    let alice = KeyPair::random();
    let bob = KeyPair::random();

    // Bob wants to send Alice a message. He signs the plaintext message with his secret key. He
    // then encrypts the signed message with Alice's public key.
    let msg = b"let's get pizza";
    let signed_msg = bob.create_signed_msg(msg);
    let serialized = signed_msg.to_bytes();
    let ciphertext = alice.pk.encrypt(&serialized);

    // Alice receives Bob's encrypted message. She decrypts the message using her secret key. She
    // then verifies that the signature of the plaintext is valid using Bob's public key.
    let decrypted = alice.sk.decrypt(&ciphertext).expect("Invalid ciphertext");
    let deserialized = SignedMsg::from_bytes(&decrypted).expect("Failed to deserialize SignedMsg");
    assert!(bob.pk.verify(&deserialized.sig, &deserialized.msg));

    // We assert that the message that Alice received is the same message that Bob sent.
    assert_eq!(msg, &deserialized.msg[..]);
}
