use crate::{Ciphertext, DecryptionShare, PublicKey, PublicKeySet, Signature, PK_SIZE, SIG_SIZE};

// PublicKey uses raw IETF bytes
impl codec::Encode for PublicKey {
    fn encode(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl codec::Decode for PublicKey {
    fn decode<I: codec::Input>(value: &mut I) -> std::result::Result<Self, codec::Error> {
        let mut bytes = [0u8; PK_SIZE];
        value.read(&mut bytes)?;
        PublicKey::from_bytes(&bytes).map_err(|_| codec::Error::from("invalid public key bytes"))
    }
}

// Signature uses raw IETF bytes
impl codec::Encode for Signature {
    fn encode(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl codec::Decode for Signature {
    fn decode<I: codec::Input>(value: &mut I) -> std::result::Result<Self, codec::Error> {
        let mut bytes = [0u8; SIG_SIZE];
        value.read(&mut bytes)?;
        Signature::from_bytes(&bytes).map_err(|_| codec::Error::from("invalid signature bytes"))
    }
}

#[macro_export]
/// implement parity codec for type using bincode serialization
macro_rules! impl_codec_for_serde {
    ($type:ty) => {
        impl codec::Encode for $type {
            fn encode(&self) -> Vec<u8> {
                let encoded = bincode::serialize(&self).unwrap();
                codec::Encode::encode(&encoded)
            }
        }

        impl codec::Decode for $type {
            fn decode<I: codec::Input>(value: &mut I) -> std::result::Result<Self, codec::Error> {
                let decoded: Vec<u8> = codec::Decode::decode(value)?;
                bincode::deserialize(decoded.as_slice()).map_err(|_| {
                    codec::Error::from("parity-scale-codec decode error in threshold_crypto")
                })
            }
        }
    };
}

impl_codec_for_serde!(DecryptionShare);
impl_codec_for_serde!(PublicKeySet);
impl_codec_for_serde!(Ciphertext);
