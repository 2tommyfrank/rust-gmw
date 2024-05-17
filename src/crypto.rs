use crypto_bigint::{const_residue, impl_modulus, NonZero, RandomMod, Uint, U2048, U256};
use crypto_bigint::modular::constant_mod::{Residue, ResidueParams};
use futures::{SinkExt, StreamExt};
use ::rand::{rngs::StdRng, SeedableRng};
use ring::{aead::{self, BoundKey}, agreement, digest, rand};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net};
use tokio_util::{bytes::BytesMut, codec};

use crate::GmwResult;

impl_modulus!(P, U2048, "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597");
const G_INT: U2048 = U2048::from_be_hex("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659");
const G: Residue<P, 32> = const_residue!(G_INT, P);
const Q_INT: U256 = U256::from_be_hex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3");

pub struct CryptoStream {
    framed: codec::Framed<net::TcpStream, codec::LengthDelimitedCodec>,
    sealing_key: aead::SealingKey<CounterNonce>,
    opening_key: aead::OpeningKey<CounterNonce>,
}

struct CounterNonce(usize);

impl CryptoStream {
    pub async fn agree(mut stream: net::TcpStream) -> GmwResult<Self> {
        let rng = rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let my_public_key = private_key.compute_public_key().unwrap();
        stream.write(my_public_key.as_ref()).await?;
        let mut peer_public_key_bytes = vec![0u8; my_public_key.as_ref().len()];
        stream.read(&mut peer_public_key_bytes).await?;
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, &peer_public_key_bytes);
        let unbound_keys = agreement::agree_ephemeral(private_key, &peer_public_key, |key| (
            aead::UnboundKey::new(&aead::AES_256_GCM, key),
            aead::UnboundKey::new(&aead::AES_256_GCM, key),
        )).unwrap();
        let sealing_key = aead::SealingKey::new(unbound_keys.0.unwrap(), CounterNonce(0));
        let opening_key = aead::OpeningKey::new(unbound_keys.1.unwrap(), CounterNonce(0));
        let framed = codec::Framed::new(stream, codec::LengthDelimitedCodec::new());
        Ok(CryptoStream { framed, sealing_key, opening_key })
    }

    pub async fn send(&mut self, message: &[u8]) -> GmwResult<()> {
        let CryptoStream { framed, sealing_key, opening_key: _ } = self;
        let delimited = [&message.len().to_le_bytes(), message].concat();
        let mut bytes = BytesMut::from(delimited.as_slice());
        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut bytes).unwrap();
        framed.send(bytes.into()).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> GmwResult<Vec<u8>> {
        let CryptoStream { framed, sealing_key: _, opening_key } = self;
        let mut bytes = framed.next().await.unwrap()?;
        opening_key.open_in_place(aead::Aad::empty(), &mut bytes).unwrap();
        let message_len = usize::from_le_bytes(bytes[..8].try_into().unwrap());
        Ok(Vec::from(&bytes[8..(message_len + 8)]))
    }

    pub async fn ot_send(&mut self, m0: u8, m1: u8) -> GmwResult<()> {
        let q: NonZero<Uint<4>> = NonZero::new(Q_INT).unwrap();
        let mut rng = StdRng::from_entropy();
        let a = U256::random_mod(&mut rng, &q);
        let A = G.pow_bounded_exp(&a, 256);
        self.send(&serialize_residue(A)).await?;
        let B = deserialize_residue(self.recv().await?);
    
        let pre_hash = B.pow_bounded_exp(&a, 256);
        let mut bytes = serialize_residue(pre_hash);
        bytes[0] ^= m0;
        let hash = digest::digest(&digest::SHA256, &bytes);
        self.send(&hash.as_ref()).await?;
    
        let pre_hash = (B * A.invert().0).pow_bounded_exp(&a, 256);
        let mut bytes = serialize_residue(pre_hash);
        bytes[0] ^= m1;
        let hash = digest::digest(&digest::SHA256, &bytes);
        self.send(&hash.as_ref()).await?;
    
        Ok(())
    }

    pub async fn ot_recv(&mut self, choice: bool) -> GmwResult<u8> {
        let q: NonZero<Uint<4>> = NonZero::new(Q_INT).unwrap();
        let mut rng = StdRng::from_entropy();
        let A = deserialize_residue(self.recv().await?);
        let b = U256::random_mod(&mut rng, &q);
        let B = G.pow_bounded_exp(&b, 256) * A.pow_bounded_exp::<32>(&Uint::from(choice as u8), 8);
        self.send(&serialize_residue(B)).await?;
    
        let pre_hash = A.pow_bounded_exp(&b, 256);
        let mut key = serialize_residue(pre_hash);
        let key0 = key[0];
        let (ct0, ct1) = (self.recv().await?, self.recv().await?);
        let ciphertext = if choice { ct1 } else { ct0 };
    
        for plaintext in 0..u8::MAX {
            key[0] = key0 ^ plaintext;
            let hash = digest::digest(&digest::SHA256, &key);
            if hash.as_ref() == ciphertext { return Ok(plaintext); }
        }
        panic!("OT failed");
    }    
}

impl aead::NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        const MAX: usize = if 8 * aead::NONCE_LEN < (usize::BITS as usize) {
            1 << (8 * aead::NONCE_LEN)
        } else { usize::MAX };
        if self.0 < MAX {
            self.0 += 1;
            let counter_bits = self.0.to_le_bytes();
            let mut nonce = [0u8; aead::NONCE_LEN];
            nonce[..counter_bits.len()].copy_from_slice(&counter_bits);
            Ok(aead::Nonce::assume_unique_for_key(nonce))
        } else { Err(ring::error::Unspecified) }
    }
}

fn serialize_residue(residue: Residue<P, 32>) -> Vec<u8> {
    let words = residue.as_montgomery().as_words();
    words.map(|word| word.to_le_bytes()).concat()
}

fn deserialize_residue(bytes: Vec<u8>) -> Residue<P, 32> {
    let words: Vec<u64> = bytes.chunks(8).map(|bytestring| {
        u64::from_le_bytes(bytestring.try_into().unwrap())
    }).collect();
    Residue::from_montgomery(Uint::from_words(words.try_into().unwrap()))
}
