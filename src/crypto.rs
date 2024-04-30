use futures::{SinkExt, StreamExt};
use ring::{aead::{self, BoundKey}, agreement, rand};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net};
use tokio_util::{bytes::BytesMut, codec};

use crate::GmwResult;

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
