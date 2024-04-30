use std::iter;

use crypto_bigint::{NonZero, RandomMod, Uint};
use crypto_bigint::{const_residue, impl_modulus, modular::constant_mod::Residue, U2048, U256};
use crypto_bigint::modular::constant_mod::ResidueParams;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use ring::digest::{self, digest};

use crate::crypto::CryptoStream;
use crate::{GmwResult, NUM_PARTIES};

impl_modulus!(P, U2048, "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597");
const G_INT: U2048 = U2048::from_be_hex("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659");
const G: Residue<P, 32> = const_residue!(G_INT, P);
const Q_INT: U256 = U256::from_be_hex("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3");

pub enum Gate {
    Not { input: usize, output: usize },
    Xor { left: usize, right: usize, output: usize },
    And { left: usize, right: usize, output: usize },
}

pub struct Circuit {
    pub gates: Vec<Gate>,
    pub rounds: Vec<usize>,
    pub inputs: Vec<usize>,
    pub output: usize,
}

pub async fn eval(circuit: Circuit, wires: &mut Vec<u8>, id: usize, inputs: Vec<u8>, parties: &mut [CryptoStream]) -> GmwResult<Vec<u8>> {
    let mut rng = StdRng::from_entropy();

    // Send input shares
    let input_wires = &mut wires[circuit.inputs[id]..circuit.inputs[id + 1]];
    input_wires.copy_from_slice(&inputs);
    let input_shares: Vec<Vec<u8>> = vec![
        vec![(rng.next_u32() % 2) as u8; inputs.len()];
        parties.len()
    ];
    for (shares_row, party) in iter::zip(input_shares, parties.iter_mut()) {
        party.send(&shares_row).await?;
        for (input, share) in iter::zip(input_wires.iter_mut(), shares_row) {
            *input ^= share;
        }
    }

    // Receive input shares
    for i in 0..id {
        let shares = parties[i].recv().await?;
        let input_wires = &mut wires[circuit.inputs[i]..circuit.inputs[i + 1]];
        input_wires.copy_from_slice(&shares);
    }
    for i in id..parties.len() {
        let shares = parties[i].recv().await?;
        let input_wires = &mut wires[circuit.inputs[i + 1]..circuit.inputs[i + 2]];
        input_wires.copy_from_slice(&shares);
    }

    for i in 0..(circuit.rounds.len() - 1) {
        let mut and_gates: Vec<(u8, u8, usize)> = vec![];
        for j in circuit.rounds[i]..circuit.rounds[i+1] {
            match circuit.gates[j] {
                Gate::Not { input, output } => {
                    wires[output] = if id == 0 { 1 - wires[input] } else { wires[input] }
                },
                Gate::Xor { left, right, output } => {
                    wires[output] = wires[left] ^ wires[right]
                },
                Gate::And { left, right, output } => {
                    wires[output] = wires[left] & wires[right];
                    and_gates.push((wires[left], wires[right], output));
                },
            }
        }
        for (left, right, output) in and_gates {
            for i in 0..id {
                let m0 = rng.next_u32() as u8;
                let m1 = left ^ m0;
                ot_send(&mut parties[i], m0, m1).await?;
                wires[output] ^= m0;
            }
            for i in (id + 1)..NUM_PARTIES {
                wires[output] ^= ot_recv(&mut parties[i - 1], right != 0).await?;
            }
        }
    }

    // Output shares
    let output_wires = &mut wires[circuit.output..];
    for party in parties.iter_mut() {
        party.send(output_wires).await?;
    }
    for party in parties.iter_mut() {
        let shares = party.recv().await?;
        for (output, share) in iter::zip(output_wires.iter_mut(), shares) {
            *output ^= share;
        }
    }
    Ok(Vec::from(output_wires))
}

pub async fn ot_send(stream: &mut CryptoStream, m0: u8, m1: u8) -> GmwResult<()> {
    let q: NonZero<Uint<4>> = NonZero::new(Q_INT).unwrap();
    let mut rng = StdRng::from_entropy();
    let a = U256::random_mod(&mut rng, &q);
    let A = G.pow_bounded_exp(&a, 256);
    {
        let words = A.as_montgomery().as_words();
        let bytes = words.map(|word| word.to_le_bytes()).concat();
        stream.send(&bytes).await?;
    }
    let B: Residue<P, 32> = {
        let bytes = stream.recv().await?;
        let words: Vec<u64> = bytes.chunks(8).map(|bytestring| {
            u64::from_le_bytes(bytestring.try_into().unwrap())
        }).collect();
        Residue::from_montgomery(Uint::from_words(words.try_into().unwrap()))
    };
    {
        let pre_hash = B.pow_bounded_exp(&a, 256);
        let words = pre_hash.as_montgomery().as_words();
        let mut bytes = words.map(|word| word.to_le_bytes()).concat();
        bytes[0] ^= m0;
        let hash = digest(&digest::SHA256, &bytes);
        stream.send(&hash.as_ref()).await?;
    }
    {
        let pre_hash = (B * A.invert().0).pow_bounded_exp(&a, 256);
        let words = pre_hash.as_montgomery().as_words();
        let mut bytes = words.map(|word| word.to_le_bytes()).concat();
        bytes[0] ^= m1;
        let hash = digest(&digest::SHA256, &bytes);
        stream.send(&hash.as_ref()).await?;
    }
    Ok(())
}

pub async fn ot_recv(stream: &mut CryptoStream, choice: bool) -> GmwResult<u8> {
    let q: NonZero<Uint<4>> = NonZero::new(Q_INT).unwrap();
    let mut rng = StdRng::from_entropy();
    let A: Residue<P, 32> = {
        let bytes = stream.recv().await?;
        let words: Vec<u64> = bytes.chunks(8).map(|bytestring| {
            u64::from_le_bytes(bytestring.try_into().unwrap())
        }).collect();
        Residue::from_montgomery(Uint::from_words(words.try_into().unwrap()))
    };
    let b = U256::random_mod(&mut rng, &q);
    let B = G.pow_bounded_exp(&b, 256) * A.pow_bounded_exp::<32>(&Uint::from(choice as u8), 8);
    {
        let words = B.to_montgomery().to_words();
        let bytes = words.map(|word| word.to_le_bytes()).concat();
        stream.send(&bytes).await?;
    }
    let mut key = {
        let pre_hash = A.pow_bounded_exp(&b, 256);
        let words = pre_hash.as_montgomery().as_words();
        words.map(|word| word.to_le_bytes()).concat()
    };
    let key0 = key[0];
    let (ct0, ct1) = (stream.recv().await?, stream.recv().await?);
    let ciphertext = if choice { ct1 } else { ct0 };
    for plaintext in 0..u8::MAX {
        key[0] = key0 ^ plaintext;
        let hash = digest(&digest::SHA256, &key);
        if hash.as_ref() == ciphertext { return Ok(plaintext); }
    }
    panic!("OT failed");
}
