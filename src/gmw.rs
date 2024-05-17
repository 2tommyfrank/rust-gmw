use std::iter;

use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::crypto::CryptoStream;
use crate::{GmwResult, NUM_PARTIES};

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

impl Circuit {
    pub async fn eval(self, wires: &mut Vec<u8>, id: usize, inputs: Vec<u8>, parties: &mut [CryptoStream]) -> GmwResult<Vec<u8>> {
        let mut rng = StdRng::from_entropy();
    
        // Send input shares
        let input_wires = &mut wires[self.inputs[id]..self.inputs[id + 1]];
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
            let input_wires = &mut wires[self.inputs[i]..self.inputs[i + 1]];
            input_wires.copy_from_slice(&shares);
        }
        for i in id..parties.len() {
            let shares = parties[i].recv().await?;
            let input_wires = &mut wires[self.inputs[i + 1]..self.inputs[i + 2]];
            input_wires.copy_from_slice(&shares);
        }
    
        for i in 0..(self.rounds.len() - 1) {
            let mut and_gates: Vec<(u8, u8, usize)> = vec![];
            for j in self.rounds[i]..self.rounds[i+1] {
                match self.gates[j] {
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
                    parties[i].ot_send(m0, m1).await?;
                    wires[output] ^= m0;
                }
                for i in (id + 1)..NUM_PARTIES {
                    wires[output] ^= parties[i - 1].ot_recv(right != 0).await?;
                }
            }
        }
    
        // Output shares
        let output_wires = &mut wires[self.output..];
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
}
