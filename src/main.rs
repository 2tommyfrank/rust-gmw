#![feature(slice_as_chunks)]

mod gmw;
mod crypto;

use gmw::ot_send;
use tokio::net;

use crate::{crypto::CryptoStream, gmw::{eval, ot_recv, Circuit, Gate}};

type GmwResult<T> = Result<T, Box<dyn std::error::Error>>;

const NUM_PARTIES: usize = 3;

#[tokio::main]
async fn main() -> GmwResult<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        let id: usize = str::parse(&args[1])?;
        let mut parties: Vec<CryptoStream> = vec![];
        for i in 0..id {
            let port = 8080 + (i * 10) + id;
            let stream = net::TcpStream::connect(format!("localhost:{}", port)).await?;
            parties.push(CryptoStream::agree(stream).await?);
        }
        for i in (id + 1)..NUM_PARTIES {
            let port = 8080 + i + (id * 10);
            let listener = net::TcpListener::bind(format!("localhost:{}", port)).await?;
            let (stream, _) = listener.accept().await?;
            parties.push(CryptoStream::agree(stream).await?);
        }
        let circuit = Circuit {
            gates: vec![
                Gate::And { left: 0, right: 1, output: 18 },
                Gate::Xor { left: 1, right: 2, output: 19 },
                Gate::Not { input: 3, output: 20 },
                Gate::And { left: 2, right: 4, output: 21 },
                Gate::Xor { left: 5, right: 5, output: 22 },
                Gate::And { left: 0, right: 0, output: 23 },
                Gate::And { left: 5, right: 7, output: 24 },
            ],
            rounds: vec![0, 1, 2, 3, 4, 5, 6, 7],
            inputs: vec![0, 5, 11, 18],
            output: 0,
        };
        let mut wires: Vec<u8> = vec![0; 25];
        let mut inputs = vec![0; circuit.inputs[id + 1] - circuit.inputs[id]];
        for i in 0..inputs.len() {
            if i % 2 == 0 { inputs[i] = 1; }
        }
        let outputs = eval(circuit, &mut wires, id, inputs, &mut parties).await?;
        println!("{:?}", outputs);
    } else { panic!("Invalid arguments"); }
    Ok(())
}

async fn crypto_test() -> GmwResult<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 {
        let addr = format!("{}:{}", args[2], args[3]);
        match args[1].as_str() {
            "listen" => {
                let listener = net::TcpListener::bind(addr).await?;
                let (stream, _) = listener.accept().await?;
                let mut stream = CryptoStream::agree(stream).await?;
                println!("{}", String::from_utf8(stream.recv().await?)?);
            },
            "connect" => {
                let stream = net::TcpStream::connect(addr).await?;
                let mut stream = CryptoStream::agree(stream).await?;
                stream.send("message".as_bytes()).await?;
            },
            _ => panic!("Invalid command"),
        }
    } else { panic!("Invalid arguments"); }
    Ok(())
}

async fn ot_test() -> GmwResult<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 5 {
        match args[1].as_str() {
            "receive" => {
                let choice: bool = str::parse::<u8>(&args[2]).unwrap() != 0;
                let addr = format!("{}:{}", args[3], args[4]);
                let listener = net::TcpListener::bind(addr).await?;
                let (stream, _) = listener.accept().await?;
                let mut stream = CryptoStream::agree(stream).await?;
                println!("{}", ot_recv(&mut stream, choice).await?);
            },
            _ => panic!("Invalid command"),
        }
    } else if args.len() == 6 {
        match args[1].as_str() {
            "send" => {
                let m0: u8 = str::parse(&args[2]).unwrap();
                let m1: u8 = str::parse(&args[3]).unwrap();
                let addr = format!("{}:{}", args[4], args[5]);
                let stream = net::TcpStream::connect(addr).await?;
                let mut stream = CryptoStream::agree(stream).await?;
                ot_send(&mut stream, m0, m1).await?;
            },
            _ => panic!("Invalid command"),
        }
    } else { panic!("Invalid arguments"); }
    Ok(())
}