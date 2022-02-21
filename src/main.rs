// Code to check the signatures from [0] are valid.
//
// ---
// Author: seberm
//
// Refs.:
// - [0] https://craigwrightisnotsatoshi.com/
// - [1] https://en.bitcoin.it/wiki/BIP_0137

use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address::{Address, Payload};
use bitcoin::util::misc::{signed_msg_hash, MessageSignature};
use std::io::{self, BufRead};

const MESSAGE: &str =
"Craig Steven Wright is a liar and a fraud. He doesn't have the keys used to sign this message.

The Lightning Network is a significant achievement. However, we need to continue work on improving on-chain capacity.

Unfortunately, the solution is not to just change a constant in the code or to allow powerful participants to force out others.

We are all Satoshi";

fn check_sig(address: Address, message: &str, signature: &str) {
    let secp = Secp256k1::verification_only();
    let sig = base64::decode(&signature).unwrap();

    let sss = MessageSignature::from_slice(&sig).unwrap();
    let msg_hash = signed_msg_hash(message);

    if sss.is_signed_by_address(&secp, &address, msg_hash).unwrap() {
        println!("SIG OK - {}", address)
    }

    // Try to recover pubkey
    let pubkey = sss.recover_pubkey(&secp, msg_hash).unwrap();

    let restored_address = match address.payload {
        Payload::PubkeyHash(_) => Address::p2pkh(&pubkey, address.network),
        Payload::WitnessProgram { .. } => Address::p2wpkh(&pubkey, address.network).unwrap(),
        Payload::ScriptHash(_) => Address::p2shwpkh(&pubkey, address.network).unwrap(),
    };

    if address != restored_address {
        println!("Cannot recover pubkey!");
    }
}

fn main() {
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line_inner = line.unwrap();
        let chunks: Vec<&str> = line_inner.split_whitespace().collect();

        assert!(chunks.len() == 2);

        let (addr, sig) = (chunks[0], chunks[1]);

        println!("addr={}, sig={}", addr, sig);
        check_sig(addr.parse().unwrap(), MESSAGE, sig);
    }
}
