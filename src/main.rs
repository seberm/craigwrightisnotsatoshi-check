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
use std::error::Error;

#[derive(Debug)]
pub enum MyError {
    PubkeyRecoveryError,
}

const MESSAGE: &str =
"Craig Steven Wright is a liar and a fraud. He doesn't have the keys used to sign this message.

The Lightning Network is a significant achievement. However, we need to continue work on improving on-chain capacity.

Unfortunately, the solution is not to just change a constant in the code or to allow powerful participants to force out others.

We are all Satoshi";

fn check_sig(address: Address, message: &str, signature: &str) -> Result<(), MyError> {
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
        return Err(MyError::PubkeyRecoveryError);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line_inner = line?;
        let chunks: Vec<&str> = line_inner.split_whitespace().collect();

        assert!(chunks.len() == 2);

        let (addr, sig) = (chunks[0], chunks[1]);

        println!("addr={}, sig={}", addr, sig);
        match check_sig(addr.parse().unwrap(), MESSAGE, sig) {
            Err(MyError::PubkeyRecoveryError) => {
                println!("Cannot recover pubkey!");
                //println!("Caused by: {}", e);
            }
            Ok(_) => {}
        };
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_valid_signatures() {
        let checks: Vec<(&str, &str)> = vec![
            ("1FbPLPR1XoufBQRPGd9JBLPbKLaGjbax5m", "G3SsgKMKAOiOaMzKSGqpKo5MFpt0biP9MbO5UkSl7VxRKcv6Uz+3mHsuEJn58lZlRksvazOKAtuMUMolg/hE9WI="),
            ("19PYG68GkQ9nY99QeUSyUFy6vWxSyPmXA8", "HFjd/SzCNDyXRY/skSjEKusK/adVtBf0ldT1ayvPb+WsLa5Qr0A4seEXjOmtg9K/wcJnv/E3F5TezZNB/ULoZI8="),
            ("12cFuwo1i3FMhkmJoCN8D4SjeCeRsXf96q", "GySQXGlZ+Meq3braDzg3lq7GStteOg+0A9Q5gGKzCcOmET5vnULXo0vsb6anu1wLSL1BnaD0p71U9i+c41Fq48w="),
            ("1NWRrbPwHhpp28eQeman5YRV84D2aYe1Yw", "HDE35UqJUUa8tkjt3NThu+SwF8arV27Lwg6idBTN7lm+epmjdQlvnWvCqUHrOBPCPQ50aK5VhLnUUFIEDE4KXlo="),
            ("1MN82eH1Eu3hznewHFkfsAajknhj78Uup5", "HAZ+ot0bWlK4t40kTqC9H0tCjVeCa3WCR0xyYNMX94uqAAXTOHITT8X0QzQI4UFlHCzPhfcxsgMgniiTY0FkUHc="),
            ("1DYHUEjrVE5gyKAn7P13wuRhs6x9EeijBX", "G08ZpNNnXNawyvIEpa79QpP4+MjZhBd1+0/nAGCcI5X2DgtqfJDyYVpkVg9VXXy9rG7B/NK8TmdO4ep62QLkvlw="),
            ("1KnT26DTvstGKW7P6BxMBEz8QbKa1iix9C", "HF4BP/4DlRRJ38MlS0zcI9MDNWAfDZo3apmD+wzPPMfdAfuzt0ae0OOrUNW6ye+6mPYSwmnOaUfhR2EqyivCpX4="),
        ];

        for (address, signature) in checks.iter() {
            check_sig(address.parse().unwrap(), MESSAGE, signature).unwrap();
        }
    }

    #[test]
    fn check_invalid_signatures() {
        let checks: Vec<(&str, &str)> = vec![
            ("19PYG68GkQ9nY99QeUSyUFy6vWxSyPmXA8", "G3SsgKMKAOiOaMzKSGqpKo5MFpt0biP9MbO5UkSl7VxRKcv6Uz+3mHsuEJn58lZlRksvazOKAtuMUMolg/hE9WI="),
            ("1FbPLPR1XoufBQRPGd9JBLPbKLaGjbax5m", "HFjd/SzCNDyXRY/skSjEKusK/adVtBf0ldT1ayvPb+WsLa5Qr0A4seEXjOmtg9K/wcJnv/E3F5TezZNB/ULoZI8="),
        ];

        for (address, signature) in checks.iter() {
            assert!(check_sig(address.parse().unwrap(), MESSAGE, signature).is_err());
        }
    }
}
