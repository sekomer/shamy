#![allow(non_snake_case)]

use std::collections::HashMap;

use shamy::schnorr;
use shamy::shamir;
use shamy::threshold::{self, Participant};

fn main() {
    let n = 3;
    let t = 2;
    let keygen_output = shamir::shamir_keygen(n, t);

    let msg = b"rust is best";

    let signers: Vec<Participant> = keygen_output.participants.iter().take(t).copied().collect();
    let ids = signers.iter().map(|p| p.id).collect::<Vec<_>>();

    let mut nonces = HashMap::new();
    let mut nonce_pairs = Vec::new();
    for p in &signers {
        let r_i = schnorr::generate_nonce();
        let R_i = schnorr::compute_nonce_point(&r_i);
        nonces.insert(p.id, r_i);
        nonce_pairs.push((p.id, R_i));
    }
    let R = threshold::aggregate_nonce(&nonce_pairs, &ids);

    let c = schnorr::compute_challenge(&R, &keygen_output.public_key, msg);

    let partial_signatures = signers
        .iter()
        .map(|signer| {
            let r_i = nonces.get(&signer.id).unwrap();
            threshold::partial_sign(signer, r_i, &c)
        })
        .collect::<Vec<_>>();

    let signature = threshold::finalize_signature_lagrange(&partial_signatures, R);

    match signature.verify(msg, &keygen_output.public_key) {
        true => println!("success ✅"),
        false => println!("something bad happened ❌"),
    }
}
